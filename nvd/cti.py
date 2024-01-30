import collections
import os
from typing import Dict, Iterable, Iterator, Optional, Set, Union
from stix2 import Filter, MemorySource
from stix2.datastore import DataSource
from networkx import Graph

import requests
import tempfile
import json
from typing import Iterator
import logging

logger = logging.getLogger(__name__)

DEFAULT_ATTACK_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
DEFAULT_CAPEC_URL = 'https://raw.githubusercontent.com/mitre/cti/94c2b6660793e84464f7317c4e103749a0e8c153/capec/2.1/stix-capec.json'

DEFAULT_ATTACK_PATH = os.path.expanduser('~/src/attack-stix-data/enterprise-attack/enterprise-attack.json')
DEFAULT_CAPEC_PATH = os.path.expanduser('~/src/cti/capec/2.1/stix-capec.json')


def get_attack_navigator_layer(
        cve_ids_to_cwe_ids: Dict[str, Iterable[str]],
        cve_ids: Optional[Iterable[str]] = None,
        attack_data_source: Optional[Union[str, DataSource]] = None, 
        capec_data_source: Optional[Union[str, DataSource]] = None) -> dict:

    cwe_ids = set()
    if not cve_ids:
        cve_ids = cve_ids_to_cwe_ids.keys()

    for cve_id in cve_ids:
        try:
            cwe_ids.update(cve_ids_to_cwe_ids[cve_id])
        except KeyError:
            logger.debug(f'No CWEs mapped to CVE {cve_id}')

    if not cwe_ids:
        raise ValueError('No CWE mappings available for CVEs (CVEs: {cve_ids})')
    
    attack_data_source = get_stix2_memory_source(path=DEFAULT_ATTACK_PATH, url=DEFAULT_ATTACK_URL) if attack_data_source is None else attack_data_source
    capec_data_source = get_stix2_memory_source(path=DEFAULT_CAPEC_PATH, url=DEFAULT_CAPEC_URL) if capec_data_source is None else capec_data_source

    g = get_cti_graph(attack_data_source, capec_data_source)
    
    attack_techniques = attack_data_source.query(Filter('type', '=', 'attack-pattern'))
    attack_technique_ids = {parse_stix2_external_id(o, 'mitre-attack') for o in attack_techniques}

    selected_attack_technique_ids = _get_attack_technique_ids_from_cwe_ids(g, cwe_ids)
    deselected_attack_techniques = attack_technique_ids - selected_attack_technique_ids

    layer = {
        'name': 'NIST NVD to ATT&CK',
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        'domain': 'enterprise-attack',
        'techniques': [],
        'hideDisabled': False,
    }
    for attack_technique in attack_technique_ids:
        layer['techniques'].append({
            'techniqueID': attack_technique,
            'color': '#6495ED'
        })
    
    for attack_technique in deselected_attack_techniques:
        layer['techniques'].append({
            'techniqueID': attack_technique,
            'enabled': False,
            'comment': 'This technique is not mapped to any CWEs.'
        })
    
    return layer


def get_cti_graph(attack_data_source: Union[str, DataSource], capec_data_source: Union[str, DataSource]) -> Graph:
    """
    Return an undirected graph providing pivot points between MITRE CWE, CAPEC, and ATT&CK with external IDs as labels.
    """
    attack_data_source = get_stix2_memory_source(path=DEFAULT_ATTACK_PATH, url=DEFAULT_ATTACK_URL) if attack_data_source is None else attack_data_source
    capec_data_source = get_stix2_memory_source(path=DEFAULT_CAPEC_PATH, url=DEFAULT_CAPEC_URL) if capec_data_source is None else capec_data_source

    g = Graph()
    for o in capec_data_source.query(Filter('type', '=', 'attack-pattern')):
        capec_id = parse_stix2_external_id(o, 'capec')
        
        attack_technique_ids = parse_stix2_external_ids(o, 'ATTACK')
        for attack_technique_id in attack_technique_ids:
            g.add_edge(capec_id, attack_technique_id)

        cwe_ids = parse_stix2_external_ids(o, 'cwe')
        for cwe_id in cwe_ids:
            g.add_edge(capec_id, cwe_id)

    return g


def get_mappings_between_cve_ids_and_cwe_ids(cves: Iterable[dict]) -> dict:
    m = collections.defaultdict(list)
    for cve in cves:
        cve_id = cve['id']
        for cwe_id in parse_cwe_ids(cve):
            if cwe_id not in m[cve_id]:
                m[cve_id].append(cwe_id)
    return dict(m)


def _get_attack_technique_ids_from_cwe_ids(g: Graph, cwe_ids: Set[str]) -> Iterator[str]:
    capec_ids  = _get_capec_technique_ids_from_cwe_ids(g, cwe_ids)
    attack_ids = _get_attack_technique_ids_from_capec_ids(g, capec_ids)
    return attack_ids


def _get_attack_technique_ids_from_capec_ids(g: Graph, capec_ids: Set[str]) -> Set[str]:
    result = set()
    for (a, b) in g.edges:
        if a.startswith('T') and b.startswith('CAPEC-') and b in capec_ids:
            result.add(a)
        elif a.startswith('CAPEC-') and b.startswith('T') and a in capec_ids:
            result.add(b)
    return result


def _get_capec_technique_ids_from_cwe_ids(g: Graph, cwe_ids: Set[str]) -> Set[str]:
    result = set()
    for (a, b) in g.edges:
        if a.startswith('CAPEC-') and b.startswith('CWE-') and b in cwe_ids:
            result.add(a)
        elif a.startswith('CWE-') and b.startswith('CAPEC-') and a in cwe_ids:
            result.add(b)
    return result


def get_stix2_memory_source(path: Optional[str] = None, url: Optional[str] = None):
    if os.path.exists(path):
        return get_stix2_memory_source_from_file(path)
    elif url:
        return get_stix2_memory_source_from_web(url)
    else:
        raise ValueError('Either path or url must be specified')


def get_stix2_memory_source_from_file(path: str):
    src = MemorySource()
    src.load_from_file(path)
    return src


def get_stix2_memory_source_from_web(url: str):
    with tempfile.NamedTemporaryFile() as file:
        response = requests.get(url)
        file.write(response.content)
        return get_stix2_memory_source_from_file(file.name)


def parse_stix2_external_id(o: dict, source_name: str) -> Optional[str]:
    for external_reference in o.get("external_references", []):
        if external_reference.get("source_name") == source_name:
            return external_reference["external_id"]


def parse_stix2_external_ids(o: dict, source_name: str) -> Set[str]:
    external_ids = set()
    for ref in o.get("external_references", []):
        if ref.get("source_name") == source_name:
            external_ids.add(ref["external_id"])
    return external_ids