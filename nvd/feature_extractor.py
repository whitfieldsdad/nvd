import collections
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional
from nvd import files
from cvss import CVSS2, CVSS3
import inflection

CPE_DEPRECATION_REMAP = "CPE Deprecation Remap"
CVE_CISA_KEV_UPDATE = "CVE CISA KEV Update"
CVE_MODIFIED = "CVE Modified"
CVE_RECEIVED = "CVE Received"
CVE_REJECTED = "CVE Rejected"
CVE_SOURCE_UPDATE = "CVE Source Update"
CVE_TRANSLATED = "CVE Translated"
CVE_UNREJECTED = "CVE Unrejected"
CWE_REMAP = "CWE Remap"
INITIAL_ANALYSIS = "Initial Analysis"
MODIFIED_ANALYSIS = "Modified Analysis"
REANALYSIS = "Reanalysis"
VENDOR_COMMENT = "Vendor Comment"

CVE_CHANGE_HISTORY_EVENT_TYPES = {
    CPE_DEPRECATION_REMAP,
    CVE_CISA_KEV_UPDATE,
    CVE_MODIFIED,
    CVE_RECEIVED,
    CVE_REJECTED,
    CVE_SOURCE_UPDATE,
    CVE_TRANSLATED,
    CVE_UNREJECTED,
    CWE_REMAP,
    INITIAL_ANALYSIS,
    MODIFIED_ANALYSIS,
    REANALYSIS,
    VENDOR_COMMENT,
}

def get_cvss3_metrics(vector: str) -> dict:
    """
    Returns a set of snakecased CVSS3 metrics for a given CVSS3 vector
    
    :param vector: CVSS3 vector (e.g. CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N)
    :return: dict of CVSS3 metrics (e.g. {'attack_vector': 'NETWORK', 'attack_complexity': 'HIGH', ...})

    Example usage:

    >>> from pprint import pprint
    >>> metrics = get_cvss3_metrics('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N')
    >>> pprint(metrics)
    {'attack_complexity': 'HIGH',
    'attack_vector': 'NETWORK',
    'availability_impact': 'NONE',
    'availability_requirement': 'NOT_DEFINED',
    'base_score': 3.7,
    'base_severity': 'LOW',
    'confidentiality_impact': 'NONE',
    'confidentiality_requirement': 'NOT_DEFINED',
    'environmental_score': 3.7,
    'environmental_severity': 'LOW',
    'exploit_code_maturity': 'NOT_DEFINED',
    'integrity_impact': 'LOW',
    'integrity_requirement': 'NOT_DEFINED',
    'modified_attack_complexity': 'HIGH',
    'modified_attack_vector': 'NETWORK',
    'modified_availability_impact': 'NONE',
    'modified_confidentiality_impact': 'NONE',
    'modified_integrity_impact': 'LOW',
    'modified_privileges_required': 'NONE',
    'modified_user_interaction': 'NONE',
    'privileges_required': 'NONE',
    'remediation_level': 'NOT_DEFINED',
    'report_confidence': 'NOT_DEFINED',
    'scope': 'UNCHANGED',
    'temporal_score': 3.7,
    'temporal_severity': 'LOW',
    'user_interaction': 'NONE',
    'vector_string': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N',
    'version': '3.0'}
    """
    o = CVSS3(vector).as_json()
    return snakecase_dict(o)


def get_cvss2_metrics(vector: str) -> dict:
    """
    Returns a set of snakecased CVSS2 metrics for a given CVSS2 vector

    :param vector: CVSS2 vector (e.g. AV:N/AC:M/Au:N/C:N/I:P/A:N)
    :return: dict of CVSS2 metrics (e.g. {'access_complexity': 'MEDIUM', 'access_vector': 'NETWORK', ...})

    Example usage:

    >>> from pprint import pprint
    >>> metrics = get_cvss2_metrics('AV:N/AC:M/Au:N/C:N/I:P/A:N')
    >>> pprint(metrics)    
    {'access_complexity': 'MEDIUM',
    'access_vector': 'NETWORK',
    'authentication': 'NONE',
    'availability_impact': 'NONE',
    'availability_requirement': 'NOT_DEFINED',
    'base_score': 4.3,
    'collateral_damage_potential': 'NOT_DEFINED',
    'confidentiality_impact': 'NONE',
    'confidentiality_requirement': 'NOT_DEFINED',
    'environmental_score': 0.0,
    'exploitability': 'NOT_DEFINED',
    'integrity_impact': 'PARTIAL',
    'integrity_requirement': 'NOT_DEFINED',
    'remediation_level': 'NOT_DEFINED',
    'report_confidence': 'NOT_DEFINED',
    'target_distribution': 'NOT_DEFINED',
    'temporal_score': 0.0,
    'vector_string': 'AV:N/AC:M/Au:N/C:N/I:P/A:N',
    'version': '2.0'}
    """
    o = CVSS2(vector).as_json()
    return snakecase_dict(o)


def snakecase_dict(d: dict) -> dict:
    return {inflection.underscore(k): v for k, v in d.items()}


@dataclass()
class FeatureExtractor:
    path_to_cpes_file: str
    path_to_cves_file: str
    path_to_cve_change_history_file: str
    path_to_sources_file: str

    def iter_cpes(
            self, 
            cpe_ids: Optional[Iterable[str]] = None,
            cve_ids: Optional[Iterable[str]] = None,
            deprecated: Optional[bool] = None) -> Iterator[dict]:
        
        cpes = files.read_jsonl_file(self.path_to_cpes_file)
        
        if deprecated is not None:
            cpes = filter(lambda o: o['deprecated'] is deprecated, cpes)

        if cpe_ids:
            cpe_ids = frozenset(cpe_ids)
            cpes = filter(lambda o: o['id'] in cpe_ids, cpes)

        if cve_ids:
            m = self.get_cpe_to_cve_map(cve_ids=cve_ids, cpe_ids=cpe_ids)
            cpe_ids = frozenset(m.keys())
            cpes = filter(lambda o: o['id'] in cpe_ids, cpes)
            
        yield from cpes

    def iter_sources(
            self, 
            event_types: Optional[Iterable[str]] = None,
            source_ids: Optional[Iterable[str]] = None,
            cve_ids: Optional[Iterable[str]] = None, 
            cve_change_ids: Optional[Iterable[str]] = None,
            cpe_ids: Optional[Iterable[str]] = None) -> Iterator[dict]:
        
        sources = files.read_jsonl_file(self.path_to_sources_file)
        
        if any((event_types, cve_ids, cve_change_ids, cpe_ids)):
            history = self.iter_cve_change_history(
                event_types=event_types,
                source_ids=source_ids,
                cve_ids=cve_ids,
                cve_change_ids=cve_change_ids,
                cpe_ids=cpe_ids,
            )
            source_ids = {line['sourceIdentifier'] for line in history}
            if not source_ids:
                return

        if source_ids:
            source_ids = frozenset(source_ids)
            sources = filter(lambda o: any((source_id in source_ids for source_id in o['sourceIdentifiers'])), sources)

        yield from sources

    def get_cve(self, cve_id: str) -> Optional[dict]:
        for cve in self.iter_cves(cve_ids=[cve_id]):
            return cve
    
    def iter_cves(self, cve_ids: Optional[Iterable[str]] = None, cpe_ids: Optional[Iterable[str]] = None) -> Iterator[dict]:
        cves = files.read_jsonl_file(self.path_to_cves_file)
        yield from filter_cves(cves, cve_ids=cve_ids, cpe_ids=cpe_ids)

    def get_cve_ids_in_cisa_known_exploited_vulnerabilities_catalogue(self, cve_ids: Optional[Iterable[str]] = None, cpe_ids: Optional[Iterable[str]] = None) -> Iterator[dict]:
        history = self.iter_cisa_kev_update_events(cve_ids=cve_ids, cpe_ids=cpe_ids)
        return {line['cveId'] for line in history}

    def iter_cisa_kev_update_events(self, cve_ids: Optional[Iterable[str]] = None, cpe_ids: Optional[Iterable[str]] = None) -> Iterator[dict]:
        yield from self.iter_cve_change_history(event_types=[CVE_CISA_KEV_UPDATE], cve_ids=cve_ids, cpe_ids=cpe_ids)

    def iter_cve_change_history(
            self,
            event_types: Optional[Iterable[str]] = None,
            source_ids: Optional[Iterable[str]] = None,
            cve_ids: Optional[Iterable[str]] = None, 
            cve_change_ids: Optional[Iterable[str]] = None,
            cpe_ids: Optional[Iterable[str]] = None) -> Iterator[dict]:

        history = files.read_jsonl_file(self.path_to_cve_change_history_file)
        
        if event_types:
            event_types = frozenset(event_types)
            history = filter(lambda line: line['eventName'] in event_types, history)
        
        if cve_change_ids:
            cve_change_ids = frozenset(cve_change_ids)
            history = filter(lambda line: line['cveChangeId'] in cve_change_ids, history)

        if source_ids:
            source_ids = frozenset(source_ids)
            history = filter(lambda line: line['sourceIdentifier'] in source_ids, history)
        
        if not (cve_ids or cpe_ids):
            yield from history
        else:
            cve_ids = {cve['id'] for cve in self.iter_cves(cve_ids=cve_ids, cpe_ids=cpe_ids)}
            if cve_ids:
                for line in history:
                    cve_id = line['cveId']
                    if cve_id in cve_ids:
                        yield line

    def iter_cve_metrics(self, cve_ids: Optional[Iterable[str]] = None, cpe_ids: Optional[Iterable[str]] = None) -> Iterator[dict]:
        for cve in self.iter_cves(cve_ids=cve_ids, cpe_ids=cpe_ids):
            metrics = extract_primary_cvss_metrics_from_cve(cve)
            metrics['id'] = cve['id']
            yield metrics

    def get_cve_to_cpe_map(self, vulnerable: Optional[bool] = None) -> Dict[str, List[str]]:
        mappings = collections.defaultdict(list)
        for cve in files.read_jsonl_file(self.path_to_cves_file):
            cve_id = cve['id']
            for cpe_id in extract_cpe_ids_from_cve(cve, vulnerable=vulnerable):
                if cve_id not in mappings[cpe_id]:
                    mappings[cpe_id].append(cve_id)
        return dict(mappings)

    def get_cpe_to_cve_map(self, vulnerable: Optional[bool] = None) -> Dict[str, List[str]]:
        cve_to_cpe_mappings = self.get_cve_to_cpe_map(vulnerable=vulnerable)
        cpe_to_cve_mappings = collections.defaultdict(list)
        for cve_id, cpe_ids in cve_to_cpe_mappings.items():
            for cpe_id in cpe_ids:
                cpe_to_cve_mappings[cpe_id].append(cve_id)
        return dict(cpe_to_cve_mappings)


def filter_cves(
        cves: Iterable[dict],
        cve_ids: Optional[Iterable[str]] = None,
        cpe_ids: Optional[Iterable[str]] = None,
        vulnerable: bool = True) -> Iterator[str]:

    if cve_ids:
        cve_ids = frozenset(cve_ids)
        cves = filter(lambda cve: cve['id'] in cve_ids, cves)
    
    if cpe_ids:
        cpe_ids = frozenset(cpe_ids)
        cves = filter(lambda cve: bool(cpe_ids & set(extract_cpe_ids_from_cve(cve, vulnerable=vulnerable))), cves)

    yield from cves


def extract_primary_cvss_metrics_from_cve(cve: dict) -> dict:
    return {
        'cvss2': extract_primary_cvss2_metrics_from_cve(cve),
        'cvss3': extract_primary_cvss3_metrics_from_cve(cve),
    }


def extract_primary_cvss3_metrics_from_cve(cve: dict) -> Optional[dict]:
    metrics = cve.get('metrics')
    if metrics:
        for k in ['cvssMetricV31', 'cvssMetricV30']:
            if k in metrics:
                for m in metrics[k]:
                    if m['type'] == 'Primary':
                        return get_cvss3_metrics(m['vectorString'])


def extract_primary_cvss2_metrics_from_cve(cve: dict) -> Optional[dict]:
    metrics = cve.get('metrics')
    if metrics:
        for k in ['cvssMetricV2']:
            if k in metrics:
                for m in metrics[k]:
                    if m['type'] == 'Primary':
                        return get_cvss2_metrics(m['vectorString'])


def extract_cpe_ids_from_cve(cve: dict, vulnerable: Optional[bool] = True) -> List[str]:
    cpe_ids = list()
    for config in cve.get('configurations', []):
        for node in config['nodes']:
            for cpe in node['cpeMatch']:
                if vulnerable is not None and vulnerable != cpe['vulnerable']:
                    continue
                
                cpe_id = cpe['criteria']
                if cpe_id not in cpe_ids:
                    cpe_ids.append(cpe_id)
    return cpe_ids
