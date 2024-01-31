from typing import Iterator, Optional, Set
from cvss import CVSS2 as _CVSS2, CVSS3 as _CVSS3
from nvd import util
from nvd.types.cve import CVE
from nvd.types.cvss2 import CVSS2
from nvd.types.cvss3 import CVSS3
from nvd.types.cpe import CPE

import cpe

from nvd.types.source import Source


def parse_cve(cve: dict) -> CVE:
    return CVE(
        id=cve['id'],
        name=cve.get('cisaVulnerabilityName'),
        description=next((d['value'] for d in cve['descriptions'] if d['lang'] == 'en'), None),
        create_time=util.parse_datetime(cve['published']),
        update_time=util.parse_datetime(cve['lastModified']),
        status=cve['vulnStatus'],
        evaluator_impact=cve.get('evaluatorImpact'),
        cvss2=_extract_primary_cvss2_metrics_from_cve(cve),
        cvss3=_extract_primary_cvss3_metrics_from_cve(cve),
    )


def _extract_primary_cvss3_metrics_from_cve(cve: dict) -> Optional[CVSS3]:
    metrics = cve.get('metrics')
    if metrics:
        for k in ['cvssMetricV31', 'cvssMetricV30']:
            if k in metrics:
                for m in metrics[k]:
                    if m['type'] == 'Primary':
                        return parse_cvss3_vector(m['cvssData']['vectorString'])


def _extract_primary_cvss2_metrics_from_cve(cve: dict) -> Optional[CVSS2]:
    metrics = cve.get('metrics')
    if metrics:
        for k in ['cvssMetricV2']:
            if k in metrics:
                for m in metrics[k]:
                    if m['type'] == 'Primary':
                        return parse_cvss2_vector(m['cvssData']['vectorString'])


def parse_cpe(cpe: dict) -> CPE:
    title = next((d['title'] for d in cpe.get('titles', []) if d['lang'] == 'en'), None)
    deprecated = cpe.get('deprecated', False)
    
    return CPE(
        id=cpe['cpeName'],
        name=title,
        create_time=util.parse_datetime(cpe['created']),
        update_time=util.parse_datetime(cpe['lastModified']),
        deprecated=deprecated,
        deprecated_by=[o['cpeName'] for o in cpe.get('deprecatedBy', []) if deprecated],
    )


def parse_cpe_id(cpe_id: str) -> CPE:
    return cpe.parse(cpe_id)


def parse_cvss3_vector(vector: str) -> CVSS3:
    o = _CVSS3(vector).as_json()
    d = util.snakecase_dict(o)
    return CVSS3(**d)


def parse_cvss2_vector(vector: str) -> CVSS2:
    o = _CVSS2(vector).as_json()
    d = util.snakecase_dict(o)
    return CVSS2(**d)


def parse_source(o: dict) -> Source:
    return Source(
        name=o['name'],
        contact_email=o.get('contactEmail') or None,
        source_identifiers=o['sourceIdentifiers'],
        create_time=util.parse_datetime(o['created']),
        update_time=util.parse_datetime(o['lastModified']),
    )


def extract_cwe_ids_from_cve(o: dict) -> Set[str]:
    cwe_ids = set()
    for weakness in o.get('weaknesses', []):
        for description in weakness['description']:
            if description['lang'] == 'en':
                value = description['value']
                if value.startswith('CWE-'):
                    cwe_id = value
                    cwe_ids.add(cwe_id)
    return cwe_ids
