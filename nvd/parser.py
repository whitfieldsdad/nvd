from typing import Optional
from cvss import CVSS2 as _CVSS2, CVSS3 as _CVSS3
from nvd import util
from nvd.types.cve import CVE
from nvd.types.cvss2 import CVSS2
from nvd.types.cvss3 import CVSS3
from cpe import CPE

import cpe


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
                        return parse_cvss3_vector(m['vectorString'])


def _extract_primary_cvss2_metrics_from_cve(cve: dict) -> Optional[CVSS2]:
    metrics = cve.get('metrics')
    if metrics:
        for k in ['cvssMetricV2']:
            if k in metrics:
                for m in metrics[k]:
                    if m['type'] == 'Primary':
                        return parse_cvss2_vector(m['vectorString'])


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
