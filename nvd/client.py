import collections
from dataclasses import dataclass
from nvd import files

import os
import time
from typing import Dict, Iterator, List, Optional
import requests
import logging

logger = logging.getLogger(__name__)

API_KEY = os.getenv("NIST_NVD_API_KEY")


@dataclass()
class Client:
    api_key: str = API_KEY

    def __post_init__(self):
        if not self.api_key:
            raise ValueError("API key not provided - pass as an argument or set NIST_NVD_API_KEY environment variable")

    @property
    def request_delay(self):
        return 0.06
        
    def _iter_objects(self, url: str, response_subkey: str, object_subkey: Optional[str] = None):
        response = requests.get(url)
        headers = {
            "apiKey": self.api_key,
        }
        params = {
            'startIndex': 0
        }
        response = requests.get(url, headers=headers)
        reply = response.json()

        for o in reply[response_subkey]:
            yield o[object_subkey] if object_subkey else o

        # Read any remaining pages.
        page_size = reply['resultsPerPage']
        total_results = reply['totalResults']

        while params['startIndex'] < total_results:
            response = requests.get(url, headers=headers, params=params)
            reply = response.json()

            for o in reply[response_subkey]:
                yield o[object_subkey] if object_subkey else o

            params['startIndex'] += page_size
            time.sleep(self.request_delay)
        
    def iter_cves(self) -> Iterator[dict]:
        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        yield from self._iter_objects(url, 'vulnerabilities', 'cve')

    def iter_cve_change_history(self) -> Iterator[dict]:
        url = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0'
        yield from self._iter_objects(url, 'cveChanges', 'change')

    def iter_cpes(self) -> Iterator[dict]:
        url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
        yield from self._iter_objects(url, 'products', 'cpe')

    def iter_cpe_match_criteria(self) -> Iterator[dict]:
        url = 'https://services.nvd.nist.gov/rest/json/cpematch/2.0'
        yield from self._iter_objects(url, 'matchStrings', 'matchString')

    def iter_sources(self) -> Iterator[dict]:
        url = 'https://services.nvd.nist.gov/rest/json/source/2.0'
        yield from self._iter_objects(url, 'sources')
    
    def get_cve_to_cpe_map(self, path_to_cves: str, vulnerable: bool = True) -> Dict[str, List[str]]:
        return get_cve_to_cpe_map(path_to_cves, vulnerable=vulnerable)
    
    def get_cpe_to_cve_map(self, path_to_cves: str, vulnerable: bool = True) -> Dict[str, List[str]]:
        return get_cpe_to_cve_map(path_to_cves, vulnerable=vulnerable)


def get_cve_to_cpe_map(path_to_cves: str, vulnerable: bool = True) -> Dict[str, List[str]]:
    mappings = collections.defaultdict(list)
    for cve in files.read_jsonl_file(path_to_cves):
        cve_id = cve['id']

        for config in cve.get('configurations', []):
            for node in config['nodes']:
                for cpe in node['cpeMatch']:
                    cpe_id = cpe['criteria']
                    if vulnerable is not None and vulnerable != cpe['vulnerable']:
                        continue
                    
                    if cpe_id not in mappings[cve_id]:
                        mappings[cve_id].append(cpe_id)
                        
    return dict(mappings)


def get_cpe_to_cve_map(path_to_cves: str, vulnerable: bool = True) -> Dict[str, List[str]]:
    cve_to_cpe_mappings = get_cve_to_cpe_map(path_to_cves, vulnerable=vulnerable)
    cpe_to_cve_mappings = collections.defaultdict(list)
    for cve_id, cpe_ids in cve_to_cpe_mappings.items():
        for cpe_id in cpe_ids:
            cpe_to_cve_mappings[cpe_id].append(cve_id)
    
    return dict(cpe_to_cve_mappings)
