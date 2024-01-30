from dataclasses import dataclass
import json

import os
import time
from typing import Iterator, Optional
import requests
import logging
from nvd import files, util

from nvd.constants import CPE_MATCH_CRITERIA, CPES, CVE_CHANGES, CVES, DEFAULT_FILE_FORMAT, SOURCES, WORKDIR

logger = logging.getLogger(__name__)

API_KEY = os.getenv("NIST_NVD_API_KEY")

_WRITE_BUFFER_SIZE = 10000


@dataclass()
class Client:
    workdir: str = WORKDIR
    file_format: str = DEFAULT_FILE_FORMAT
    api_key: str = API_KEY

    def __post_init__(self):
        if not self.api_key:
            raise ValueError("API key not provided - pass as an argument or set NIST_NVD_API_KEY environment variable")

        os.makedirs(self.workdir, exist_ok=True)

    @property
    def cves_file(self) -> str:
        return os.path.join(self.workdir, f'{CVES}.{self.file_format}')
    
    @property
    def cve_changes_file(self) -> str:
        return os.path.join(self.workdir, f'{CVE_CHANGES}.{self.file_format}')
    
    @property
    def cpes_file(self) -> str:
        return os.path.join(self.workdir, f'{CPES}.{self.file_format}')
    
    @property
    def cpe_match_criteria_file(self) -> str:
        return os.path.join(self.workdir, f'{CPE_MATCH_CRITERIA}.{self.file_format}')
    
    @property
    def sources_file(self) -> str:
        return os.path.join(self.workdir, f'{SOURCES}.{self.file_format}')

    @property
    def raw_cves_file(self) -> str:
        return os.path.join(self.workdir, f'{CVES}.jsonl')
    
    @property
    def raw_cve_changes_file(self) -> str:
        return os.path.join(self.workdir, f'{CVE_CHANGES}.jsonl')
    
    @property
    def raw_cpes_file(self) -> str:
        return os.path.join(self.workdir, f'{CPES}.jsonl')
    
    @property
    def raw_cpe_match_criteria_file(self) -> str:
        return os.path.join(self.workdir, f'{CPE_MATCH_CRITERIA}.jsonl')
    
    @property
    def raw_sources_file(self) -> str:
        return os.path.join(self.workdir, f'{SOURCES}.jsonl')

    def __post_init__(self):
        if not self.api_key:
            raise ValueError("API key not provided - pass as an argument or set NIST_NVD_API_KEY environment variable")

    @property
    def request_delay(self):
        return 0.06
    
    def _iter_objects(self, path: str, url: str, response_subkey: str, object_subkey: Optional[str] = None):
        if not os.path.exists(path):
            self._download_objects(path, url, response_subkey, object_subkey)
        yield from files.read_jsonl_file(path)
        
    def _download_objects(self, path: str, url: str, response_subkey: str, object_subkey: Optional[str] = None, force: bool = False):
        if force or not os.path.exists(path):
            with open(path, 'w') as file:
                lines = []
                for o in self._iter_objects_from_web(url, response_subkey, object_subkey):
                    lines.append(json.dumps(o))
                    if len(lines) >= _WRITE_BUFFER_SIZE:
                        file.write('\n'.join(lines))
                        file.write('\n')
                        lines.clear()

    def _iter_objects_from_web(self, url: str, response_subkey: str, object_subkey: Optional[str] = None):
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
        if not os.path.exists(self.raw_cves_file):
            self.download_cves()
        yield from files.read_jsonl_file(self.raw_cves_file)

    def iter_cve_change_history(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_cve_changes_file):
            self.download_cve_change_history()
        yield from files.read_jsonl_file(self.raw_cve_changes_file)

    def iter_cpes(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_cpes_file):
            self.download_cpes()
        yield from files.read_jsonl_file(self.raw_cpes_file)

    def iter_cpe_match_criteria(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_cpe_match_criteria_file):
            self.download_cpe_match_criteria()
        yield from files.read_jsonl_file(self.raw_cpe_match_criteria_file)

    def iter_sources(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_sources_file):
            self.download_sources()
        yield from files.read_jsonl_file(self.raw_sources_file)

    def download_cves(self, force: bool = False):
        self._download_objects(self.raw_cves_file, 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'vulnerabilities', 'cve', force=force)

    def download_cve_change_history(self, force: bool = False):
        self._download_objects(self.raw_cve_changes_file, 'https://services.nvd.nist.gov/rest/json/cve/1.0', 'CVE_Items', 'cve', force=force)

    def download_cpes(self, force: bool = False):
        self._download_objects(self.raw_cpes_file, 'https://services.nvd.nist.gov/rest/json/cpes/1.0', 'products', 'cpe', force=force)

    def download_cpe_match_criteria(self, force: bool = False):
        self._download_objects(self.raw_cpe_match_criteria_file, 'https://services.nvd.nist.gov/rest/json/cpematch/1.0', 'matchStrings', 'matchString', force=force)
    
    def download_sources(self, force: bool = False):
        self._download_objects(self.raw_sources_file, 'https://services.nvd.nist.gov/rest/json/source/1.0', 'sources', 'source', force=force)
