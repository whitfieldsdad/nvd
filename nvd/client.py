import collections
from dataclasses import dataclass
import dataclasses
import json

import os
import time

from urllib3 import Retry
from nvd.types.cpe import CPE
from nvd.types.cve import CVE
from nvd.types.cvss2 import CVSS2
from nvd.types.cvss3 import CVSS3
from nvd.types.weakness import Weakness
import nvd.types.parser as parser
from typing import Any, Dict, Iterable, Iterator, Optional, Set, Union
import requests
import logging
from nvd import files, util
import pandas as pd
import requests.adapters
import polars as pl

from nvd.constants import CPE_MATCH_CRITERIA, CPES, CVE_CHANGES, CVES, DEFAULT_FILE_FORMAT, SOURCES, WORKDIR

logger = logging.getLogger(__name__)

API_KEY = os.getenv("NIST_NVD_API_KEY")

_WRITE_BUFFER_SIZE = 10000


@dataclass()
class Client:
    workdir: str = WORKDIR
    api_key: str = API_KEY

    def __post_init__(self):
        if not self.api_key:
            raise ValueError("API key not provided - pass as an argument or set NIST_NVD_API_KEY environment variable")

        os.makedirs(self.workdir, exist_ok=True)

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

    @property
    def request_delay(self):
        return 0.06

    def _iter_objects(self, path: str, url: str, response_subkey: str, object_subkey: Optional[str] = None):
        if not os.path.exists(path):
            self._download_objects(path, url, response_subkey, object_subkey)
        yield from files.read_jsonl_file(path)
        
    def _download_objects(self, path: str, url: str, response_subkey: str, object_subkey: Optional[str] = None, force: bool = False):
        if force or not os.path.exists(path) or os.path.getsize(path) == 0:
            with open(path, 'w') as file:
                lines = []
                for o in self._iter_objects_from_web(url, response_subkey, object_subkey):
                    lines.append(json.dumps(o))
                    if len(lines) >= _WRITE_BUFFER_SIZE:
                        file.write('\n'.join(lines))
                        file.write('\n')
                        lines.clear()

    def _iter_objects_from_web(self, url: str, response_subkey: str, object_subkey: Optional[str] = None):
        session = requests.Session()
        session.headers = {
            "apiKey": self.api_key,
        }
        retry_strategy = Retry(
            total=5,
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
        )
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retry_strategy))

        response = session.get(url)
        params = {
            'startIndex': 0
        }
        response = session.get(url, params=params)
        response.raise_for_status()
        reply = response.json()

        for o in reply[response_subkey]:
            yield o[object_subkey] if object_subkey else o

        # Read any remaining pages.
        page_size = reply['resultsPerPage']
        total_results = reply['totalResults']

        while params['startIndex'] < total_results:
            response = session.get(url, params=params)
            response.raise_for_status()
            reply = response.json()

            for o in reply[response_subkey]:
                yield o[object_subkey] if object_subkey else o

            params['startIndex'] += page_size
            time.sleep(self.request_delay)
    
    def _get_pandas_dataframe(self, rows: Iterator[Any], drop_keys: Optional[Iterable[str]] = None) -> pl.DataFrame:
        df = self._get_polars_dataframe(rows, drop_keys=drop_keys)
        return df.to_pandas()
    
    def _get_polars_dataframe(self, rows: Iterator[Any], drop_keys: Optional[Iterable[str]] = None) -> pl.DataFrame:
        rows = [dataclasses.asdict(o) for o in rows]
        if drop_keys:
            rows = [util.drop_keys(o, drop_keys) for o in rows]

        return pl.DataFrame(rows, infer_schema_length=10000)
    
    def get_cve_to_cwe_mappings(self, cve_ids: Optional[Iterable[str]] = None) -> Dict[str, Set[str]]:
        m = {}
        for cve in self.iter_raw_cves(cve_ids=cve_ids):
            if 'weaknesses' in cve:
                weaknesses = parser.extract_cwe_ids_from_cve(cve)
                if weaknesses:
                    m[cve['id']] = weaknesses
        return m

    def get_cwe_to_cve_mappings(self, cve_ids: Optional[Iterable[str]] = None) -> Dict[str, Set[str]]:
        inv = collections.defaultdict(set)
        cve_ids_to_cwe_ids = self.get_cve_to_cwe_mappings(cve_ids=cve_ids)
        for cve_id, cwe_ids in cve_ids_to_cwe_ids.items():
            for cwe_id in cwe_ids:
                inv[cwe_id].add(cve_id)
        return inv
    
    def get_cve_to_cwe_mappings_as_polars_dataframe(self, cve_ids: Optional[Iterable[str]] = None) -> pl.DataFrame:
        m = self.get_cve_to_cwe_mappings(cve_ids=cve_ids)
        rows = []
        for cve_id, cwe_ids in m.items():
            for cwe_id in cwe_ids:
                rows.append({
                    'cve_id': cve_id,
                    'cwe_id': cwe_id,
                })
        df = pl.DataFrame(rows)
        return df
    
    def get_cve_to_cwe_mappings_as_pandas_dataframe(self, cve_ids: Optional[Iterable[str]] = None) -> pd.DataFrame:
        df = self.get_cve_to_cwe_mappings_as_polars_dataframe(cve_ids=cve_ids)
        return df.to_pandas()

    def get_cves_as_polars_dataframe(self) -> pl.DataFrame:
        return self._get_polars_dataframe(self.iter_cves(), drop_keys=['cvss2', 'cvss3'])
    
    def get_cves_as_pandas_dataframe(self) -> pd.DataFrame:
        return self._get_pandas_dataframe(self.iter_cves(), drop_keys=['cvss2', 'cvss3'])

    def iter_cves(self, cve_ids: Optional[Iterable[str]] = None) -> Iterator[CVE]:
        for cve in self.iter_raw_cves(cve_ids=cve_ids):
            yield parser.parse_cve(cve)

    def iter_raw_cves(self, cve_ids: Optional[Iterable[str]] = None) -> Iterator[dict]:
        if not os.path.exists(self.raw_cves_file):
            self.download_cves()
        
        cves = files.read_jsonl_file(self.raw_cves_file)
        if cve_ids:
            cves = filter(lambda cve: cve['id'] in cve_ids, cves)
        yield from cves

    def iter_raw_cve_change_events(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_cve_changes_file):
            self.download_cve_change_history()
        yield from files.read_jsonl_file(self.raw_cve_changes_file)

    def get_cpes_as_polars_dataframe(self) -> pl.DataFrame:
        rows = []
        for o in self.iter_cpes():
            row = dataclasses.asdict(o)
            rows.append(row)
        
        df = pl.DataFrame(rows)
        return df

    def get_cpes_as_pandas_dataframe(self) -> pd.DataFrame:
        df = self.get_cpes_as_polars_dataframe()
        return df.to_pandas()

    def iter_cpes(self) -> Iterator[CPE]:
        for cpe in self.iter_raw_cpes():
            yield parser.parse_cpe(cpe)

    def iter_raw_cpes(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_cpes_file):
            self.download_cpes()
        yield from files.read_jsonl_file(self.raw_cpes_file)

    def iter_raw_cpe_match_criteria(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_cpe_match_criteria_file):
            self.download_cpe_match_criteria()
        yield from files.read_jsonl_file(self.raw_cpe_match_criteria_file)

    def get_sources_as_polars_dataframe(self) -> pl.DataFrame:
        sources = [dataclasses.asdict(o) for o in self.iter_sources()]
        df = pl.DataFrame(sources)
        return df

    def get_sources_as_pandas_dataframe(self) -> pd.DataFrame:
        df = self.get_sources_as_polars_dataframe()
        return df.to_pandas()

    def iter_sources(self) -> Iterator[dict]:
        for source in self.iter_raw_sources():
            yield parser.parse_source(source)

    def iter_raw_sources(self) -> Iterator[dict]:
        if not os.path.exists(self.raw_sources_file):
            self.download_sources()
        yield from files.read_jsonl_file(self.raw_sources_file)

    def download_cves(self, force: bool = False):
        self._download_objects(self.raw_cves_file, 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'vulnerabilities', 'cve', force=force)

    def download_cve_change_history(self, force: bool = False):
        self._download_objects(self.raw_cve_changes_file, 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0', 'cveChanges', 'change', force=force)

    def download_cpes(self, force: bool = False):
        self._download_objects(self.raw_cpes_file, 'https://services.nvd.nist.gov/rest/json/cpes/2.0', 'products', 'cpe', force=force)

    def download_cpe_match_criteria(self, force: bool = False):
        self._download_objects(self.raw_cpe_match_criteria_file, 'https://services.nvd.nist.gov/rest/json/cpematch/2.0', 'matchStrings', 'matchString', force=force)
    
    def download_sources(self, force: bool = False):
        self._download_objects(self.raw_sources_file, 'https://services.nvd.nist.gov/rest/json/source/2.0', 'sources', force=force)
