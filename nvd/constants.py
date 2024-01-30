import datetime
import os
import tempfile
from typing import Iterable, Union

# Cache directory
PRODUCT_UUID = '6a58b13b-8c2d-4e90-a53a-b14ed31071c7'
WORKDIR = os.path.join(tempfile.gettempdir(), PRODUCT_UUID)

# Data types
CVES = 'cves'
CVE_CHANGES = 'cve_changes'
CPES = 'cpes'
CPE_MATCH_CRITERIA = 'cpe_match_criteria'
SOURCES = 'sources'

# Type hints
TIME = Union[datetime.date, datetime.datetime, str, int, float]
STRS = Iterable[str]

# File formats
CSV = 'csv'
JSON = 'json'
JSONL = 'jsonl'
PARQUET = 'parquet'

FILE_FORMATS = [CSV, JSON, JSONL, PARQUET]
DEFAULT_FILE_FORMAT = PARQUET

# CVE change history event types
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
