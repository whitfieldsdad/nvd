from dataclasses import dataclass
import datetime
from typing import Optional

from nvd.types.cvss2 import CVSS2
from nvd.types.cvss3 import CVSS3


@dataclass()
class CVE:
    id: str
    name: Optional[str]
    description: Optional[str]
    create_time: datetime.datetime
    update_time: datetime.datetime
    status: Optional[str]
    evaluator_impact: Optional[str]
    cvss2: Optional[CVSS2]
    cvss3: Optional[CVSS3]
