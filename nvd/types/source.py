from dataclasses import dataclass
import datetime
from typing import List, Optional


@dataclass()
class Source:
    name: str
    create_time: datetime.datetime
    update_time: datetime.datetime
    contact_email: Optional[str]
    source_identifiers: List[str]
