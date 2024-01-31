from dataclasses import dataclass
import datetime
from typing import Optional


@dataclass()
class CPE:
    id: str
    name: Optional[str]
    create_time: datetime.datetime
    update_time: datetime.datetime
    deprecated: bool
    deprecated_by: Optional[str]

    def is_deprecated(self) -> bool:
        return self.deprecated
