import dataclasses
from json import JSONEncoder as _JSONEncoder

import datetime


class JSONEncoder(_JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        elif dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        else:
            return super().default(o)