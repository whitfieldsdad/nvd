import json
from typing import Iterator


def read_jsonl_file(path: str) -> Iterator[dict]:
    with open(path, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                yield json.loads(line)
