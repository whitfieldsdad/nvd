import json
from typing import Iterable, Iterator


def read_jsonl_file(path: str) -> Iterator[dict]:
    with open(path, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl_file(path: str, rows: Iterable[dict]) -> Iterator[dict]:
    with open(path, 'w') as file:
        for row in rows:
            file.write(json.dumps(row))
            file.write('\n')
