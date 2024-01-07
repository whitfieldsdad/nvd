from typing import Any, Iterator, Optional
import click
from nvd.client import Client
import nvd.client as nvd
import json
import itertools
import logging

JSON_INDENT = 4


@click.group()
@click.option('--verbose', '-v')
@click.option('--indent', type=int, default=JSON_INDENT)
def main(verbose: bool, indent: int):
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if indent:
        global JSON_INDENT
        JSON_INDENT = indent


@main.command('cves')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cves(output_file: Optional[str], limit: Optional[int]):
    client = Client()
    rows = client.iter_cves()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@main.command('cve-changes')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cve_changes(output_file: Optional[str], limit: Optional[int]):
    client = Client()
    rows = client.iter_cve_change_history()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@main.command('cpes')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cpes(output_file: Optional[str], limit: Optional[int]):
    client = Client()
    rows = client.iter_cpes()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@main.command('cpe-match-criteria')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cpe_match_criteria(output_file: Optional[str], limit: Optional[int]):
    client = Client()
    rows = client.iter_cpe_match_criteria()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@main.command('sources')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_sources(output_file: Optional[str], limit: Optional[int]):
    client = Client()
    rows = client.iter_sources()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


def write_json_output(data: Any, output_file: Optional[str]):
    blob = json.dumps(data, indent=JSON_INDENT)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(blob)
    else:
        print(blob)


def write_jsonl_output(rows: Iterator[dict], output_file: Optional[str], limit: Optional[int]):
    rows = itertools.islice(rows, limit)
    if output_file:
        with open(output_file, 'w') as f:
            for row in rows:
                line = json.dumps(row) + '\n'
                f.write(line)
    else:
        for row in rows:
            print(json.dumps(row))


if __name__ == "__main__":
    main()
