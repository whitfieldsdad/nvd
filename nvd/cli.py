import os
import time
from typing import Any, Iterator, Optional
import click
from nvd.client import Client
import nvd.client as nvd
import json
import itertools
import logging

logger = logging.getLogger(__name__)

JSON_INDENT = 4


@click.group()
@click.option('--verbose', '-v')
@click.option('--indent', type=int, default=JSON_INDENT)
def main(verbose: bool, indent: int):
    """
    Client for NIST NVD API
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if indent:
        global JSON_INDENT
        JSON_INDENT = indent


@main.group('download')
def download():
    """
    Download data
    """


@download.command('cves')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cves(output_file: Optional[str], limit: Optional[int]):
    """
    CVEs
    """
    client = Client()
    rows = client.iter_cves()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@download.command('cve-changes')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cve_changes(output_file: Optional[str], limit: Optional[int]):
    """
    Events related to CVEs
    """
    client = Client()
    rows = client.iter_cve_change_history()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@download.command('cpes')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cpes(output_file: Optional[str], limit: Optional[int]):
    """
    CPEs
    """
    client = Client()
    rows = client.iter_cpes()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@download.command('cpe-match-criteria')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_cpe_match_criteria(output_file: Optional[str], limit: Optional[int]):
    """
    CPE match criteria
    """
    client = Client()
    rows = client.iter_cpe_match_criteria()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@download.command('sources')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
def list_sources(output_file: Optional[str], limit: Optional[int]):
    """
    Data sources
    """
    client = Client()
    rows = client.iter_sources()
    write_jsonl_output(rows, output_file=output_file, limit=limit)



@download.command('all')
@click.option('--output-dir', '-o')
@click.option('--limit', type=int)
@click.option('--delay', type=int, default=30, help='Delay between batches of requests to avoid being rate limited')
@click.pass_context
def download_all(ctx: click.Context, output_dir: str, limit: Optional[int], delay: int):
    """
    Download all data
    """
    targets = {
        list_cves: os.path.join(output_dir, 'cves.jsonl'),
        list_cve_changes: os.path.join(output_dir, 'cve-changes.jsonl'),
        list_cpes: os.path.join(output_dir, 'cpes.jsonl'),
        list_cpe_match_criteria: os.path.join(output_dir, 'cpe-match-criteria.jsonl'),
        list_sources: os.path.join(output_dir, 'sources.jsonl'),
    }
    for f, output_file in targets.items():
        ctx.invoke(f, output_file=output_file, limit=limit)
        logger.info('Sleeping for %d seconds...', delay)
        time.sleep(delay)


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
