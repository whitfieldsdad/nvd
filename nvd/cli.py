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


@click.group()
@click.option('--workdir', '-w', default=nvd.WORKDIR)
@click.option('--verbose', '-v')
@click.pass_context
def main(ctx: click.Context, workdir: str, verbose: bool):
    """
    Client for NIST NVD API
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level)

    ctx.obj = Client(workdir=workdir)


@main.group('query')
def query():
    """
    Query data
    """


@query.command('cves')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
@click.pass_context
def list_cves(ctx: click.Context, output_file: Optional[str], limit: Optional[int]):
    """
    CVEs
    """
    client: Client = ctx.obj
    rows = client.iter_cves()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@query.command('cve-changes')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
@click.pass_context
def list_cve_changes(ctx: click.Context, output_file: Optional[str], limit: Optional[int]):
    """
    Events related to CVEs
    """
    client: Client = ctx.obj
    rows = client.iter_cve_change_history()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@query.command('cpes')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
@click.pass_context
def list_cpes(ctx: click.Context, output_file: Optional[str], limit: Optional[int]):
    """
    CPEs
    """
    client: Client = ctx.obj
    rows = client.iter_cpes()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@query.command('cpe-match-criteria')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
@click.pass_context
def list_cpe_match_criteria(ctx: click.Context, output_file: Optional[str], limit: Optional[int]):
    """
    CPE match criteria
    """
    client: Client = ctx.obj
    rows = client.iter_cpe_match_criteria()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@query.command('sources')
@click.option('--output-file', '-o')
@click.option('--limit', type=int)
@click.pass_context
def list_sources(ctx: click.Context, output_file: Optional[str], limit: Optional[int]):
    """
    Data sources
    """
    client: Client = ctx.obj
    rows = client.iter_sources()
    write_jsonl_output(rows, output_file=output_file, limit=limit)


@main.group('download')
def download():
    """
    Download data
    """


@download.command('cves')
@click.option('--force', '-f', is_flag=True)
@click.pass_context
def download_cves(ctx: click.Context, force: bool):
    """
    CVEs
    """
    client: Client = ctx.obj
    client.download_cves(force=force)


@download.command('cve-changes')
@click.option('--force', '-f', is_flag=True)
@click.pass_context
def download_cve_changes(ctx: click.Context, force: bool):
    """
    Events related to CVEs
    """
    client: Client = ctx.obj
    client.download_cve_change_history(force=force)


@download.command('cpes')
@click.option('--force', '-f', is_flag=True)
@click.pass_context
def download_cpes(ctx: click.Context, force: bool):
    """
    CPEs
    """
    client: Client = ctx.obj
    client.download_cpes(force=force)


@download.command('cpe-match-criteria')
@click.option('--force', '-f', is_flag=True)
@click.pass_context
def download_cpe_match_criteria(ctx: click.Context, force: bool):
    """
    CPE match criteria
    """
    client: Client = ctx.obj
    client.download_cpe_match_criteria(force=force)



@download.command('sources')
@click.option('--force', '-f', is_flag=True)
@click.pass_context
def download_sources(ctx: click.Context, force: bool):
    """
    Data sources
    """
    client: Client = ctx.obj
    client.download_sources(force=force)


@query.command('all')
@click.option('--force', '-f', is_flag=True)
@click.option('--delay', type=int, default=30, help='Delay between batches of requests to avoid being rate limited')
@click.pass_context
def download_all(ctx: click.Context, force: bool, delay: int):
    """
    Download all data
    """
    targets = {
        download_cves,
        download_cve_changes,
        download_cpes,
        download_cpe_match_criteria,
        download_sources,
    }
    for f in targets:
        ctx.invoke(f, force=force)
        logger.info('Sleeping for %d seconds...', delay)
        time.sleep(delay)


def write_json_output(data: Any, output_file: Optional[str]):
    blob = json.dumps(data, indent=4)
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
