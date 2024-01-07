# A Python 3 client for the NIST National Vulnerability Database (NVD)

## Features

- List information about [vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities), [products](https://nvd.nist.gov/developers/products), and [data sources](https://nvd.nist.gov/developers/data-sources) in JSONL format

## Usage

### Command line interface

#### List all CVEs

```bash
poetry run nvd cves | jq
```

```bash
poetry run nvd cves -o cves.jsonl
```

#### List changes for all CVEs

```bash
poetry run nvd cve-changes | jq
```

```bash
poetry run nvd cve-changes -o cve-changes.jsonl
```

#### List all CPEs

```bash
poetry run nvd cpes | jq
```

```bash
poetry run nvd cpes -o cpes.jsonl
```

#### List match criteria for all CPEs

```bash
poetry run nvd cpe-match-criteria | jq
```

```bash
poetry run nvd cpe-match-criteria -o cpe-match-criteria.jsonl
```

#### List all data sources

```bash
poetry run nvd data-sources | jq
```

```bash
poetry run nvd data-sources -o data-sources.jsonl
```
