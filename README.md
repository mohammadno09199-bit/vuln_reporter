# VulnReporterPlus

**VulnReporterPlus** is a defensive Python tool that reads **Nmap scan results (XML/JSON)**, extracts open services (and CPEs when available), then queries **NVD (NIST)** to find related **CVEs**. Optionally, it enriches results with **CISA KEV** to highlight vulnerabilities that are known to be exploited in the wild.

The output is a single **JSON report** that you can use for triage, patch prioritization, and reporting.

---

## What it does

For each host and open port found in an Nmap scan:

1. Collects service info (service name / product / version / CPEs if present)
2. Finds relevant vulnerabilities using NVD:
   - **Best case:** query by Nmap-provided **CPEs**
   - Otherwise: search for **CPE candidates** via NVD CPE API, then query CVEs by those CPEs
   - Fallback: **keyword search** on NVD (broader, less accurate)
3. (Optional) Enriches each CVE with **CISA KEV** details:
   - whether it is in KEV
   - due date
   - ransomware campaign usage flag (if present)

---

## Features

- Supports **Nmap XML** and **Nmap JSON** inputs
- Uses **NVD API 2.0** for CVE and CPE lookups
- Optional **CISA KEV** enrichment (high confidence “exploited in the wild” signal)
- Built-in HTTP retries for common transient errors ($429$, $5xx$)
- Simple in-memory caching to reduce repeated calls per identical service fingerprint
- Filters and sorting:
  - Optional minimum CVSS filter (`--min-cvss`)
  - Prioritizes KEV items first, then higher CVSS

---

## Requirements

- Python 3.9+ (recommended)
- Python package:
  - `requests`

Network access is required to query:
- NVD API: `https://services.nvd.nist.gov/`
- CISA KEV feed (optional): `https://www.cisa.gov/`

---

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

(If you have a `requirements.txt`, you can use that instead.)

---

## Usage

Main script example:

```bash
python3 vuln_reporter_plus.py -i scan.xml -o vulnerability_summary.json
```

### Input formats

- XML: `-i scan.xml` (typical output from Nmap)
- JSON: `-i scan.json` (a JSON structure matching the parser expectations)

### Common examples

Limit CVEs per service:

```bash
python3 vuln_reporter_plus.py -i scan.xml -o report.json -l 10
```

Try more/less CPE candidates:

```bash
python3 vuln_reporter_plus.py -i scan.xml -o report.json --cpe-candidates 8
```

Only include CVEs with $CVSS \ge 7.0$:

```bash
python3 vuln_reporter_plus.py -i scan.xml -o report.json --min-cvss 7.0
```

Disable CISA KEV enrichment:

```bash
python3 vuln_reporter_plus.py -i scan.xml -o report.json --no-kev
```

Set a delay between NVD requests (rate-limit safety):

```bash
python3 vuln_reporter_plus.py -i scan.xml -o report.json --delay 1.2
```

Provide an NVD API key (recommended for better rate limits):

```bash
python3 vuln_reporter_plus.py -i scan.xml -o report.json --nvd-api-key "YOUR_KEY"
```

Or via environment variable:

```bash
export NVD_API_KEY="YOUR_KEY"
python3 vuln_reporter_plus.py -i scan.xml -o report.json
```

---

## CLI Options

- `-i, --input` : Path to Nmap scan file (`.xml` or `.json`) **(required)**
- `-o, --output` : Output JSON path (default: `vulnerability_summary.json`)
- `-l, --limit` : Max CVEs per service (default: $20$)
- `--cpe-candidates` : How many CPE candidates to try (default: $6$)
- `--min-cvss` : Only include CVEs with $CVSS \ge$ value (default: disabled)
- `--no-kev` : Disable CISA KEV enrichment
- `--nvd-api-key` : NVD API key (or set `NVD_API_KEY`)
- `--delay` : Delay between NVD requests in seconds (default: $0.8$)

---

## Output

A JSON report is produced at the path you specify with `-o`.

High-level structure:

- `meta`: tool info and settings used
- `targets`: list of hosts
  - each host has `services`
    - each service includes detected fingerprint + a list of `vulnerabilities`

Each vulnerability entry includes fields like:

- `cve_id`
- `description`
- `cvss_score`, `cvss_version`, `severity`
- `published`, `last_modified`
- `references`
- `sources` (e.g., `["NVD"]`)
- `cisa_kev`, `cisa_due_date`, `cisa_ransomware_campaign` (if KEV is enabled)

---

## Notes / Accuracy

- Results are best when Nmap provides **CPEs** (e.g., using version detection).
- Keyword-based matching is broader and may include unrelated CVEs.
- KEV enrichment is a strong signal, but you should still validate impact in your own environment.

---

## Responsible Use

This project is intended for **defensive security**, reporting, and patch prioritization.

---

## License

MIT License
