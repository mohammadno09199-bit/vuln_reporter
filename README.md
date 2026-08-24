

````markdown
# NVD Vulnerability Reporter (Python)

A modular Python tool that analyzes Nmap JSON scan outputs and cross-references detected services/versions with the official **NIST NVD (National Vulnerability Database) API 2.0** to fetch known CVEs and CVSS scores.

> **Disclaimer:** This tool is strictly intended for educational purposes, local lab environments, and authorized security assessments.

---

## 🚀 Features

- Parses structured open-port scan data.
- Queries NIST NVD API 2.0 using keyword-based matching for product and version.
- Extracts CVE ID, CVSS score (v3.1 / v3.0 / v2), descriptions, and official reference links.
- Handles network timeouts, HTTP errors, and request exceptions gracefully.
- Exports structured, JSON-formatted vulnerability summary reports.

---

## 📋 Requirements

- Python 3.9+
- `requests` library

---

## 🛠️ Installation

```bash
git clone https://github.com/mohammadno09199-bit/vuln_reporter.git
cd vuln_reporter
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 💻 Usage

1. Place your `scan_report.json` in the project root directory.
2. Run the reporter:

```bash
python3 vuln_reporter.py
```

3. The generated summary will be saved to `vulnerability_summary.json`.

---

## 📄 License
MIT License
````

---
