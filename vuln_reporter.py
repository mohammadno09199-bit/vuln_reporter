import argparse
import json
import logging
import os
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("VulnReporterPlus")


# ----------------------------
# Models
# ----------------------------
@dataclass
class ServiceFingerprint:
    port: int
    service: str = "unknown"
    product: str = ""
    version: str = ""
    cpes: List[str] = None

    def normalized_query(self) -> str:
        q = f"{self.product} {self.version}".strip()
        return q if q else (self.service or "unknown")

    def key(self) -> str:
        cpe_part = ",".join(sorted(self.cpes or []))
        return f"{self.port}|{self.service}|{self.product}|{self.version}|{cpe_part}"


@dataclass
class VulnRecord:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_version: str
    severity: str
    published: str
    last_modified: str
    references: List[str]
    sources: List[str]  # e.g., ["NVD"]
    cisa_kev: bool = False
    cisa_due_date: str = ""
    cisa_ransomware_campaign: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ----------------------------
# HTTP helpers (Session + Retry)
# ----------------------------
def build_session(timeout: int = 20) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.request_timeout = timeout  # type: ignore
    return session


def http_get(session: requests.Session, url: str, *, params: Dict[str, Any] = None, headers: Dict[str, str] = None) -> requests.Response:
    timeout = getattr(session, "request_timeout", 20)
    return session.get(url, params=params, headers=headers, timeout=timeout)


def http_post(session: requests.Session, url: str, *, json_body: Dict[str, Any], headers: Dict[str, str] = None) -> requests.Response:
    timeout = getattr(session, "request_timeout", 20)
    return session.post(url, json=json_body, headers=headers, timeout=timeout)


# ----------------------------
# Nmap Parser
# ----------------------------
class NmapParser:
    """Parse Nmap XML/JSON and extract hosts + open ports + service fingerprints (including CPE when available)."""

    @staticmethod
    def parse_xml(file_path: Path) -> List[Dict[str, Any]]:
        hosts_data: List[Dict[str, Any]] = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address")
                ip = addr_elem.get("addr") if addr_elem is not None else "Unknown"

                open_ports: List[Dict[str, Any]] = []
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        state_elem = port.find("state")
                        if state_elem is None or state_elem.get("state") != "open":
                            continue

                        port_id = int(port.get("portid", 0))
                        service_elem = port.find("service")

                        service_name = "unknown"
                        product = ""
                        version = ""
                        cpes: List[str] = []

                        if service_elem is not None:
                            service_name = service_elem.get("name", "unknown")
                            product = service_elem.get("product", "") or ""
                            version = service_elem.get("version", "") or ""
                            # Extract CPEs if present: <cpe>cpe:/a:vendor:product:version</cpe>
                            for cpe_elem in service_elem.findall("cpe"):
                                if cpe_elem.text and cpe_elem.text.strip():
                                    cpes.append(cpe_elem.text.strip())

                        open_ports.append({
                            "port": port_id,
                            "service": service_name,
                            "product": product,
                            "version": version,
                            "cpes": sorted(list(set(cpes))),
                        })

                if open_ports:
                    hosts_data.append({"host": ip, "open_ports": open_ports})

            return hosts_data

        except ET.ParseError as e:
            logger.error(f"Failed to parse XML file: {e}")
            return []

    @staticmethod
    def parse_json(file_path: Path) -> List[Dict[str, Any]]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON file: {e}")
            return []


# ----------------------------
# CISA KEV (reputable enrichment)
# ----------------------------
class CISAKEVClient:
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, session: requests.Session):
        self.session = session
        self._kev_by_cve: Dict[str, Dict[str, Any]] = {}

    def load(self) -> None:
        logger.info("Loading CISA KEV feed ...")
        r = http_get(self.session, self.KEV_URL, params=None, headers={"User-Agent": "VulnReporterPlus/3.0"})
        r.raise_for_status()
        data = r.json()
        items = data.get("vulnerabilities", []) or []
        self._kev_by_cve = {}
        for it in items:
            cve = (it.get("cveID") or "").strip()
            if cve:
                self._kev_by_cve[cve.upper()] = it

        logger.info(f"CISA KEV loaded: {len(self._kev_by_cve)} CVEs")

    def enrich(self, v: VulnRecord) -> VulnRecord:
        it = self._kev_by_cve.get((v.cve_id or "").upper())
        if not it:
            return v
        v.cisa_kev = True
        v.cisa_due_date = it.get("dueDate", "") or ""
        v.cisa_ransomware_campaign = it.get("knownRansomwareCampaignUse", "") or ""
        return v


# ----------------------------
# NVD Client (CVE + CPE)
# ----------------------------
class NVDClient:
    """NVD API 2.0 client (CVE + CPE). Supports API key and rate limiting."""

    CVE_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CPE_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    def __init__(
        self,
        session: requests.Session,
        *,
        api_key: str = "",
        timeout: int = 20,
        delay: float = 0.8,
    ):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.api_key = api_key.strip()

        self.headers = {
            "User-Agent": "VulnReporterPlus/3.0 (Defensive Reporting Tool)",
        }
        if self.api_key:
            # NVD expects header name apiKey
            self.headers["apiKey"] = self.api_key

    def _sleep_rate_limit(self) -> None:
        time.sleep(self.delay)

    @staticmethod
    def _extract_cvss(cve_obj: Dict[str, Any]) -> Tuple[Optional[float], str, str]:
        metrics = cve_obj.get("metrics", {}) or {}

        def pick(metric_key: str, version_label: str) -> Optional[Tuple[float, str, str]]:
            arr = metrics.get(metric_key) or []
            if not arr:
                return None
            cvss_data = (arr[0].get("cvssData") or {})
            score = cvss_data.get("baseScore", None)
            sev = cvss_data.get("baseSeverity", "") or ""
            try:
                score_f = float(score) if score is not None else None
            except (ValueError, TypeError):
                score_f = None
            return (score_f, version_label, sev)

        for k, vlabel in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            got = pick(k, vlabel)
            if got:
                return got

        return (None, "N/A", "")

    @staticmethod
    def _extract_description_en(cve_obj: Dict[str, Any]) -> str:
        descs = cve_obj.get("descriptions", []) or []
        for d in descs:
            if d.get("lang") == "en" and d.get("value"):
                return d["value"]
        # fallback
        if descs and isinstance(descs[0], dict):
            return descs[0].get("value", "") or ""
        return "No description available."

    @staticmethod
    def _extract_references(cve_obj: Dict[str, Any], cve_id: str) -> List[str]:
        refs = []
        ref_data = cve_obj.get("references", []) or []
        for r in ref_data:
            url = r.get("url")
            if url:
                refs.append(url)
        # always include NVD detail page
        if cve_id and f"https://nvd.nist.gov/vuln/detail/{cve_id}" not in refs:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        # de-dup
        out = []
        seen = set()
        for x in refs:
            if x not in seen:
                out.append(x)
                seen.add(x)
        return out

    def search_cpe_candidates(self, keyword: str, max_candidates: int = 5) -> List[str]:
        """Find candidate CPE names via NVD CPE API based on keyword/product string."""
        if not keyword.strip():
            return []

        params = {
            "keywordSearch": keyword.strip(),
            "resultsPerPage": max(1, min(max_candidates, 20)),
        }

        self._sleep_rate_limit()
        r = http_get(self.session, self.CPE_BASE, params=params, headers=self.headers)
        if r.status_code >= 400:
            logger.warning(f"NVD CPE query failed ({r.status_code}) for keyword='{keyword}'")
            return []

        data = r.json()
        products = data.get("products", []) or []
        cpes: List[str] = []
        for p in products:
            cpe = (p.get("cpe") or {})
            name = cpe.get("cpeName")
            if name:
                cpes.append(name)

        # de-dup
        uniq = []
        seen = set()
        for c in cpes:
            if c not in seen:
                uniq.append(c)
                seen.add(c)
        return uniq[:max_candidates]

    def search_cves_by_cpe(self, cpe_name: str, limit: int = 10, start_index: int = 0) -> List[VulnRecord]:
        if not cpe_name.strip():
            return []

        params = {
            "cpeName": cpe_name.strip(),
            "resultsPerPage": max(1, min(limit, 2000)),
            "startIndex": max(0, start_index),
        }

        self._sleep_rate_limit()
        r = http_get(self.session, self.CVE_BASE, params=params, headers=self.headers)
        if r.status_code >= 400:
            logger.warning(f"NVD CVE by CPE failed ({r.status_code}) for cpe='{cpe_name}'")
            return []

        data = r.json()
        vulns = data.get("vulnerabilities", []) or []

        out: List[VulnRecord] = []
        for item in vulns:
            cve = item.get("cve", {}) or {}
            cve_id = cve.get("id", "Unknown") or "Unknown"

            score, cvss_ver, severity = self._extract_cvss(cve)
            desc_en = self._extract_description_en(cve)
            refs = self._extract_references(cve, cve_id)

            out.append(VulnRecord(
                cve_id=cve_id,
                description=desc_en,
                cvss_score=score,
                cvss_version=cvss_ver,
                severity=severity,
                published=cve.get("published", "") or "",
                last_modified=cve.get("lastModified", "") or "",
                references=refs,
                sources=["NVD"],
            ))

        return out

    def search_cves_by_keyword(self, query: str, limit: int = 10, start_index: int = 0) -> List[VulnRecord]:
        if not query.strip():
            return []

        params = {
            "keywordSearch": query.strip(),
            "resultsPerPage": max(1, min(limit, 2000)),
            "startIndex": max(0, start_index),
        }

        self._sleep_rate_limit()
        r = http_get(self.session, self.CVE_BASE, params=params, headers=self.headers)
        if r.status_code >= 400:
            logger.warning(f"NVD keyword search failed ({r.status_code}) for query='{query}'")
            return []

        data = r.json()
        vulns = data.get("vulnerabilities", []) or []

        out: List[VulnRecord] = []
        for item in vulns:
            cve = item.get("cve", {}) or {}
            cve_id = cve.get("id", "Unknown") or "Unknown"

            score, cvss_ver, severity = self._extract_cvss(cve)
            desc_en = self._extract_description_en(cve)
            refs = self._extract_references(cve, cve_id)

            out.append(VulnRecord(
                cve_id=cve_id,
                description=desc_en,
                cvss_score=score,
                cvss_version=cvss_ver,
                severity=severity,
                published=cve.get("published", "") or "",
                last_modified=cve.get("lastModified", "") or "",
                references=refs,
                sources=["NVD"],
            ))
        return out


# ----------------------------
# Aggregation / Reporter
# ----------------------------
class VulnerabilityReporterPlus:
    def __init__(
        self,
        input_path: str,
        output_path: str,
        *,
        max_cves_per_service: int = 20,
        cpe_candidates: int = 6,
        nvd_api_key: str = "",
        include_cisa_kev: bool = True,
        min_cvss: float = -1.0,
        delay: float = 0.8,
    ):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.max_cves_per_service = max_cves_per_service
        self.cpe_candidates = cpe_candidates
        self.include_cisa_kev = include_cisa_kev
        self.min_cvss = min_cvss

        self.session = build_session(timeout=20)
        self.nvd = NVDClient(self.session, api_key=nvd_api_key, delay=delay)
        self.cisa = CISAKEVClient(self.session)

        # simple in-memory cache to reduce repeated calls
        self._service_cache: Dict[str, List[VulnRecord]] = {}

    def _load_input(self) -> List[Dict[str, Any]]:
        if not self.input_path.is_file():
            logger.error(f"Input file not found: {self.input_path}")
            sys.exit(1)

        logger.info(f"Loading input file: {self.input_path}")
        suf = self.input_path.suffix.lower()
        if suf == ".xml":
            return NmapParser.parse_xml(self.input_path)
        if suf == ".json":
            return NmapParser.parse_json(self.input_path)

        logger.error("Unsupported file extension. Please provide an .xml or .json file.")
        sys.exit(1)

    @staticmethod
    def _dedup_merge(vulns: List[VulnRecord]) -> List[VulnRecord]:
        merged: Dict[str, VulnRecord] = {}
        for v in vulns:
            k = (v.cve_id or "").upper()
            if not k:
                continue
            if k not in merged:
                merged[k] = v
            else:
                # merge sources + references
                merged[k].sources = sorted(list(set((merged[k].sources or []) + (v.sources or []))))
                merged[k].references = sorted(list(set((merged[k].references or []) + (v.references or []))))
                # keep best cvss if one is missing
                if merged[k].cvss_score is None and v.cvss_score is not None:
                    merged[k].cvss_score = v.cvss_score
                    merged[k].cvss_version = v.cvss_version
                    merged[k].severity = v.severity
        return list(merged.values())

    def _sort_vulns(self, vulns: List[VulnRecord]) -> List[VulnRecord]:
        def score_key(v: VulnRecord) -> Tuple[int, float]:
            kev = 1 if v.cisa_kev else 0
            score = v.cvss_score if v.cvss_score is not None else -1.0
            return (kev, score)
        return sorted(vulns, key=score_key, reverse=True)

    def _filter_min_cvss(self, vulns: List[VulnRecord]) -> List[VulnRecord]:
        if self.min_cvss < 0:
            return vulns
        out = []
        for v in vulns:
            if v.cvss_score is None:
                continue
            if v.cvss_score >= self.min_cvss:
                out.append(v)
        return out

    def _collect_vulns_for_service(self, fp: ServiceFingerprint) -> List[VulnRecord]:
        cache_key = fp.key()
        if cache_key in self._service_cache:
            return self._service_cache[cache_key]

        found: List[VulnRecord] = []
        cpes = fp.cpes or []
        query = fp.normalized_query()

        # Strategy A: if Nmap already provided CPEs, use them directly (best accuracy)
        if cpes:
            logger.info(f"Using Nmap CPEs for port {fp.port}: {len(cpes)} CPE(s)")
            for cpe in cpes[: max(1, self.cpe_candidates)]:
                chunk = self.nvd.search_cves_by_cpe(cpe, limit=self.max_cves_per_service)
                found.extend(chunk)

        # Strategy B: derive CPE candidates from NVD CPE API and query CVEs by those CPEs
        if not found:
            logger.info(f"Finding CPE candidates via NVD for: '{query}'")
            cpe_candidates = self.nvd.search_cpe_candidates(query, max_candidates=self.cpe_candidates)
            for cpe in cpe_candidates:
                chunk = self.nvd.search_cves_by_cpe(cpe, limit=self.max_cves_per_service)
                found.extend(chunk)

        # Strategy C: fallback to keyword search (least accurate, but broader)
        if not found:
            logger.info(f"Fallback to NVD keyword search for: '{query}'")
            found.extend(self.nvd.search_cves_by_keyword(query, limit=self.max_cves_per_service))

        # de-dup + enrich with KEV
        found = self._dedup_merge(found)

        if self.include_cisa_kev:
            for v in found:
                self.cisa.enrich(v)

        found = self._filter_min_cvss(found)
        found = self._sort_vulns(found)

        # final clamp (after sorting)
        found = found[: self.max_cves_per_service]

        self._service_cache[cache_key] = found
        return found

    def run(self) -> None:
        hosts_data = self._load_input()

        if not hosts_data:
            logger.warning("No valid hosts or open ports found in the scan file.")
            return

        if self.include_cisa_kev:
            try:
                self.cisa.load()
            except Exception as e:
                logger.warning(f"Could not load CISA KEV feed (continuing without KEV): {e}")
                self.include_cisa_kev = False

        report: Dict[str, Any] = {
            "meta": {
                "tool": "VulnReporterPlus",
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "input_file": str(self.input_path),
                "providers": ["NVD"] + (["CISA_KEV"] if self.include_cisa_kev else []),
                "max_cves_per_service": self.max_cves_per_service,
                "cpe_candidates": self.cpe_candidates,
                "min_cvss": self.min_cvss,
            },
            "targets": []
        }

        for host_entry in hosts_data:
            host_ip = host_entry.get("host", "Unknown")
            open_ports = host_entry.get("open_ports", []) or []
            logger.info(f"Analyzing target: {host_ip} ({len(open_ports)} open ports)")

            host_result = {"host": host_ip, "services": []}

            for p in open_ports:
                fp = ServiceFingerprint(
                    port=int(p.get("port", 0)),
                    service=p.get("service", "unknown") or "unknown",
                    product=(p.get("product", "") or "").strip(),
                    version=(p.get("version", "") or "").strip(),
                    cpes=p.get("cpes", []) or [],
                )

                logger.info(f"Collecting vulnerabilities for port {fp.port} -> '{fp.normalized_query()}'")
                vulns = self._collect_vulns_for_service(fp)

                host_result["services"].append({
                    "port": fp.port,
                    "service": fp.service,
                    "product": fp.product,
                    "version": fp.version,
                    "cpes": fp.cpes or [],
                    "vulnerabilities_found": len(vulns),
                    "vulnerabilities": [v.to_dict() for v in vulns],
                })

            report["targets"].append(host_result)

        try:
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"Report successfully saved to: {self.output_path}")
        except OSError as e:
            logger.error(f"Failed to write output report: {e}")


# ----------------------------
# CLI
# ----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Match Nmap scan outputs (XML/JSON) with vulnerabilities using NVD + CISA KEV enrichment."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to Nmap scan file (scan.xml or scan.json)")
    parser.add_argument("-o", "--output", default="vulnerability_summary.json", help="Output JSON path")
    parser.add_argument("-l", "--limit", type=int, default=20, help="Max CVEs per service (default: 20)")
    parser.add_argument("--cpe-candidates", type=int, default=6, help="How many CPE candidates to try (default: 6)")
    parser.add_argument("--min-cvss", type=float, default=-1.0, help="Filter: only include CVEs with CVSS >= value (default: disabled)")
    parser.add_argument("--no-kev", action="store_true", help="Disable CISA KEV enrichment")
    parser.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY", ""), help="NVD API key (or set env NVD_API_KEY)")
    parser.add_argument("--delay", type=float, default=0.8, help="Delay between NVD requests for rate-limit safety (default: 0.8s)")

    args = parser.parse_args()

    reporter = VulnerabilityReporterPlus(
        input_path=args.input,
        output_path=args.output,
        max_cves_per_service=args.limit,
        cpe_candidates=args.cpe_candidates,
        nvd_api_key=args.nvd_api_key,
        include_cisa_kev=not args.no_kev,
        min_cvss=args.min_cvss,
        delay=args.delay,
    )
    reporter.run()


if __name__ == "__main__":
    main()
