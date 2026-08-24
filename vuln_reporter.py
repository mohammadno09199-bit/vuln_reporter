import argparse
import json
import logging
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests

# پیکربندی لاگ‌ها با فرمت خوانا
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("VulnReporter")


class NmapParser:
    """کلاس ویژه پارس کردن خروجی‌های مختلف Nmap (XML و JSON)."""

    @staticmethod
    def parse_xml(file_path: Path) -> List[Dict[str, Any]]:
        """استخراج اطلاعات هاست و پورت‌ها از فایل استاندارد XML ان‌مپ."""
        hosts_data = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for host in root.findall("host"):
                # بررسی وضعیت بالا بودن هاست (Up)
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                # استخراج آدرس IP
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address")
                
                ip = addr_elem.get("addr") if addr_elem is not None else "Unknown"
                
                open_ports = []
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        state_elem = port.find("state")
                        if state_elem is not None and state_elem.get("state") == "open":
                            port_id = int(port.get("portid", 0))
                            service_elem = port.find("service")
                            
                            service_name = "unknown"
                            product = ""
                            version = ""

                            if service_elem is not None:
                                service_name = service_elem.get("name", "unknown")
                                product = service_elem.get("product", "")
                                version = service_elem.get("version", "")

                            open_ports.append({
                                "port": port_id,
                                "service": service_name,
                                "product": product,
                                "version": version
                            })

                if open_ports:
                    hosts_data.append({
                        "host": ip,
                        "open_ports": open_ports
                    })

            return hosts_data

        except ET.ParseError as e:
            logger.error(f"Failed to parse XML file: {e}")
            return []

    @staticmethod
    def parse_json(file_path: Path) -> List[Dict[str, Any]]:
        """پارس کردن فایل‌های گزارش آماده در فرمت JSON."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON file: {e}")
            return []


class NVDClient:
    """کلاس ارتباط با NIST NVD API 2.0."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, timeout: int = 15, delay: float = 1.0):
        self.timeout = timeout
        self.delay = delay
        self.headers = {
            "User-Agent": "Security-Audit-Script/2.0 (Ethical Learning Project)"
        }

    def search_cves(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """جستجوی آسیب‌پذیری‌ها بر اساس کلیدواژه سرویس و نسخه."""
        if not query.strip():
            return []

        params = {
            "keywordSearch": query.strip(),
            "resultsPerPage": limit
        }

        try:
            time.sleep(self.delay)  # رعایت محدودیت نرخ ارسال درخواست (Rate Limit)
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            results = []
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown")

                # استخراج خلاصه توضیحات انگلیسی
                descriptions = cve.get("descriptions", [])
                desc_en = next(
                    (d.get("value") for d in descriptions if d.get("lang") == "en"),
                    "No description available."
                )

                # استخراج امتیاز CVSS به ترتیب اولویت نسخه‌ها
                metrics = cve.get("metrics", {})
                cvss_score = "N/A"
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                results.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "description": desc_en,
                    "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })

            return results

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout querying NVD for: '{query}'")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying NVD for '{query}': {e}")
            return []


class VulnerabilityReporter:
    """کلاس اصلی هماهنگ‌کننده فرایند تحلیل و ساخت گزارش."""

    def __init__(self, input_path: str, output_path: str, max_cves: int = 5):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.max_cves = max_cves
        self.nvd_client = NVDClient()

    def run(self) -> None:
        if not self.input_path.is_file():
            logger.error(f"Input file not found: {self.input_path}")
            sys.exit(1)

        # تشخیص خودکار فرمت فایل (XML یا JSON)
        logger.info(f"Loading input file: {self.input_path}")
        if self.input_path.suffix.lower() == ".xml":
            hosts_data = NmapParser.parse_xml(self.input_path)
        elif self.input_path.suffix.lower() == ".json":
            hosts_data = NmapParser.parse_json(self.input_path)
        else:
            logger.error("Unsupported file extension. Please provide an .xml or .json file.")
            sys.exit(1)

        if not hosts_data:
            logger.warning("No valid hosts or open ports found in the scan file.")
            return

        final_report = []

        for host_entry in hosts_data:
            host_ip = host_entry.get("host", "Unknown")
            open_ports = host_entry.get("open_ports", [])
            logger.info(f"Analyzing target: {host_ip} ({len(open_ports)} open ports)")

            host_result = {
                "host": host_ip,
                "services": []
            }

            for p in open_ports:
                port = p.get("port")
                service = p.get("service", "unknown")
                product = p.get("product", "").strip()
                version = p.get("version", "").strip()

                # ساخت کلیدواژه جستجو
                query = f"{product} {version}".strip() or service
                logger.info(f"Querying CVEs for Port {port} -> Service: '{query}'")

                cves = self.nvd_client.search_cves(query, limit=self.max_cves)

                host_result["services"].append({
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "vulnerabilities_found": len(cves),
                    "cve_list": cves
                })

            final_report.append(host_result)

        # ذخیره گزارش ساختاریافته در فایل خروجی
        try:
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(final_report, f, indent=2, ensure_ascii=False)
            logger.info(f"Report successfully saved to: {self.output_path}")
        except OSError as e:
            logger.error(f"Failed to write output report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="CLI Tool to match Nmap scan outputs (XML/JSON) with NIST NVD CVEs."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the Nmap scan file (e.g., scan.xml or scan.json)"
    )
    parser.add_argument(
        "-o", "--output",
        default="vulnerability_summary.json",
        help="Path to save the output JSON report (default: vulnerability_summary.json)"
    )
    parser.add_argument(
        "-l", "--limit",
        type=int,
        default=5,
        help="Max number of CVEs to fetch per service (default: 5)"
    )

    args = parser.parse_args()

    reporter = VulnerabilityReporter(
        input_path=args.input,
        output_path=args.output,
        max_cves=args.limit
    )
    reporter.run()


if __name__ == "__main__":
    main()
