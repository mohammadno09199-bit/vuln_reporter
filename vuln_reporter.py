import json
import logging
from pathlib import Path
from typing import Any, Dict, List
import requests

# تنظیم فرمت لاگ‌ها در خط فرمان
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)


class VulnReporter:
    """تحلیل گزارش Nmap و استخراج آسیب‌پذیری‌های مرتبط از پایگاه رسمی NIST NVD."""

    def __init__(self, input_file: str = "scan_report.json") -> None:
        self.input_file = Path(input_file)
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # ارسال User-Agent استاندارد برای ممانعت از مسدود شدن درخواست توسط سرور
        self.headers = {
            "User-Agent": "Security-Audit-Script/1.0 (Ethical Learning Project)"
        }

    def load_scan_data(self) -> Dict[str, Any]:
        """اعتبارسنجی و خواندن فایل JSON خروجی اسکن."""
        if not self.input_file.exists():
            raise FileNotFoundError(f"File not found: {self.input_file}")

        with open(self.input_file, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as err:
                raise ValueError(f"Invalid JSON format: {err}")

    def query_vulnerabilities(
        self, product: str, version: str = ""
    ) -> List[Dict[str, Any]]:
        """ارسال درخواست به NIST NVD بر اساس نام و نسخه محصول."""
        product_clean = product.strip()
        version_clean = version.strip()

        if not product_clean:
            return []

        # ترکیب نام محصول و نسخه برای افزایش دقت نتایج
        search_query = f"{product_clean} {version_clean}".strip()

        params = {
            "keywordSearch": search_query,
            "resultsPerPage": 5  # دریافت ۵ آسیب‌پذیری اول برای هر سرویس
        }

        try:
            response = requests.get(
                self.api_url,
                params=params,
                headers=self.headers,
                timeout=20  # مهلت ۲۰ ثانیه‌ای برای پاسخ شبکه
            )
            response.raise_for_status()
            data = response.json()

        except requests.Timeout:
            logging.warning(
                f"Request timed out while querying NIST NVD for: '{search_query}'"
            )
            return []
        except requests.HTTPError as http_err:
            logging.warning(
                f"HTTP error from NIST NVD for '{search_query}': {http_err}"
            )
            return []
        except requests.RequestException as req_err:
            logging.warning(
                f"Network error while querying NIST NVD for '{search_query}': {req_err}"
            )
            return []

        results: List[Dict[str, Any]] = []

        # استخراج فیلدهای کلیدی از پاسخ ساختاریافته NIST
        for item in data.get("vulnerabilities", []):
            cve_dict = item.get("cve", {})
            cve_id = cve_dict.get("id", "N/A")

            # استخراج خلاصه توضیحات انگلیسی
            summary = "No English description available."
            for desc in cve_dict.get("descriptions", []):
                if desc.get("lang") == "en":
                    summary = desc.get("value", "")
                    break

            # استخراج امتیاز CVSS (نسخه ۳.۱، ۳.۰ یا ۲)
            metrics = cve_dict.get("metrics", {})
            score: Any = "N/A"
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_entries = metrics.get(metric_key, [])
                if metric_entries:
                    score = metric_entries[0].get("cvssData", {}).get("baseScore", "N/A")
                    break

            results.append({
                "id": cve_id,
                "cvss_score": score,
                "summary": (summary[:140] + "...") if len(summary) > 140 else summary,
                "reference_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

        return results

    def generate_report(self, output_file: str = "vulnerability_summary.json") -> None:
        """پردازش هاست‌ها و ساخت فایل گزارش نهایی."""
        scan_data = self.load_scan_data()
        final_summary: Dict[str, Any] = {}

        for host, details in scan_data.items():
            logging.info(f"Analyzing host: {host}")
            final_summary[host] = []

            for port_info in details.get("open_ports", []):
                port_num = port_info.get("port")
                service_name = port_info.get("service", "")
                
                # استخراج مقادیر محصول و نسخه در صورت وجود فیلد مجزا یا ترکیبی
                raw_product = port_info.get("product", "")
                version = port_info.get("version", "")

                vulns: List[Dict[str, Any]] = []

                if raw_product:
                    logging.info(
                        f"Checking vulnerabilities for port {port_num} ({raw_product} {version})..."
                    )
                    vulns = self.query_vulnerabilities(raw_product, version)

                final_summary[host].append({
                    "port": port_num,
                    "service": service_name,
                    "product": raw_product,
                    "version": version,
                    "vulnerabilities_found": len(vulns),
                    "cve_list": vulns
                })

        output_path = Path(output_file)
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(final_summary, out, indent=4, ensure_ascii=False)

        logging.info(f"Vulnerability report generated successfully: {output_path}")


if __name__ == "__main__":
    input_scan_file = "scan_report.json"

    try:
        reporter = VulnReporter(input_file=input_scan_file)
        reporter.generate_report(output_file="vulnerability_summary.json")
    except Exception as e:
        logging.error(f"Execution terminated: {e}")
