import os
import glob
import json
from .utils import log_info, log_success, Colors

def search_cve(query: str, cve_dir: str = "cve"):
    log_info(f"Searching CVE Intelligence Database for query: '{query}'...")
    matches = []
    pattern = os.path.join(cve_dir, "**", "*.json")
    for file_path in glob.glob(pattern, recursive=True):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                searchable = json.dumps(data).lower()
                if query.lower() in searchable:
                    matches.append(data)
        except Exception:
            continue

    if not matches:
        print(f"{Colors.YELLOW}No matching CVE advisories found.{Colors.RESET}")
        return []

    print(f"\nFound {len(matches)} matching advisory record(s):\n" + "-"*60)
    for cve in matches:
        cvss = cve.get("cvss_score", "N/A")
        severity = cve.get("severity", "UNKNOWN")
        print(f"{Colors.BOLD}{cve.get('cve_id')}{Colors.RESET} - {cve.get('title')}")
        print(f"  Vendor/Product: {cve.get('vendor')} / {cve.get('product')}")
        print(f"  CVSS: {Colors.RED if cvss >= 8.0 else Colors.YELLOW}{cvss} ({severity}){Colors.RESET}")
        print(f"  Mitigation: {cve.get('mitigation')}")
        print("-" * 60)

    log_success(f"Total matching CVEs returned: {len(matches)}")
    return matches
