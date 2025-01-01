import os
from .utils import log_info, log_alert, log_success, Colors

def check_ioc(ioc_value: str, intel_dir: str = "intel"):
    log_info(f"Querying Threat Intelligence Feeds for IoC: {ioc_value}")
    ioc_clean = ioc_value.strip().lower()

    # Check IP reputation feed
    ip_feed_path = os.path.join(intel_dir, "feeds", "malicious_ips.txt")
    if os.path.exists(ip_feed_path):
        with open(ip_feed_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    parts = line.strip().split(",")
                    ip = parts[0].strip()
                    if ip == ioc_clean:
                        tag = parts[1].strip() if len(parts) > 1 else "Malicious Host"
                        log_alert(f"IOC MATCH! {ioc_value} identified as: {tag} in IP Threat Feed!")
                        return True

    # Check Domain reputation feed
    domain_feed_path = os.path.join(intel_dir, "feeds", "malicious_domains.txt")
    if os.path.exists(domain_feed_path):
        with open(domain_feed_path, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith("#") and d == ioc_clean:
                    log_alert(f"IOC MATCH! {ioc_value} listed on Domain Blacklist Feed!")
                    return True

    log_success(f"No adverse intelligence found for {ioc_value} in current local feeds.")
    return False
