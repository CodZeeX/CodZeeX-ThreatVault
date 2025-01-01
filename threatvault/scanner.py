import os
import re
import math
from .utils import log_info, log_alert, log_success, Colors

COMMON_SUSPICIOUS_PATTERNS = [
    (r"(?i)powershell.*(?:-enc|-e\s+[a-z0-9+/=]{20,})", "Encoded PowerShell Command Cradle", "HIGH"),
    (r"(?i)Invoke-Expression|IEX\s*\(", "In-Memory PowerShell Execution (IEX)", "HIGH"),
    (r"(?i)DownloadString|DownloadFile|Net\.WebClient", "Remote Download WebClient Artifact", "MEDIUM"),
    (r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows", "Shadow Copy Deletion (Ransomware Tactic)", "CRITICAL"),
    (r"(?i)cmd(?:\.exe)?\s+/c\s+echo.*>.*&&.*start", "Obfuscated Command Pipe Stager", "MEDIUM"),
    (r"(?i)certutil(?:\.exe)?\s+-urlcache\s+-split\s+-f", "Certutil Living-off-the-land Downloader", "HIGH"),
    (r"(?i)rundll32(?:\.exe)?.*dllregisterserver", "Suspicious Rundll32 Execution", "MEDIUM"),
    (r"(?i)wscript\.shell|wscript\.exe.*\.vbs", "Script Host Execution", "MEDIUM"),
    (r"(?i)<\?php.*eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)", "Generic PHP Obfuscated WebShell", "CRITICAL"),
]

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def scan_file(filepath: str):
    matches = []
    try:
        with open(filepath, "rb") as f:
            content = f.read()
        entropy = calculate_entropy(content)
        high_entropy = entropy > 7.2
        text_sample = content.decode("utf-8", errors="ignore")

        for pattern, desc, severity in COMMON_SUSPICIOUS_PATTERNS:
            if re.search(pattern, text_sample):
                matches.append({"rule": desc, "severity": severity, "path": filepath})

        if high_entropy and len(content) > 1024:
            matches.append({
                "rule": f"Abnormally High Shannon Entropy ({entropy:.2f}/8.00) - Possible Packing/Encryption",
                "severity": "MEDIUM",
                "path": filepath
            })
    except Exception as e:
        pass
    return matches

def scan_directory(target_dir: str):
    log_info(f"Starting ThreatVault heuristic & pattern scan on: {target_dir}")
    total_scanned = 0
    total_detections = 0
    results = []

    for root, _, files in os.walk(target_dir):
        for f in files:
            path = os.path.join(root, f)
            total_scanned += 1
            res = scan_file(path)
            if res:
                total_detections += len(res)
                results.extend(res)
                for item in res:
                    log_alert(f"[{item['severity']}] {item['rule']} in {path}")

    log_success(f"Scan complete. Files inspected: {total_scanned}, Detections: {total_detections}")
    return results
