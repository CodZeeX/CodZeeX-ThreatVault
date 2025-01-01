# CodZeeX ThreatVault 🛡️
> Enterprise Open-Source Threat Intelligence, Detection Engineering & System Hardening Framework
> Maintained by [CodZeeX Organization](https://github.com/organizations/CodZeeX) | Author: **RobsHs**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![MITRE ATT&CK v15](https://img.shields.io/badge/MITRE%20ATT%26CK-v15.1-red.svg)](https://attack.mitre.org/)
[![Sigma Rules](https://img.shields.io/badge/Sigma%20Rules-3500+-orange.svg)](rules/sigma/)
[![YARA Signatures](https://img.shields.io/badge/YARA%20Signatures-2500+-yellow.svg)](rules/yara/)
[![CVE Index](https://img.shields.io/badge/CVE%20Database-2024--2026-brightgreen.svg)](cve/)

---

## 🌟 Overview
**ThreatVault** is an enterprise-ready cybersecurity intelligence and defense framework developed under the **CodZeeX** organization. It unifies detection engineering, threat intelligence feeds, automated hardening playbooks, and a high-performance Python scanner engine into a single modular architecture.

### Key Capabilities:
- 🎯 **3,500+ Sigma Detection Rules**: Windows Sysmon, Linux Auditd, CloudTrail, Azure Entra ID, and Network telemetry.
- 🧬 **2,500+ YARA Signatures**: Modern detection for Ransomware (LockBit, Akira, BlackCat), Infostealers (RedLine, Lumma), WebShells, and Memory Injections.
- 📑 **CVE Intelligence Index**: Comprehensive technical mitigations, detection queries, and CVSS v3.1/v4.0 scoring for critical 2024–2026 vulnerabilities.
- 📡 **Automated Threat Intelligence Feeds**: Curated IP blocklists, C2 domain reputation, and IoC malware hashes with automated validation.
- 🔒 **CIS Hardening Baselines**: Production-grade hardening scripts for Linux (sysctl, sshd, auditd), Windows Defender ASR, Docker, and Kubernetes Pod Security Standards.
- ⚡ **ThreatVault CLI**: Fast, multithreaded scanning engine for threat hunting, rule validation, and host auditing.

---

## 🚀 Installation & Quick Start

```bash
# Clone the repository
git clone https://github.com/CodZeeX/CodZeeX-ThreatVault.git
cd CodZeeX-ThreatVault

# Install dependencies and ThreatVault CLI
pip install -e .
```

### CLI Usage Examples:

```bash
# 1. Scan a directory or binary for YARA signatures and high-entropy packed code
threatvault scan --path /path/to/suspicious_files

# 2. Inspect and evaluate Sigma rules against an event log (JSON format)
threatvault sigma --log sample_events.json --rule rules/sigma/windows/proc_creation_powershell_download.yml

# 3. Query CVE advisory database for mitigations and SIEM detection queries
threatvault cve --search "CVE-2025"

# 4. Check an IP or Domain against local threat intelligence feeds
threatvault intel --check 198.51.100.42

# 5. Run a local CIS security baseline audit on the current system
threatvault audit --system

# 6. Display repository intelligence metrics
threatvault stats
```

---

## 📁 Repository Structure

```
CodZeeX-ThreatVault/
├── .github/workflows/     # CI/CD Rule Validation & Linting Pipeline
├── cli/                   # CLI entrypoints and wrapper scripts
├── cve/                   # CVE Intelligence (2024, 2025, 2026 advisories)
├── hardening/             # CIS Hardening scripts (Linux, Windows, K8s, Docker)
│   ├── docker/
│   ├── kubernetes/
│   ├── linux/
│   └── windows/
├── intel/                 # Threat Feeds & Actor Dossiers
│   ├── actors/            # APT profiles & MITRE matrix mapping
│   └── feeds/             # Reputation IP lists, domain blocklists, hashes
├── rules/                 # Detection Rules
│   ├── sigma/             # Windows, Linux, Cloud, and Network Sigma rules
│   └── yara/              # Ransomware, Infostealer, WebShell YARA signatures
├── tests/                 # Unit and integration test suite
└── threatvault/           # Core Python engine package
    ├── cli.py             # CLI command handlers
    ├── cve_engine.py      # CVE search & advisory manager
    ├── hardening_auditor.py# System security compliance inspector
    ├── intel_manager.py   # IOC & reputation checker
    ├── scanner.py         # Multi-threaded signature & entropy scanner
    └── sigma_engine.py    # Sigma rule parser & condition evaluator
```

---

## 🛡️ MITRE ATT&CK Matrix Coverage

| Tactic | Key Techniques Detected | Example Rules |
|---|---|---|
| **Initial Access** | T1190 (Exploit Public-Facing App), T1566 (Phishing) | Web exploit payloads, Office macro execution |
| **Execution** | T1059 (Command & Scripting Interpreter), T1204 (User Execution) | Suspicious PowerShell, MSHTA, Rundll32 proxy |
| **Persistence** | T1547 (Boot/Logon Autostart), T1053 (Scheduled Task) | Registry Run keys, Cron job injection, WMI |
| **Privilege Escalation** | T1068 (Exploitation for Priv Esc), T1548 (Abuse Elevation) | Sudoers bypass, Kernel exploit signatures |
| **Defense Evasion** | T1027 (Obfuscation), T1070 (Indicator Removal) | Event log clearing, AMSI bypass, Timestomping |
| **Credential Access** | T1003 (OS Credential Dumping), T1555 (Credentials from Store) | LSASS dump, SAM hive copy, DPAPI theft |
| **Lateral Movement** | T1021 (Remote Services), T1570 (Lateral Tool Transfer) | PsExec, WMI win32_process, SMB named pipes |
| **Command & Control** | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) | Cobalt Strike beaconing, DNS tunneling |

---

## 🤝 Contributing
We welcome contributions from the global cybersecurity community!
Please read our [CONTRIBUTING.md](CONTRIBUTING.md) and adhere to the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## 📄 License
Released under the [MIT License](LICENSE). Copyright (c) 2025-2026 **CodZeeX Organization & RobsHs**.
