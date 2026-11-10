# PentAudit 🛡️
> **Autonomous Pentest Platform & AI Security Tool Auditor**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK Mapped](https://img.shields.io/badge/Framework-MITRE%20ATT%2CK-red.svg)](https://attack.mitre.org/)
[![NIST SP 800-53 Mapped](https://img.shields.io/badge/Framework-NIST%20800--53-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

PentAudit is a specialized python security tool designed to **audit the security posture of autonomous pentest platforms and AI security tools** deployed on an internal network. 

Autonomous pentest platforms (like PenTera, NodeZero) and AI-driven behavior analytics/UEBA platforms (like Exabeam, Darktrace) are extremely powerful. However, because they must harvest credentials, run active scans, and have high-level network permissions, they become a **prime target for insiders**. PentAudit helps security teams verify that their security tools aren't creating new, critical blind spots or acting as launchpads for internal attackers.

---

## 🚀 Key Features

* **Network Discovery:** Scans internal subnets via fast, multithreaded socket scanners and `nmap` integration to find dashboards of major pentest and AI tools.
* **HTTP Fingerprinting:** Connects to discovered dashboards and analyzes titles, headers, and body signatures to identify the platforms with calculated confidence levels.
* **DNS Enumeration:** Automatically checks for obvious DNS names (e.g., `pentera.corp.local`, `nodezero.*`) that insiders could easily guess.
* **Exposed Report Scanner:** Scans file shares for exported pentest reports (PDF, CSV, XLSX) left open to standard users.
* **8 Automated Security Checks:** Evaluates the identified systems against common exposure vectors.
* **Professional HTML Reports:** Generates dark-themed, glassmorphic, interactive HTML dashboards containing executive statistics, technical evidence, mitigation guidelines, and mapping to **MITRE ATT&CK** and **NIST SP 800-53**.
* **Educational Demo Mode:** Runs with simulated data to easily demonstrate the tool's capabilities for interviews or showcases.

---

## 🛠️ The 8 Security Checks

PentAudit automates 8 core checks to identify critical configuration gaps:

| Check ID | Security Check | Threat Vector | MITRE Technique | NIST Control |
|---|---|---|---|---|
| **CHK-001** | Dashboard Auth | Web console accessible without login | [T1078 (Valid Accounts)](https://attack.mitre.org/techniques/T1078/) | AC-3 (Access Enforcement) |
| **CHK-002** | Default Credentials | Factory-set passwords still active | [T1078.001 (Default Accounts)](https://attack.mitre.org/techniques/T1078/001/) | IA-5 (Authenticator Mgmt) |
| **CHK-003** | MFA Enforcement | Multi-factor authentication missing | [T1078 (Valid Accounts)](https://attack.mitre.org/techniques/T1078/) | IA-2(1) (MFA) |
| **CHK-004** | API Key Exposure | REST APIs accessible without tokens | [T1106 (Native API)](https://attack.mitre.org/techniques/T1106/) | SC-8 (Transmission Conf) |
| **CHK-005** | Share Permissions | Exported reports open to domain users | [T1039 (Network Shared Drive)](https://attack.mitre.org/techniques/T1039/) | AC-6 (Least Privilege) |
| **CHK-006** | UEBA Whitelist Gap | Platform IP permanently excluded from AI SIEM | [T1562.001 (Impair Defenses)](https://attack.mitre.org/techniques/T1562/001/) | SI-4 (System Monitoring) |
| **CHK-007** | Session Management | Insecure cookie flags and missing timeout | [T1539 (Steal Web Session)](https://attack.mitre.org/techniques/T1539/) | AC-12 (Session Termination) |
| **CHK-008** | Credential Storage | Harvested NTLM/hashes stored unrotated | [T1552 (Unsecured Credentials)](https://attack.mitre.org/techniques/T1552/) | SC-28 (Protection at Rest) |

---

## 📊 Report Dashboard Preview

PentAudit generates high-fidelity, interactive reports designed to impress both executives and engineers. Below is an overview of the report structure:

1. **Executive Risk Summary:** Shows overall system risk score (Critical, High, Medium, Low) and statistics cards.
2. **Platform Inventory:** Lists identified hosts, ports, confidence levels, and active links.
3. **MITRE ATT&CK & NIST SP 800-53 Mappings:** Every finding is linked directly to industry-standard offensive and defensive security frameworks.
4. **Remediation Plans:** Provides actionable, step-by-step mitigation instructions for network administrators.

*(You can find a complete generated report in [examples/sample_report.html](examples/sample_report.html))*

---

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Divesh010/Pentaudit.git
   cd pentaudit
   ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. *(Optional)* Install [Nmap](https://nmap.org/download.html) on your system to enable advanced active port scanning and service fingerprint detection. If Nmap is not installed, PentAudit automatically falls back to a clean, multithreaded socket scanner.

---

## 🚀 Usage

### 1. Run a Showcase/Demo Scan (No Live Network Required)
Excellent for demonstrating the tool's performance and output format for recruiters or interviews:
```bash
python pentaudit.py --demo --output demo_report.html
```

### 2. Live Scan a Network Range
Scan an internal subnet and identify exposed platforms:
```bash
python pentaudit.py --target 192.168.1.0/24 --output live_report.html
```

### 3. DNS Enumeration Only
Resolve potential dashboard addresses using common naming patterns:
```bash
python pentaudit.py --target 192.168.1.0/24 --domain corp.internal --discover-only
```

### 4. Re-generate Report from Saved Scan Data
Load previous results from JSON and export a new styled HTML dashboard:
```bash
python pentaudit.py --from-results report.json --output new_report.html
```

---

## 📁 Project Structure

```
pentaudit/
├── README.md                 # Project description, setup, usage
├── requirements.txt          # Python dependencies
├── pentaudit.py              # Root-level entry point wrapper
├── pentaudit/
│   ├── __init__.py           # Package details
│   ├── main.py               # CLI parser and core flow orchestrator
│   ├── discovery.py          # Multithreaded socket/nmap network scanner
│   ├── auditor.py            # The 8 automated security checks
│   ├── reporter.py           # Jinja2 and raw-string report engine
│   ├── config.py             # Constants, signatures, and default credentials database
│   └── utils.py              # Safe console writing wrapper with ASCII fallbacks
├── templates/
│   └── report_template.html  # High-fidelity glassmorphic HTML template
├── tests/
│   ├── test_discovery.py     # Unit tests for discovery scanning
│   ├── test_auditor.py       # Unit tests for active security checks
│   └── test_reporter.py      # Unit tests for stats and file builders
├── docs/
│   └── architecture.md       # Detailed technical design document
└── examples/
    └── sample_report.html    # Pre-generated audit report sample
```

---

## 🧪 Running Tests

Ensure all functionalities are working properly using the standard python test runner:
```bash
python -m unittest discover -s tests
```

---

## 💡 Research Basis & Blog Post
This project is built based on original research analyzing the security blind spots of autonomous pentest platforms in internal enterprise networks. The detailed analysis, threat modeling, and defensive methodologies can be found in our technical blog: [Hacking the Hackers: Auditing Autonomous Pentest Platforms](docs/blog_post.md).

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
