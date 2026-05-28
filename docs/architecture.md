# PentAudit — Technical Architecture & Design Document

## Overview

PentAudit is a modular, lightweight Python-based security auditing framework designed to analyze the security configuration and exposure risk of autonomous pentest platforms and AI-driven behavior analytics tools on internal enterprise networks.

As security tools become increasingly autonomous, they store massive amounts of high-value data (plaintext passwords, NTLM hashes, attack paths). PentAudit was built to answer a critical defensive question: **Who audits the security posture of the security tools themselves?**

This document outlines the software architecture, modular layout, core subsystems, data models, and mapping strategies of the PentAudit tool.

---

## System Architecture

PentAudit is built with a strictly decoupled, pipe-and-filter-style modular architecture. Each step in the execution pipeline is completely separate, passing structured data to the next step.

```
+---------------------------------------------------------------------------------+
|                                PentAudit CLI                                    |
|                                (pentaudit.py)                                   |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                              Discovery Subsystem                                |
|                                (discovery.py)                                   |
|   - Port Scan (socket / python-nmap)                                            |
|   - HTTP service fingerprint matching (signatures in config.py)                 |
|   - Guessable DNS enumeration                                                   |
|   - Exposed report file share discovery                                         |
+---------------------------------------------------------------------------------+
                                       |
                                       | Outputs: List[PlatformDict]
                                       v
+---------------------------------------------------------------------------------+
|                               Auditing Subsystem                                |
|                                 (auditor.py)                                    |
|   - Iterates through discovered platform inventory                              |
|   - Runs 8 automated security checks                                            |
|   - Formats technical proof-of-concept evidence per check                       |
|   - Maps each finding to MITRE ATT&CK & NIST SP 800-53                          |
+---------------------------------------------------------------------------------+
                                       |
                                       | Outputs: List[FindingDict]
                                       v
+---------------------------------------------------------------------------------+
|                               Reporting Subsystem                               |
|                                 (reporter.py)                                   |
|   - Gathers scan metadata and platform/finding lists                            |
|   - Computes overall system risk metrics & counts                               |
|   - Renders a professional glassmorphic HTML dashboard (report_template.html)   |
|   - Exports machine-readable JSON results file                                  |
+---------------------------------------------------------------------------------+
```

---

## Module Breakdown

### 1. Central Configuration (`pentaudit/config.py`)
Acts as the single source of truth for the entire application. It contains:
- **`PENTEST_PLATFORM_PORTS`**: Port mappings commonly used by security dashboards.
- **`PLATFORM_SIGNATURES`**: Keywords matching page titles, HTTP response headers, and bodies to confidently identify platforms.
- **`DEFAULT_CREDENTIALS`**: Database of factory-set accounts to test access.
- **`MITRE_TECHNIQUES`**: Detailed mappings for tactics and techniques.

### 2. Network Discovery (`pentaudit/discovery.py`)
Scans the network range and compiles an inventory. It includes:
- **Port Scanner**: Multithreaded TCP socket connections or `python-nmap` integration.
- **Fingerprinter**: Tries HTTPS/HTTP connections, checks headers, body content, and titles using signatures.
- **DNS Resolver**: Enumerates common internal hostnames.
- **Exposed Share Scanner**: Locates insecure exports on standard SMB/file shares.

### 3. Security Auditor (`pentaudit/auditor.py`)
Responsible for running the active assessments. It executes 8 distinct security tests (see `README.md` for details) and generates detailed findings structures:

```python
{
    "check_id": "CHK-001",
    "title": "Dashboard Accessible Without Authentication",
    "risk_level": "CRITICAL",
    "platform_name": "PenTera",
    "platform_host": "10.0.5.50",
    "platform_url": "https://10.0.5.50:8443",
    "description": "The dashboard returned content without authentication...",
    "evidence": "HTTP GET https://10.0.5.50:8443 -> 200 OK (no login redirect)",
    "mitre_technique": "T1078",
    "mitre_details": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "remediation": "Enable authentication immediately with RBAC...",
    "nist_control": "AC-3, IA-2",
    "timestamp": "2026-05-28T17:20:00"
}
```

### 4. Report Generator (`pentaudit/reporter.py`)
Formats findings into standard structures and renders the HTML dashboard via Jinja2:
- **Risk Score Engine**: Computes overall severity based on the highest risk finding.
- **HTML Renderer**: Standardizes output tables, banners, cards, and colors.
- **JSON Exporter**: Generates machine-readable output for SIEM ingestion or audit logging.

### 5. Utility Layer (`pentaudit/utils.py`)
Exposes shared formatting, logging, and styling methods. Includes a robust `_safe_print` unicode wrapper that falls back to ASCII text and grid styles to ensure 100% crash-free execution on legacy Windows shells or automated build systems.

---

## Key Extensibility Points

PentAudit is designed to easily grow as new tools and threat vectors emerge.

### How to Add a New Platform Signature
Add a new dictionary key to the `PLATFORM_SIGNATURES` dictionary in `pentaudit/config.py`:

```python
"NewToolName": {
    "title_keywords": ["newtool", "newtool-console"],
    "header_keywords": ["x-newtool-auth"],
    "body_keywords": ["newtool autonomous audit"],
    "default_ports": [443, 9443]
}
```

### How to Add a New Security Check
1. Define a check metadata mapping in `MITRE_TECHNIQUES` (if a new technique is targeted).
2. Add a new private method in `SecurityAuditor` inside `pentaudit/auditor.py`:

```python
def _chk009_unencrypted_communication(self, platform):
    check_id = "CHK-009"
    title = "Unencrypted HTTP Communication Active"
    # Test logic...
    if is_insecure:
        self._add_finding(
            check_id=check_id,
            title=title,
            risk_level="HIGH",
            platform=platform,
            description="Dashboard communicates using plaintext HTTP...",
            evidence="URL starts with http://...",
            mitre_technique="T1040", # Network Sniffing
            remediation="Enforce TLS 1.3 on all dashboard connections.",
            nist_control="SC-8"
        )
```

3. Register the new check in `run_all_checks()`:
```python
self._chk009_unencrypted_communication(platform)
```

---

## Defensive Philosophy

PentAudit is built around a "Defense-in-Depth" security approach:
1. **Reduce the Attack Surface:** Restrict access to administrative dashboards via local firewalls or VPNs.
2. **Deterministic Alerting:** Traditional UEBA models fail to baseline systems with sparse user access (like security platforms). PentAudit recommends simple, rule-based SOC alerts to flag *any* unauthorized user accessing these systems.
3. **Time-Box Exclusions:** Whitelists in SIEM/UEBA systems should be dynamic and active only during pre-defined scan windows, leaving the system fully monitored between scans.
