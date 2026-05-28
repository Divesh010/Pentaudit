"""
config.py — Central configuration for PentAudit
================================================

WHY THIS FILE EXISTS:
Instead of scattering magic numbers and strings throughout your code,
you put them all in one place. If you need to change a port number or 
add a new platform, you only change THIS file.

This is called "separation of concerns" — a key software engineering principle.
"""

# ─── Ports commonly used by pentest platforms and AI security tools ───────────
# When we scan a network, we check these ports to find dashboards.
# Each port is associated with specific platforms.

PENTEST_PLATFORM_PORTS = {
    443:  "HTTPS (default web dashboard)",
    8443: "Alternative HTTPS (PenTera, NodeZero)",
    8080: "HTTP alternative (many tools)",
    3000: "Grafana / custom dashboards",
    5601: "Kibana (Elastic SIEM)",
    9090: "Prometheus / misc dashboards",
    8834: "Nessus vulnerability scanner",
    3780: "Rapid7 InsightVM / Nexpose",
}

# ─── Platform fingerprints ───────────────────────────────────────────────────
# When we connect to a web dashboard, we look for these strings in the 
# HTTP response to identify WHAT platform it is. This is called "fingerprinting."
#
# Example: If the HTML page contains "PenTera" in its title, we know it's PenTera.

PLATFORM_SIGNATURES = {
    "PenTera": {
        "title_keywords": ["pentera", "pentera platform"],
        "header_keywords": ["x-pentera", "pentera"],
        "body_keywords": ["pentera", "automated penetration"],
        "default_ports": [443, 8443],
    },
    "NodeZero": {
        "title_keywords": ["nodezero", "horizon3", "h3"],
        "header_keywords": ["nodezero", "horizon3"],
        "body_keywords": ["nodezero", "horizon3.ai", "autonomous pentest"],
        "default_ports": [443, 8443],
    },
    "Darktrace": {
        "title_keywords": ["darktrace", "threat visualizer"],
        "header_keywords": ["darktrace"],
        "body_keywords": ["darktrace", "threat visualizer", "antigena"],
        "default_ports": [443],
    },
    "Vectra": {
        "title_keywords": ["vectra", "cognito"],
        "header_keywords": ["vectra"],
        "body_keywords": ["vectra", "cognito", "detect platform"],
        "default_ports": [443, 8443],
    },
    "Exabeam": {
        "title_keywords": ["exabeam", "advanced analytics"],
        "header_keywords": ["exabeam"],
        "body_keywords": ["exabeam", "ueba", "advanced analytics"],
        "default_ports": [443, 8443],
    },
    "Nessus": {
        "title_keywords": ["nessus"],
        "header_keywords": ["nessus", "tenable"],
        "body_keywords": ["nessus", "tenable", "vulnerability scan"],
        "default_ports": [8834],
    },
    "Rapid7 InsightVM": {
        "title_keywords": ["insightvm", "nexpose", "rapid7"],
        "header_keywords": ["rapid7", "nexpose"],
        "body_keywords": ["rapid7", "insightvm", "nexpose"],
        "default_ports": [3780],
    },
    "Wazuh": {
        "title_keywords": ["wazuh"],
        "header_keywords": ["wazuh"],
        "body_keywords": ["wazuh", "ossec"],
        "default_ports": [443, 5601],
    },
}

# ─── DNS patterns to check ──────────────────────────────────────────────────
# Pentest platforms often get obvious DNS names. We check for these.
# The tool will try: pentera.{domain}, nodezero.{domain}, etc.

DNS_PATTERNS = [
    "pentera", "pentest", "nodezero", "horizon3",
    "darktrace", "vectra", "exabeam", "nessus",
    "rapid7", "insightvm", "wazuh", "siem",
    "security-scanner", "vuln-scanner", "pentest-lab",
]

# ─── File share patterns ────────────────────────────────────────────────────
# When searching file shares for exported pentest reports, we look for
# files with these extensions and name patterns.

REPORT_FILE_EXTENSIONS = [".pdf", ".csv", ".xlsx", ".html", ".json", ".xml"]

REPORT_NAME_KEYWORDS = [
    "pentest", "penetration", "vulnerability", "scan-results",
    "nodezero", "pentera", "security-assessment", "attack-path",
    "credential", "findings", "audit-report",
]

# ─── Risk scoring ────────────────────────────────────────────────────────────
# Each finding gets a risk level. These are the definitions.

RISK_LEVELS = {
    "CRITICAL": {
        "score": 4,
        "color": "#DC3545",
        "description": "Immediate exploitation possible — fix now",
    },
    "HIGH": {
        "score": 3,
        "color": "#FD7E14",
        "description": "Easily exploitable with minimal skill — fix within 24 hours",
    },
    "MEDIUM": {
        "score": 2,
        "color": "#FFC107",
        "description": "Exploitable under certain conditions — fix within 1 week",
    },
    "LOW": {
        "score": 1,
        "color": "#28A745",
        "description": "Minor risk, defense-in-depth improvement — fix within 1 month",
    },
    "INFO": {
        "score": 0,
        "color": "#17A2B8",
        "description": "Informational finding — no immediate risk",
    },
}

# ─── MITRE ATT&CK technique mappings ────────────────────────────────────────
# Each check maps to one or more MITRE ATT&CK techniques.
# This makes our report look professional and industry-standard.

MITRE_TECHNIQUES = {
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "description": "Adversary uses legitimate credentials to access systems.",
    },
    "T1078.001": {
        "name": "Valid Accounts: Default Accounts",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/001/",
        "description": "Adversary uses default vendor credentials.",
    },
    "T1106": {
        "name": "Native API",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1106/",
        "description": "Adversary interacts with native OS or platform APIs.",
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1039/",
        "description": "Adversary collects data from shared network drives.",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
        "description": "Adversary disables or modifies security tools to avoid detection.",
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1539/",
        "description": "Adversary steals session cookies for unauthorized access.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/",
        "description": "Adversary finds credentials stored insecurely.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Adversary enumerates files and directories for sensitive data.",
    },
}

# ─── Default credentials database ───────────────────────────────────────────
# Known default username/password combinations for security platforms.
# During an audit, we test these (WITH PERMISSION) to see if they were changed.

DEFAULT_CREDENTIALS = [
    {"platform": "Generic",   "username": "admin",       "password": "admin"},
    {"platform": "Generic",   "username": "admin",       "password": "password"},
    {"platform": "Generic",   "username": "admin",       "password": "Password1"},
    {"platform": "Generic",   "username": "admin",       "password": "changeme"},
    {"platform": "Generic",   "username": "administrator", "password": "administrator"},
    {"platform": "Nessus",    "username": "admin",       "password": "nessus"},
    {"platform": "Wazuh",     "username": "admin",       "password": "admin"},
    {"platform": "Wazuh",     "username": "wazuh",       "password": "wazuh"},
    {"platform": "Rapid7",    "username": "nxadmin",     "password": "nxpassword"},
    {"platform": "Kibana",    "username": "elastic",     "password": "changeme"},
    {"platform": "Grafana",   "username": "admin",       "password": "admin"},
]

# ─── Scan settings ──────────────────────────────────────────────────────────

SCAN_TIMEOUT = 5          # Seconds to wait for a connection
HTTP_TIMEOUT = 10         # Seconds to wait for HTTP response
MAX_THREADS = 20          # Maximum parallel scan threads
DEMO_MODE = False         # If True, simulate findings without real scanning
