"""
discovery.py — Network Discovery Module
=========================================

WHAT THIS MODULE DOES:
Scans a network to find pentest platforms and AI security tools.
Think of it like a detective searching a building — it goes room by room
(IP by IP) and checks if any security tool dashboards are running.

HOW IT WORKS:
1. Port Scanning    → Check which IPs have web dashboards open
2. Fingerprinting   → Connect to each dashboard and identify the platform
3. DNS Enumeration  → Check common DNS names like "pentera.corp.local"
4. Share Scanning   → Look for exported pentest reports on file shares

DEMO MODE:
Since you can't always scan a real network (especially for GitHub demos),
this module includes a --demo mode that simulates realistic findings.
"""

import socket
import json
import os
import concurrent.futures
from datetime import datetime

# Import our own modules
from pentaudit.config import (
    PENTEST_PLATFORM_PORTS,
    PLATFORM_SIGNATURES,
    DNS_PATTERNS,
    REPORT_FILE_EXTENSIONS,
    REPORT_NAME_KEYWORDS,
    SCAN_TIMEOUT,
    HTTP_TIMEOUT,
    MAX_THREADS,
)
from pentaudit.utils import (
    print_phase, print_success, print_warning,
    print_info, print_error, timer_start, timer_end,
)

# Try to import optional libraries (graceful fallback if not installed)
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class DiscoveryScanner:
    """
    Discovers pentest platforms and AI security tools on a network.
    
    USAGE:
        scanner = DiscoveryScanner(target="10.0.0.0/24")
        results = scanner.run()
    
    Each result is a dict like:
        {
            "host": "10.0.5.50",
            "port": 443,
            "platform": "PenTera",
            "url": "https://10.0.5.50:443",
            "status": "identified",
            "confidence": "high",
            "discovered_at": "2026-05-28T17:00:00"
        }
    """

    def __init__(self, target, domain=None, demo_mode=False):
        """
        Initialize the scanner.
        
        Args:
            target:    IP address, range (10.0.0.0/24), or single host
            domain:    Internal domain name (e.g., "corp.internal") for DNS checks
            demo_mode: If True, return simulated findings without real scanning
        """
        self.target = target
        self.domain = domain
        self.demo_mode = demo_mode
        self.results = []          # Store discovered platforms
        self.open_ports = []       # Store hosts with open ports
        self.dns_findings = []     # Store DNS resolution results
        self.share_findings = []   # Store found report files

    def run(self):
        """
        Run all discovery phases and return combined results.
        This is the main entry point — call this to start scanning.
        """
        print_phase("PHASE 1: DISCOVERY — Finding Pentest Platforms & AI Security Tools")

        if self.demo_mode:
            print_warning("Running in DEMO MODE — using simulated network data")
            return self._run_demo()

        # Phase 1a: Port Scan
        self._scan_ports()

        # Phase 1b: Fingerprint discovered services
        self._fingerprint_services()

        # Phase 1c: DNS enumeration (if domain provided)
        if self.domain:
            self._enumerate_dns()

        # Summary
        print_info(f"Discovery complete: {len(self.results)} platform(s) found")
        return self.results

    # ─── Port Scanning ───────────────────────────────────────────────────────

    def _scan_ports(self):
        """
        Scan the target network for open ports that pentest platforms use.
        
        HOW PORT SCANNING WORKS:
        Your computer tries to connect to each IP:port combination.
        If the connection succeeds → the port is OPEN (something is listening).
        If it fails → the port is CLOSED (nothing there).
        
        We check ports like 443, 8443, 8080 because those are where
        web dashboards typically run.
        """
        print_info(f"Scanning target: {self.target}")
        ports_to_scan = list(PENTEST_PLATFORM_PORTS.keys())
        print_info(f"Checking ports: {ports_to_scan}")

        start = timer_start()

        if NMAP_AVAILABLE:
            self._scan_with_nmap(ports_to_scan)
        else:
            # Fallback: use basic socket scanning if nmap isn't installed
            print_warning("python-nmap not installed, using basic socket scanner")
            self._scan_with_sockets(ports_to_scan)

        elapsed = timer_end(start)
        print_success(f"Port scan complete in {elapsed}s — {len(self.open_ports)} open port(s) found")

    def _scan_with_nmap(self, ports):
        """Scan using nmap (more accurate, but requires nmap installed)."""
        try:
            nm = nmap.PortScanner()
            port_str = ",".join(str(p) for p in ports)
            print_info(f"Running: nmap -sV -p {port_str} {self.target} --open")

            nm.scan(hosts=self.target, ports=port_str, arguments="-sV --open")

            for host in nm.all_hosts():
                for port in ports:
                    if nm[host].has_tcp(port) and nm[host]["tcp"][port]["state"] == "open":
                        service = nm[host]["tcp"][port].get("product", "unknown")
                        self.open_ports.append({
                            "host": host,
                            "port": port,
                            "service": service,
                            "state": "open",
                        })
                        print_success(f"Found open port: {host}:{port} ({service})")
        except Exception as e:
            print_error(f"Nmap scan failed: {e}")
            print_warning("Falling back to socket scanner")
            self._scan_with_sockets(ports)

    def _scan_with_sockets(self, ports):
        """
        Basic port scanner using Python sockets.
        This is a fallback when nmap isn't installed.
        
        HOW IT WORKS:
        For each IP:port, we try to open a TCP connection.
        If it connects within the timeout → port is open.
        If it times out or refuses → port is closed.
        
        We use ThreadPoolExecutor to scan multiple ports in parallel
        (otherwise scanning would be very slow).
        """
        # Parse target - handle single IP or CIDR range
        hosts = self._parse_target(self.target)
        
        # Create all (host, port) combinations to scan
        scan_jobs = [(host, port) for host in hosts for port in ports]
        print_info(f"Scanning {len(hosts)} host(s) × {len(ports)} port(s) = {len(scan_jobs)} checks")

        # Scan in parallel using thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {
                executor.submit(self._check_port, host, port): (host, port)
                for host, port in scan_jobs
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    print_success(f"Found open port: {result['host']}:{result['port']}")

    def _check_port(self, host, port):
        """
        Check if a single port is open on a host.
        Returns a dict if open, None if closed.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SCAN_TIMEOUT)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:  # 0 means connection succeeded = port is open
                return {
                    "host": host,
                    "port": port,
                    "service": PENTEST_PLATFORM_PORTS.get(port, "unknown"),
                    "state": "open",
                }
        except (socket.timeout, socket.error, OSError):
            pass
        return None

    def _parse_target(self, target):
        """
        Parse a target string into a list of IP addresses.
        
        Supports:
        - Single IP: "10.0.5.50" → ["10.0.5.50"]
        - CIDR /24:  "10.0.5.0/24" → ["10.0.5.1", "10.0.5.2", ..., "10.0.5.254"]
        - CIDR /16:  Too many hosts, we limit to first 256
        """
        if "/" in target:
            # Parse CIDR notation
            base_ip, prefix = target.split("/")
            prefix = int(prefix)
            parts = list(map(int, base_ip.split(".")))

            hosts = []
            if prefix == 24:
                # Scan .1 to .254 in the subnet
                for i in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
            elif prefix == 16:
                # /16 is 65k hosts — limit to first subnet for speed
                print_warning(f"/16 range is large. Scanning first /24 only for speed.")
                for i in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.0.{i}")
            else:
                # For other ranges, just scan the base IP
                hosts.append(base_ip)
            return hosts
        else:
            return [target]

    # ─── Service Fingerprinting ──────────────────────────────────────────────

    def _fingerprint_services(self):
        """
        Connect to each discovered open port and try to identify
        which platform is running.
        
        HOW FINGERPRINTING WORKS:
        1. Make an HTTP/HTTPS request to the dashboard URL
        2. Look at the HTML page title, headers, and body content
        3. Match against known signatures from our config
        
        Example: If the page title contains "Darktrace", we know it's Darktrace.
        """
        if not self.open_ports:
            print_warning("No open ports found — skipping fingerprinting")
            return

        print_info(f"Fingerprinting {len(self.open_ports)} service(s)...")

        for entry in self.open_ports:
            host = entry["host"]
            port = entry["port"]
            platform = self._identify_platform(host, port)

            self.results.append({
                "host": host,
                "port": port,
                "platform": platform["name"],
                "url": f"https://{host}:{port}" if port == 443 or port == 8443 else f"http://{host}:{port}",
                "confidence": platform["confidence"],
                "status": "identified" if platform["name"] != "Unknown" else "unidentified",
                "discovered_at": datetime.now().isoformat(),
            })

    def _identify_platform(self, host, port):
        """
        Try to identify what platform is running on host:port.
        Returns {"name": "PenTera", "confidence": "high"} or similar.
        """
        if not REQUESTS_AVAILABLE:
            return {"name": "Unknown (requests library not installed)", "confidence": "none"}

        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}:{port}"
            try:
                response = requests.get(
                    url,
                    timeout=HTTP_TIMEOUT,
                    verify=False,                    # Don't verify SSL (internal certs)
                    allow_redirects=True,
                    headers={"User-Agent": "PentAudit/1.0 Security Auditor"}
                )

                # Check response against each platform's signatures
                for platform_name, signatures in PLATFORM_SIGNATURES.items():
                    confidence = self._match_signatures(response, signatures)
                    if confidence != "none":
                        print_success(f"Identified: {platform_name} at {url} (confidence: {confidence})")
                        return {"name": platform_name, "confidence": confidence}

                # If no match but we got a response, it's an unknown web service
                return {"name": "Unknown Web Service", "confidence": "low"}

            except requests.exceptions.SSLError:
                # SSL error might still indicate a platform — try next scheme
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        return {"name": "Unknown", "confidence": "none"}

    def _match_signatures(self, response, signatures):
        """
        Check if an HTTP response matches a platform's fingerprint signatures.
        Returns confidence level: "high", "medium", "low", or "none".
        
        We check three things:
        1. Page title (most reliable → "high" confidence)
        2. HTTP headers (reliable → "medium" confidence)
        3. Page body content (least reliable → "low" confidence)
        """
        matches = 0
        page_text = response.text.lower() if response.text else ""
        headers_text = str(response.headers).lower()

        # Check title keywords (high value)
        for keyword in signatures.get("title_keywords", []):
            if f"<title" in page_text and keyword.lower() in page_text:
                matches += 3  # Title match is worth more

        # Check header keywords (medium value)
        for keyword in signatures.get("header_keywords", []):
            if keyword.lower() in headers_text:
                matches += 2

        # Check body keywords (lower value)
        for keyword in signatures.get("body_keywords", []):
            if keyword.lower() in page_text:
                matches += 1

        # Convert match score to confidence
        if matches >= 5:
            return "high"
        elif matches >= 3:
            return "medium"
        elif matches >= 1:
            return "low"
        return "none"

    # ─── DNS Enumeration ─────────────────────────────────────────────────────

    def _enumerate_dns(self):
        """
        Try common DNS names that pentest platforms might use.
        
        WHY THIS MATTERS:
        IT teams often give security tools obvious DNS names like:
        - pentera.corp.internal
        - nodezero.corp.internal
        - security-scanner.corp.internal
        
        An insider can guess these names to find platforms without scanning.
        """
        if not self.domain:
            return

        print_info(f"Checking DNS patterns for domain: {self.domain}")

        for pattern in DNS_PATTERNS:
            hostname = f"{pattern}.{self.domain}"
            try:
                ip = socket.gethostbyname(hostname)
                self.dns_findings.append({
                    "hostname": hostname,
                    "ip": ip,
                    "status": "resolved",
                })
                print_success(f"DNS resolved: {hostname} → {ip}")
            except socket.gaierror:
                # Name doesn't exist — that's normal, move on
                pass

    # ─── Demo Mode ───────────────────────────────────────────────────────────

    def _run_demo(self):
        """
        Return simulated findings for demonstration purposes.
        
        WHY DEMO MODE EXISTS:
        1. You can't scan real networks in a GitHub demo
        2. Recruiters can run the tool and see realistic output
        3. You can test the auditor and reporter without a live network
        """
        print_info("Generating simulated discovery results...")

        self.results = [
            {
                "host": "10.0.5.50",
                "port": 8443,
                "platform": "PenTera",
                "url": "https://10.0.5.50:8443",
                "confidence": "high",
                "status": "identified",
                "discovered_at": datetime.now().isoformat(),
            },
            {
                "host": "10.0.5.55",
                "port": 443,
                "platform": "NodeZero",
                "url": "https://10.0.5.55:443",
                "confidence": "high",
                "status": "identified",
                "discovered_at": datetime.now().isoformat(),
            },
            {
                "host": "10.0.3.20",
                "port": 443,
                "platform": "Darktrace",
                "url": "https://10.0.3.20:443",
                "confidence": "medium",
                "status": "identified",
                "discovered_at": datetime.now().isoformat(),
            },
            {
                "host": "10.0.3.25",
                "port": 8443,
                "platform": "Exabeam",
                "url": "https://10.0.3.25:8443",
                "confidence": "medium",
                "status": "identified",
                "discovered_at": datetime.now().isoformat(),
            },
            {
                "host": "10.0.8.10",
                "port": 8834,
                "platform": "Nessus",
                "url": "https://10.0.8.10:8834",
                "confidence": "high",
                "status": "identified",
                "discovered_at": datetime.now().isoformat(),
            },
        ]

        self.dns_findings = [
            {"hostname": "pentera.corp.internal", "ip": "10.0.5.50", "status": "resolved"},
            {"hostname": "nodezero.corp.internal", "ip": "10.0.5.55", "status": "resolved"},
            {"hostname": "darktrace.corp.internal", "ip": "10.0.3.20", "status": "resolved"},
        ]

        self.share_findings = [
            {"path": "\\\\fileserver\\security$\\pentest-results-Q1-2026.pdf", "type": "PDF Report"},
            {"path": "\\\\fileserver\\security$\\nodezero-credentials-export.csv", "type": "CSV Export"},
            {"path": "\\\\fileserver\\it-share\\pentera-scan-march.xlsx", "type": "Excel Report"},
        ]

        for r in self.results:
            print_success(f"Found: {r['platform']} at {r['url']} (confidence: {r['confidence']})")

        for d in self.dns_findings:
            print_success(f"DNS: {d['hostname']} → {d['ip']}")

        for s in self.share_findings:
            print_warning(f"Exposed report: {s['path']}")

        print_info(f"Demo discovery complete: {len(self.results)} platform(s), "
                   f"{len(self.dns_findings)} DNS record(s), {len(self.share_findings)} exposed report(s)")

        return self.results
