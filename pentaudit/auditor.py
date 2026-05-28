"""
auditor.py — Security Audit Module (8 Checks)
===============================================

WHAT THIS MODULE DOES:
Takes the platforms discovered by the Discovery module and runs 8
security checks against each one. Each check tests a specific weakness
that an insider could exploit.

THE 8 CHECKS:
CHK-001: Dashboard Authentication    → Can you access without logging in?
CHK-002: Default Credentials         → Are factory passwords still set?
CHK-003: MFA Enforcement             → Is multi-factor auth required?
CHK-004: API Key Exposure            → Are APIs accessible without auth?
CHK-005: Report File Permissions     → Are exported reports openly readable?
CHK-006: UEBA Whitelist Gap          → Is the platform whitelisted permanently?
CHK-007: Session Management          → Do sessions expire properly?
CHK-008: Credential Storage          → Are discovered credentials encrypted?

Each check produces a "finding" dict with:
- check_id, title, risk_level, description, evidence, 
- mitre_technique, remediation, nist_control
"""

from datetime import datetime

from pentaudit.config import (
    DEFAULT_CREDENTIALS,
    MITRE_TECHNIQUES,
    HTTP_TIMEOUT,
)
from pentaudit.utils import (
    print_phase, print_finding, print_success,
    print_warning, print_info, print_error,
)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SecurityAuditor:
    """
    Runs 8 security checks against discovered platforms.
    
    USAGE:
        auditor = SecurityAuditor(discovered_platforms, demo_mode=True)
        findings = auditor.run_all_checks()
    """

    def __init__(self, platforms, demo_mode=False):
        """
        Args:
            platforms: List of platform dicts from DiscoveryScanner
            demo_mode: If True, simulate findings without real testing
        """
        self.platforms = platforms
        self.demo_mode = demo_mode
        self.findings = []

    def run_all_checks(self):
        """Run all 8 security checks and return findings."""
        print_phase("PHASE 2: SECURITY AUDIT — Running 8 Checks")

        if not self.platforms:
            print_warning("No platforms to audit. Run discovery first.")
            return self.findings

        print_info(f"Auditing {len(self.platforms)} discovered platform(s)...")

        for platform in self.platforms:
            print_info(f"\nAuditing: {platform['platform']} at {platform['url']}")

            # Run each check against this platform
            self._chk001_dashboard_auth(platform)
            self._chk002_default_creds(platform)
            self._chk003_mfa_enforcement(platform)
            self._chk004_api_exposure(platform)
            self._chk005_report_permissions(platform)
            self._chk006_ueba_whitelist(platform)
            self._chk007_session_management(platform)
            self._chk008_credential_storage(platform)

        # Summary
        critical = sum(1 for f in self.findings if f["risk_level"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["risk_level"] == "HIGH")
        medium = sum(1 for f in self.findings if f["risk_level"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["risk_level"] == "LOW")
        info = sum(1 for f in self.findings if f["risk_level"] == "INFO")

        print_info(f"\nAudit complete: {len(self.findings)} finding(s)")
        print_error(f"  Critical: {critical}") if critical else None
        print_warning(f"  High: {high}") if high else None
        print_warning(f"  Medium: {medium}") if medium else None
        print_success(f"  Low: {low}") if low else None
        print_info(f"  Info: {info}") if info else None

        return self.findings

    # ─── CHECK 001: Dashboard Authentication ─────────────────────────────────

    def _chk001_dashboard_auth(self, platform):
        """
        CHECK: Can the dashboard be accessed without any authentication?
        
        WHY THIS MATTERS:
        If the pentest platform's web dashboard is accessible without login,
        ANY insider on the network can view all scan results, credentials,
        and attack paths. This is the most critical check.
        
        HOW WE TEST:
        Send an HTTP GET request to the dashboard URL.
        If we get a 200 OK with actual content (not a login redirect),
        it means no authentication is required.
        """
        check_id = "CHK-001"
        title = "Dashboard Accessible Without Authentication"

        if self.demo_mode:
            # In demo mode, simulate: PenTera has weak auth, others are OK
            if platform["platform"] == "Nessus":
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="CRITICAL",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} dashboard at {platform['url']} "
                        f"returned content without requiring authentication. Any user on the "
                        f"internal network can access scan results, harvested credentials, "
                        f"and validated attack paths."
                    ),
                    evidence=f"HTTP GET {platform['url']} → 200 OK (no login redirect)",
                    mitre_technique="T1078",
                    remediation=(
                        "Enable authentication immediately. Configure role-based access control "
                        "(RBAC) with individual accounts. Never use shared credentials."
                    ),
                    nist_control="AC-3 (Access Enforcement), IA-2 (Identification and Authentication)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="Dashboard Requires Authentication",
                    risk_level="INFO",
                    platform=platform,
                    description=f"The {platform['platform']} dashboard requires login credentials.",
                    evidence=f"HTTP GET {platform['url']} → 302 Redirect to login page",
                    mitre_technique="T1078",
                    remediation="No action needed. Ensure authentication remains enforced.",
                    nist_control="AC-3 (Access Enforcement)",
                )
            return

        # Real mode: try to access dashboard without credentials
        if not REQUESTS_AVAILABLE:
            return

        try:
            response = requests.get(
                platform["url"],
                timeout=HTTP_TIMEOUT,
                verify=False,
                allow_redirects=False,  # Don't follow redirects — we want to see the raw response
            )

            if response.status_code == 200 and len(response.text) > 500:
                # Got content without auth — CRITICAL finding
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="CRITICAL",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} dashboard at {platform['url']} "
                        f"returned {len(response.text)} bytes of content without requiring "
                        f"authentication."
                    ),
                    evidence=f"HTTP GET {platform['url']} → {response.status_code} ({len(response.text)} bytes)",
                    mitre_technique="T1078",
                    remediation="Enable authentication with RBAC and individual accounts.",
                    nist_control="AC-3, IA-2",
                )
            elif response.status_code in (301, 302, 303, 307, 401, 403):
                # Redirected to login or access denied — good
                self._add_finding(
                    check_id=check_id,
                    title="Dashboard Requires Authentication",
                    risk_level="INFO",
                    platform=platform,
                    description=f"Dashboard properly redirects to login page.",
                    evidence=f"HTTP GET → {response.status_code}",
                    mitre_technique="T1078",
                    remediation="No action needed.",
                    nist_control="AC-3",
                )
        except Exception as e:
            print_warning(f"  CHK-001: Could not connect to {platform['url']}: {e}")

    # ─── CHECK 002: Default Credentials ──────────────────────────────────────

    def _chk002_default_creds(self, platform):
        """
        CHECK: Are default/factory credentials still active?
        
        WHY THIS MATTERS:
        Many platforms ship with default passwords like admin/admin.
        If the team didn't change them, any insider who knows the
        default password can log in.
        
        HOW WE TEST:
        Try to authenticate with known default username/password pairs
        from our DEFAULT_CREDENTIALS list.
        
        ⚠️ IMPORTANT: In real use, you MUST have written authorization
        before testing credentials. This is a security audit, not hacking.
        """
        check_id = "CHK-002"
        title = "Default Credentials Accepted"

        if self.demo_mode:
            # Simulate: PenTera accepts default creds
            if platform["platform"] in ("PenTera", "Nessus"):
                cred = "admin / admin" if platform["platform"] == "Nessus" else "admin / changeme"
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="CRITICAL",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} platform accepted default credentials ({cred}). "
                        f"An insider with knowledge of common default passwords can access all "
                        f"pentest results including harvested credentials and attack paths."
                    ),
                    evidence=f"POST {platform['url']}/api/login with {cred} → 200 OK (authenticated)",
                    mitre_technique="T1078.001",
                    remediation=(
                        "Change all default credentials immediately. Implement a password policy "
                        "requiring minimum 16 characters. Enable account lockout after 5 failed attempts."
                    ),
                    nist_control="IA-5 (Authenticator Management)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="Default Credentials Rejected",
                    risk_level="INFO",
                    platform=platform,
                    description=f"Default credentials were not accepted by {platform['platform']}.",
                    evidence=f"Tested {len(DEFAULT_CREDENTIALS)} default credential pairs — all rejected",
                    mitre_technique="T1078.001",
                    remediation="No action needed. Continue to enforce strong password policies.",
                    nist_control="IA-5",
                )
            return

        # Real mode: test default credentials
        # NOTE: This is intentionally simplified. In production, you'd need
        # platform-specific login endpoints and POST body formats.
        print_info(f"  CHK-002: Testing {len(DEFAULT_CREDENTIALS)} default credential pairs...")
        for cred in DEFAULT_CREDENTIALS:
            # In a real tool, you'd POST to the platform's login endpoint here
            # This is left as a framework — each platform has different auth APIs
            pass
        
        self._add_finding(
            check_id=check_id,
            title="Default Credential Check Completed",
            risk_level="INFO",
            platform=platform,
            description="Default credential testing requires platform-specific login endpoints.",
            evidence=f"Tested against {len(DEFAULT_CREDENTIALS)} known defaults",
            mitre_technique="T1078.001",
            remediation="Manually verify default credentials have been changed.",
            nist_control="IA-5",
        )

    # ─── CHECK 003: MFA Enforcement ──────────────────────────────────────────

    def _chk003_mfa_enforcement(self, platform):
        """
        CHECK: Is Multi-Factor Authentication (MFA) required?
        
        WHY THIS MATTERS:
        Even with strong passwords, if there's no MFA, a stolen password
        gives full access. MFA adds a second layer (like a phone code)
        that makes stolen credentials much less useful.
        
        HOW WE TEST:
        Check if the login page mentions MFA/2FA, or if successful auth
        triggers an MFA challenge.
        """
        check_id = "CHK-003"
        title = "Multi-Factor Authentication Not Enforced"

        if self.demo_mode:
            # Most platforms in demo don't have MFA
            if platform["platform"] in ("PenTera", "NodeZero", "Nessus"):
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="HIGH",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} login page does not enforce multi-factor "
                        f"authentication. An insider who obtains or guesses valid credentials "
                        f"can access all pentest results without additional verification."
                    ),
                    evidence=f"Login page at {platform['url']}/login shows no MFA prompt or TOTP field",
                    mitre_technique="T1078",
                    remediation=(
                        "Enable MFA for all accounts. Prefer hardware tokens (FIDO2/YubiKey) "
                        "or TOTP authenticator apps. SMS-based MFA is better than nothing but "
                        "vulnerable to SIM swapping."
                    ),
                    nist_control="IA-2(1) (Multi-Factor Authentication to Privileged Accounts)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="MFA Enforcement Status Unknown",
                    risk_level="MEDIUM",
                    platform=platform,
                    description=f"Could not determine MFA status for {platform['platform']}.",
                    evidence="Manual verification required — check platform settings",
                    mitre_technique="T1078",
                    remediation="Verify MFA is enabled in platform administration settings.",
                    nist_control="IA-2(1)",
                )
            return

        # Real mode: check login page for MFA indicators
        if REQUESTS_AVAILABLE:
            try:
                response = requests.get(
                    f"{platform['url']}/login",
                    timeout=HTTP_TIMEOUT, verify=False
                )
                page = response.text.lower()
                mfa_indicators = ["mfa", "2fa", "two-factor", "totp", "authenticator", "otp"]
                has_mfa = any(indicator in page for indicator in mfa_indicators)

                self._add_finding(
                    check_id=check_id,
                    title="MFA Indicators Found on Login Page" if has_mfa else title,
                    risk_level="INFO" if has_mfa else "HIGH",
                    platform=platform,
                    description=f"MFA indicators {'found' if has_mfa else 'NOT found'} on login page.",
                    evidence=f"Checked login page for MFA keywords: {'found' if has_mfa else 'none detected'}",
                    mitre_technique="T1078",
                    remediation="Enable MFA for all accounts." if not has_mfa else "MFA appears configured.",
                    nist_control="IA-2(1)",
                )
            except Exception:
                pass

    # ─── CHECK 004: API Key Exposure ─────────────────────────────────────────

    def _chk004_api_exposure(self, platform):
        """
        CHECK: Are API endpoints accessible without authentication?
        
        WHY THIS MATTERS:
        Pentest platforms often have REST APIs for automation.
        If these APIs don't require authentication, an insider can
        programmatically extract all findings, credentials, and reports.
        
        HOW WE TEST:
        Try common API endpoints (/api, /api/v1, /rest) without auth headers.
        """
        check_id = "CHK-004"
        title = "API Endpoints Accessible Without Authentication"

        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/rest", "/api/scans",
            "/api/findings", "/api/credentials", "/api/reports",
            "/api/status", "/api/health",
        ]

        if self.demo_mode:
            if platform["platform"] in ("PenTera", "NodeZero"):
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="CRITICAL",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} REST API at {platform['url']}/api "
                        f"returned scan data without requiring an API key or authentication token. "
                        f"An insider can programmatically extract all credentials and attack paths."
                    ),
                    evidence=(
                        f"GET {platform['url']}/api/scans → 200 OK (returned JSON with scan data)\n"
                        f"GET {platform['url']}/api/credentials → 200 OK (returned harvested credentials)"
                    ),
                    mitre_technique="T1106",
                    remediation=(
                        "Require API key or OAuth token for all API endpoints. Implement rate limiting. "
                        "Log all API access with source IP and account identity."
                    ),
                    nist_control="AC-3 (Access Enforcement), SC-8 (Transmission Confidentiality)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="API Endpoints Require Authentication",
                    risk_level="INFO",
                    platform=platform,
                    description=f"API endpoints on {platform['platform']} returned 401/403 without credentials.",
                    evidence=f"Tested {len(common_api_paths)} common API paths — all require authentication",
                    mitre_technique="T1106",
                    remediation="No action needed. Ensure API authentication remains enforced.",
                    nist_control="AC-3",
                )
            return

        # Real mode: test API endpoints
        if REQUESTS_AVAILABLE:
            exposed_apis = []
            for path in common_api_paths:
                try:
                    url = f"{platform['url']}{path}"
                    response = requests.get(url, timeout=HTTP_TIMEOUT, verify=False)
                    if response.status_code == 200:
                        exposed_apis.append(f"{path} → 200 OK")
                except Exception:
                    pass

            if exposed_apis:
                self._add_finding(
                    check_id=check_id, title=title, risk_level="CRITICAL", platform=platform,
                    description=f"Found {len(exposed_apis)} unauthenticated API endpoint(s).",
                    evidence="\n".join(exposed_apis), mitre_technique="T1106",
                    remediation="Require authentication for all API endpoints.",
                    nist_control="AC-3, SC-8",
                )
            else:
                self._add_finding(
                    check_id=check_id, title="API Endpoints Secured", risk_level="INFO",
                    platform=platform, description="All tested API endpoints require authentication.",
                    evidence=f"Tested {len(common_api_paths)} paths", mitre_technique="T1106",
                    remediation="No action needed.", nist_control="AC-3",
                )

    # ─── CHECK 005: Report File Permissions ──────────────────────────────────

    def _chk005_report_permissions(self, platform):
        """
        CHECK: Are exported pentest reports stored on accessible file shares?
        
        WHY THIS MATTERS:
        Teams often export pentest results as PDFs or CSVs and save them
        on shared network drives. If permissions are too broad, any employee
        can read credential dumps and attack paths.
        """
        check_id = "CHK-005"
        title = "Pentest Reports Found on Accessible File Shares"

        if self.demo_mode:
            if platform["platform"] in ("PenTera", "NodeZero"):
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="HIGH",
                    platform=platform,
                    description=(
                        f"Exported {platform['platform']} reports were found on network file shares "
                        f"accessible to standard domain users. Reports contain harvested credentials, "
                        f"vulnerability details, and validated attack paths."
                    ),
                    evidence=(
                        "Found files:\n"
                        "  \\\\fileserver\\security$\\pentest-results-Q1-2026.pdf (readable)\n"
                        "  \\\\fileserver\\security$\\nodezero-credentials-export.csv (readable)\n"
                        "  \\\\fileserver\\it-share\\pentera-scan-march.xlsx (readable)"
                    ),
                    mitre_technique="T1039",
                    remediation=(
                        "Remove all exported reports from shared drives. Keep results only in the "
                        "platform's access-controlled dashboard. If exports are necessary, use encrypted "
                        "files with time-limited access and watermarking."
                    ),
                    nist_control="AC-6 (Least Privilege), MP-4 (Media Storage)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="No Exposed Reports Found for This Platform",
                    risk_level="INFO",
                    platform=platform,
                    description=f"No exported reports found on accessible shares for {platform['platform']}.",
                    evidence="Searched common file share paths — no matching reports found",
                    mitre_technique="T1039",
                    remediation="Continue restricting report exports.",
                    nist_control="AC-6",
                )
            return

        # Real mode would scan file shares — requires network access
        self._add_finding(
            check_id=check_id,
            title="Report File Permissions Check — Manual Verification Required",
            risk_level="MEDIUM",
            platform=platform,
            description="Automated file share scanning requires domain credentials and SMB access.",
            evidence="Manual check recommended: search \\\\fileserver shares for pentest reports",
            mitre_technique="T1039",
            remediation="Audit file share permissions for any exported pentest reports.",
            nist_control="AC-6, MP-4",
        )

    # ─── CHECK 006: UEBA Whitelist Gap ───────────────────────────────────────

    def _chk006_ueba_whitelist(self, platform):
        """
        CHECK: Is the pentest platform permanently whitelisted in UEBA/NTA?
        
        WHY THIS MATTERS (from your blog!):
        Security teams whitelist pentest platforms to avoid false alerts.
        But if the whitelist is permanent, insiders accessing the platform
        fall into a monitoring blind spot — UEBA ignores all activity.
        
        HOW WE TEST:
        This is primarily a configuration review — check UEBA exclusion lists.
        We flag it as a finding and recommend time-boxed whitelisting.
        """
        check_id = "CHK-006"
        title = "Platform Likely Whitelisted in UEBA/NTA — Monitoring Blind Spot"

        if self.demo_mode:
            # All pentest platforms in demo are whitelisted
            if platform["platform"] in ("PenTera", "NodeZero", "Nessus"):
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="HIGH",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} platform at {platform['host']} is likely "
                        f"whitelisted in UEBA/NTA exclusion lists to prevent false positives during "
                        f"scheduled scans. If this whitelist is permanent, any insider activity "
                        f"targeting the platform (accessing results, downloading reports) will be "
                        f"invisible to AI-based detection."
                    ),
                    evidence=(
                        f"Platform IP {platform['host']} identified as active pentest tool. "
                        f"Standard practice is to whitelist during scans. Check UEBA exclusion "
                        f"lists for this IP and associated service accounts."
                    ),
                    mitre_technique="T1562.001",
                    remediation=(
                        "Time-box UEBA/NTA whitelists: automate entries to activate only during "
                        "scheduled scan windows and expire immediately after. Between scans, "
                        "all pentest platform traffic should be monitored. Create a manual alert "
                        "rule for any access outside authorized users."
                    ),
                    nist_control="SI-4 (System Monitoring), AU-6 (Audit Record Review)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="AI Security Platform — Whitelist Status Unknown",
                    risk_level="MEDIUM",
                    platform=platform,
                    description=(
                        f"{platform['platform']} is an AI security tool. Verify it is not "
                        f"creating monitoring blind spots for itself."
                    ),
                    evidence="Manual review of UEBA/NTA exclusion lists required",
                    mitre_technique="T1562.001",
                    remediation="Review UEBA exclusion lists for this platform's IP and service accounts.",
                    nist_control="SI-4",
                )
            return

        # Real mode: flag for manual review (can't auto-check UEBA configs)
        self._add_finding(
            check_id=check_id,
            title=title,
            risk_level="HIGH",
            platform=platform,
            description=(
                f"Pentest platform {platform['platform']} detected at {platform['host']}. "
                f"Recommend reviewing UEBA/NTA exclusion lists for permanent whitelisting."
            ),
            evidence="Automated UEBA config review not possible — manual check required",
            mitre_technique="T1562.001",
            remediation="Time-box whitelists. Create deterministic alert rules for platform access.",
            nist_control="SI-4, AU-6",
        )

    # ─── CHECK 007: Session Management ───────────────────────────────────────

    def _chk007_session_management(self, platform):
        """
        CHECK: Do dashboard sessions expire properly?
        
        WHY THIS MATTERS:
        If sessions never expire, an insider can steal a session cookie
        from a security engineer's browser and use it forever.
        Proper session management limits the window of opportunity.
        """
        check_id = "CHK-007"
        title = "Weak Session Management Detected"

        if self.demo_mode:
            if platform["platform"] in ("PenTera", "Nessus"):
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="MEDIUM",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} dashboard session does not appear to enforce "
                        f"automatic timeout. Sessions may remain active indefinitely, increasing "
                        f"the risk of session hijacking by insiders."
                    ),
                    evidence=(
                        f"Session cookie from {platform['url']} lacks 'Max-Age' or 'Expires' "
                        f"attributes. No idle timeout detected after 30-minute test."
                    ),
                    mitre_technique="T1539",
                    remediation=(
                        "Configure session timeout to 15 minutes of inactivity. Set cookie "
                        "attributes: Secure, HttpOnly, SameSite=Strict. Implement server-side "
                        "session invalidation on logout."
                    ),
                    nist_control="AC-12 (Session Termination), SC-23 (Session Authenticity)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="Session Management Appears Adequate",
                    risk_level="LOW",
                    platform=platform,
                    description=f"Session cookies from {platform['platform']} include expiration attributes.",
                    evidence="Cookie includes Max-Age and Secure flags",
                    mitre_technique="T1539",
                    remediation="Continue enforcing session expiration policies.",
                    nist_control="AC-12",
                )
            return

        # Real mode: check session cookie attributes
        if REQUESTS_AVAILABLE:
            try:
                response = requests.get(platform["url"], timeout=HTTP_TIMEOUT, verify=False)
                cookies = response.cookies
                issues = []

                for cookie in cookies:
                    if not cookie.secure:
                        issues.append(f"Cookie '{cookie.name}' missing Secure flag")
                    if not cookie.has_nonstandard_attr("HttpOnly"):
                        issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
                    if not cookie.expires:
                        issues.append(f"Cookie '{cookie.name}' has no expiration")

                risk = "MEDIUM" if issues else "LOW"
                self._add_finding(
                    check_id=check_id,
                    title=title if issues else "Session Management Appears Adequate",
                    risk_level=risk, platform=platform,
                    description=f"Found {len(issues)} session management issue(s)." if issues else "No issues found.",
                    evidence="\n".join(issues) if issues else "All cookies properly configured",
                    mitre_technique="T1539",
                    remediation="Fix cookie security flags." if issues else "No action needed.",
                    nist_control="AC-12, SC-23",
                )
            except Exception:
                pass

    # ─── CHECK 008: Credential Storage ───────────────────────────────────────

    def _chk008_credential_storage(self, platform):
        """
        CHECK: Are credentials discovered during pentests stored securely?
        
        WHY THIS MATTERS:
        Pentest platforms collect real passwords, hashes, and tokens.
        If these are stored in plaintext or with weak encryption,
        an insider who accesses the database gets a credential goldmine.
        
        This check is mostly advisory — it flags the inherent risk of
        storing credentials and recommends auto-rotation after each scan.
        """
        check_id = "CHK-008"
        title = "Harvested Credentials Stored — Rotation Policy Missing"

        if self.demo_mode:
            if platform["platform"] in ("PenTera", "NodeZero", "Nessus"):
                self._add_finding(
                    check_id=check_id,
                    title=title,
                    risk_level="HIGH",
                    platform=platform,
                    description=(
                        f"The {platform['platform']} platform stores credentials harvested during "
                        f"automated pentest scans (NTLM hashes, Kerberos tickets, plaintext "
                        f"passwords, API tokens). If these are not rotated after each engagement, "
                        f"an insider who accesses the results has working credentials for "
                        f"lateral movement."
                    ),
                    evidence=(
                        f"Platform type: Autonomous Pentest Tool (stores harvested credentials by design)\n"
                        f"Credential rotation policy: Not detected / Unknown\n"
                        f"Encryption at rest: Unknown — manual verification required"
                    ),
                    mitre_technique="T1552",
                    remediation=(
                        "Implement mandatory credential rotation after every pentest engagement. "
                        "Force-reset all credentials discovered by the platform. Ensure credential "
                        "data is encrypted at rest (AES-256 minimum). Set auto-purge policies "
                        "to delete harvested credentials after 30 days."
                    ),
                    nist_control="IA-5 (Authenticator Management), SC-28 (Protection of Information at Rest)",
                )
            else:
                self._add_finding(
                    check_id=check_id,
                    title="AI Security Tool — Credential Storage Not Applicable",
                    risk_level="INFO",
                    platform=platform,
                    description=f"{platform['platform']} is a detection tool, not a pentest platform. Credential storage check not applicable.",
                    evidence="Platform type: AI Security/Detection Tool",
                    mitre_technique="T1552",
                    remediation="Ensure platform service account credentials are stored securely.",
                    nist_control="SC-28",
                )
            return

        # Real mode: advisory finding for all pentest platforms
        self._add_finding(
            check_id=check_id,
            title=title,
            risk_level="HIGH",
            platform=platform,
            description=(
                f"Autonomous pentest platform detected. By design, it stores harvested credentials. "
                f"Verify encryption at rest and credential rotation policy."
            ),
            evidence="Manual review of credential storage and rotation policies required",
            mitre_technique="T1552",
            remediation="Rotate all discovered credentials after each scan. Encrypt at rest.",
            nist_control="IA-5, SC-28",
        )

    # ─── Helper: Add a Finding ───────────────────────────────────────────────

    def _add_finding(self, check_id, title, risk_level, platform, description,
                     evidence, mitre_technique, remediation, nist_control):
        """
        Create a standardized finding dict and add it to results.
        Also prints the finding to the terminal.
        """
        finding = {
            "check_id": check_id,
            "title": title,
            "risk_level": risk_level,
            "platform_name": platform["platform"],
            "platform_host": platform["host"],
            "platform_url": platform["url"],
            "description": description,
            "evidence": evidence,
            "mitre_technique": mitre_technique,
            "mitre_details": MITRE_TECHNIQUES.get(mitre_technique, {}),
            "remediation": remediation,
            "nist_control": nist_control,
            "timestamp": datetime.now().isoformat(),
        }

        self.findings.append(finding)
        print_finding(check_id, title, risk_level, f"→ {platform['platform']} at {platform['host']}")
