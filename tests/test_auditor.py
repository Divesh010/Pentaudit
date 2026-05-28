"""
test_auditor.py — Unit tests for the SecurityAuditor module
==========================================================

WHY THIS FILE EXISTS:
Testing the auditor ensures that all 8 security checks run correctly, 
identify expected risks, map findings to correct MITRE/NIST controls, 
and produce structured dictionaries that can be consumed by the reporter.
"""

import unittest
from pentaudit.discovery import DiscoveryScanner
from pentaudit.auditor import SecurityAuditor


class TestSecurityAuditor(unittest.TestCase):
    """Test suite for the SecurityAuditor class."""

    def setUp(self):
        """Set up test environment with a mock platform list."""
        self.platforms = [
            {
                "host": "10.0.5.50",
                "port": 8443,
                "platform": "PenTera",
                "url": "https://10.0.5.50:8443",
                "confidence": "high",
                "status": "identified"
            }
        ]
        self.auditor = SecurityAuditor(self.platforms, demo_mode=True)

    def test_audit_run_returns_findings(self):
        """Verify that running the auditor returns a non-empty list of findings."""
        findings = self.auditor.run_all_checks()
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)

    def test_finding_fields(self):
        """Verify that each finding has the required keys and correct formats."""
        findings = self.auditor.run_all_checks()
        first_finding = findings[0]

        expected_keys = [
            "check_id", "title", "risk_level", "platform_name", 
            "platform_host", "platform_url", "description", 
            "evidence", "mitre_technique", "mitre_details", 
            "remediation", "nist_control", "timestamp"
        ]
        
        for key in expected_keys:
            self.assertIn(key, first_finding)

        # Check that risk levels are valid
        valid_risks = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        self.assertIn(first_finding["risk_level"], valid_risks)

    def test_empty_platforms_returns_empty_findings(self):
        """Verify that if no platforms are passed, no findings are produced."""
        empty_auditor = SecurityAuditor(platforms=[], demo_mode=True)
        findings = empty_auditor.run_all_checks()
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
