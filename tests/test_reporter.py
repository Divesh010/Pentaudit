"""
test_reporter.py — Unit tests for the ReportGenerator module
============================================================

WHY THIS FILE EXISTS:
Testing the reporter ensures that we can calculate risk statistics,
render the HTML template successfully using Jinja2 or fallback strings,
and output valid files in the correct formats.
"""

import unittest
import os
import tempfile
import json
from pentaudit.reporter import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test suite for the ReportGenerator class."""

    def setUp(self):
        """Set up mock scan data."""
        self.platforms = [
            {
                "host": "10.0.5.50",
                "port": 8443,
                "platform": "PenTera",
                "url": "https://10.0.5.50:8443",
                "confidence": "high"
            }
        ]
        self.findings = [
            {
                "check_id": "CHK-001",
                "title": "Dashboard Accessible Without Authentication",
                "risk_level": "CRITICAL",
                "platform_name": "PenTera",
                "platform_host": "10.0.5.50",
                "platform_url": "https://10.0.5.50:8443",
                "description": "Exposed dashboard verified.",
                "evidence": "HTTP 200 OK",
                "mitre_technique": "T1078",
                "mitre_details": {"name": "Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078/"},
                "remediation": "Enable MFA immediately.",
                "nist_control": "AC-3"
            }
        ]
        self.scan_metadata = {"target": "10.0.5.0/24", "mode": "demo"}

    def test_statistics_calculation(self):
        """Verify that summary statistics are computed correctly from findings."""
        reporter = ReportGenerator(self.findings, self.platforms, self.scan_metadata)
        stats = reporter._calculate_stats()

        self.assertEqual(stats["total_findings"], 1)
        self.assertEqual(stats["total_platforms"], 1)
        self.assertEqual(stats["critical"], 1)
        self.assertEqual(stats["high"], 0)
        self.assertEqual(stats["overall_risk"], "CRITICAL")
        self.assertIn("T1078", stats["mitre_techniques_covered"])

    def test_report_generation(self):
        """Verify that report files (HTML and JSON) are created successfully."""
        reporter = ReportGenerator(self.findings, self.platforms, self.scan_metadata)
        
        # Use a temporary file path
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            json_path = os.path.join(tmpdir, "report.json")
            
            reporter.generate(output_path)
            
            # Check that both HTML and JSON files were written
            self.assertTrue(os.path.exists(output_path))
            self.assertTrue(os.path.exists(json_path))
            
            # Verify JSON file has correct structure
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.assertEqual(data["target"], "10.0.5.0/24")
                self.assertEqual(len(data["findings"]), 1)
                self.assertEqual(data["stats"]["overall_risk"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
