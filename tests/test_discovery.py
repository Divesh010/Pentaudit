"""
test_discovery.py — Unit tests for the DiscoveryScanner module
==============================================================

WHY THIS FILE EXISTS:
Writing automated tests shows that you are a professional software engineer.
It proves that your code works and ensures that if someone else modifies 
the scanner in the future, they don't break existing functionality.
"""

import unittest
from pentaudit.discovery import DiscoveryScanner


class TestDiscoveryScanner(unittest.TestCase):
    """Test suite for the DiscoveryScanner class."""

    def setUp(self):
        """Set up test environment before each test run."""
        self.scanner = DiscoveryScanner(target="10.0.5.0/24", demo_mode=True)

    def test_demo_discovery(self):
        """Verify that the discovery scanner returns simulated platforms in demo mode."""
        results = self.scanner.run()
        
        # We expect a list of platforms
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        
        # Check that expected keys are in each platform
        for platform in results:
            self.assertIn("host", platform)
            self.assertIn("port", platform)
            self.assertIn("platform", platform)
            self.assertIn("confidence", platform)
            self.assertIn("url", platform)

    def test_target_parsing_single_ip(self):
        """Verify that single IP parsing returns a list of one IP."""
        hosts = self.scanner._parse_target("192.168.1.5")
        self.assertEqual(hosts, ["192.168.1.5"])

    def test_target_parsing_cidr_24(self):
        """Verify that /24 CIDR parsing returns 254 IP addresses."""
        hosts = self.scanner._parse_target("192.168.1.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertEqual(hosts[0], "192.168.1.1")
        self.assertEqual(hosts[-1], "192.168.1.254")

    def test_signature_matching_none(self):
        """Verify that signature matching returns 'none' when there are no matches."""
        # Create a mock response object
        class MockResponse:
            def __init__(self):
                self.text = "<html><body>Standard Webpage</body></html>"
                self.headers = {"Server": "Apache"}
                
        mock_resp = MockResponse()
        signatures = {
            "title_keywords": ["nessus"],
            "header_keywords": ["nessus", "tenable"],
            "body_keywords": ["nessus"]
        }
        
        confidence = self.scanner._match_signatures(mock_resp, signatures)
        self.assertEqual(confidence, "none")


if __name__ == "__main__":
    unittest.main()
