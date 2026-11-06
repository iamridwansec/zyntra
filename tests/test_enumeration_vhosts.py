import unittest
from unittest.mock import patch

from modules.enumeration.vhosts import discover_vhosts


class TestVHostDiscovery(unittest.TestCase):

    @patch("modules.enumeration.vhosts.resolve_ips")
    @patch("modules.enumeration.vhosts.load_vhost_prefixes")
    def test_no_ipv4_address(self, mock_wordlist, mock_dns):
        mock_wordlist.return_value = ["www"]
        mock_dns.return_value = {"ipv4": [], "ipv6": []}

        result = discover_vhosts("https://example.com")

        self.assertEqual(result["status"], "error")
        self.assertIn("No IPv4 address", result["message"])

    @patch("modules.enumeration.vhosts.fetch_response")
    @patch("modules.enumeration.vhosts.resolve_ips")
    @patch("modules.enumeration.vhosts.load_vhost_prefixes")
    def test_distinct_virtual_host(
        self, mock_wordlist, mock_dns, mock_fetch
    ):
        mock_wordlist.return_value = ["www"]
        mock_dns.return_value = {"ipv4": ["192.0.2.10"], "ipv6": []}

        baseline = {
            "status_code": 200,
            "content_length": 100,
            "body_hash": "baseline",
            "location": None
        }

        control = {
            "status_code": 200,
            "content_length": 100,
            "body_hash": "control",
            "location": None
        }

        candidate = {
            "status_code": 200,
            "content_length": 250,
            "body_hash": "distinct",
            "location": None
        }

        mock_fetch.side_effect = [baseline, control, candidate]

        result = discover_vhosts("https://example.com")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["tested"], 1)
        self.assertEqual(len(result["potential_vhosts"]), 1)
        self.assertEqual(
            result["potential_vhosts"][0]["hostname"],
            "www.example.com"
        )
        self.assertEqual(
            result["potential_vhosts"][0]["classification"],
            "distinct_response"
        )

    @patch("modules.enumeration.vhosts.fetch_response")
    @patch("modules.enumeration.vhosts.resolve_ips")
    @patch("modules.enumeration.vhosts.load_vhost_prefixes")
    def test_baseline_failure(
        self, mock_wordlist, mock_dns, mock_fetch
    ):
        mock_wordlist.return_value = ["www"]
        mock_dns.return_value = {"ipv4": ["192.0.2.10"], "ipv6": []}
        mock_fetch.side_effect = OSError("Connection failed")

        result = discover_vhosts("https://example.com")

        self.assertEqual(result["status"], "error")
        self.assertIn("Baseline request failed", result["message"])


if __name__ == "__main__":
    unittest.main()
