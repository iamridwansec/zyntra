import unittest
import json
import subprocess
from unittest.mock import patch, MagicMock

from modules.recon.intelligence import (
    collect_whois,
    collect_rdap,
    collect_ip_intelligence,
    extract_ip_intelligence
)


class TestIntelligence(unittest.TestCase):


    @patch(
        "modules.recon.intelligence.subprocess.run",
        side_effect=subprocess.TimeoutExpired("whois", 10)
    )
    def test_collect_whois_timeout(self, mock_run):
        result = collect_whois("example.com")

        self.assertIsNone(result["status"])
        self.assertEqual(result["data"], "")

    @patch(
        "modules.recon.intelligence.subprocess.run",
        side_effect=FileNotFoundError("whois executable not found")
    )
    def test_collect_whois_missing_executable(self, mock_run):
        result = collect_whois("example.com")

        self.assertIsNone(result["status"])
        self.assertEqual(result["data"], "")

    @patch("modules.recon.intelligence.urllib.request.urlopen")
    def test_collect_rdap(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps(
            {"ldhName": "EXAMPLE.COM"}
        ).encode()

        mock_urlopen.return_value.__enter__.return_value = response

        result = collect_rdap("example.com")

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["data"]["ldhName"], "EXAMPLE.COM")

    @patch("modules.recon.intelligence.urllib.request.urlopen")
    def test_collect_ip_intelligence(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps(
            {"name": "Example Network"}
        ).encode()

        mock_urlopen.return_value.__enter__.return_value = response

        result = collect_ip_intelligence("192.0.2.10")

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["data"]["name"], "Example Network")

    @patch(
        "modules.recon.intelligence.urllib.request.urlopen",
        side_effect=OSError("Connection failed")
    )
    def test_rdap_failure(self, mock_urlopen):
        result = collect_rdap("example.com")

        self.assertIsNone(result["status"])
        self.assertEqual(result["data"], {})
        self.assertEqual(result["error"], "Connection failed")

    @patch(
        "modules.recon.intelligence.urllib.request.urlopen",
        side_effect=OSError("Connection failed")
    )
    def test_ip_intelligence_failure(self, mock_urlopen):
        result = collect_ip_intelligence("192.0.2.10")

        self.assertIsNone(result["status"])
        self.assertEqual(result["data"], {})
        self.assertEqual(result["error"], "Connection failed")

    def test_extract_ip_intelligence(self):
        data = {
            "name": "Example Network",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
            "entities": []
        }

        result = extract_ip_intelligence(data)

        self.assertEqual(result["network_name"], "Example Network")
        self.assertEqual(result["start_address"], "192.0.2.0")
        self.assertEqual(result["end_address"], "192.0.2.255")
        self.assertEqual(result["cidrs"], data["cidr0_cidrs"])
        self.assertEqual(result["organizations"], [])


if __name__ == "__main__":
    unittest.main()
