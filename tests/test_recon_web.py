import unittest
from unittest.mock import patch, MagicMock
from modules.recon.web import discover_web_surface


class TestWebDiscovery(unittest.TestCase):

    @patch("modules.recon.web.urllib.request.urlopen")
    def test_successful_web_discovery(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {
            "Content-Type": "text/html",
            "Content-Length": "1024",
            "Location": "",
            "Allow": "GET, POST"
        }

        mock_urlopen.return_value.__enter__.return_value = response

        result = discover_web_surface("https://example.com")

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["content_type"], "text/html")
        self.assertEqual(result["content_length"], "1024")
        self.assertEqual(result["allow"], "GET, POST")

    @patch(
        "modules.recon.web.urllib.request.urlopen",
        side_effect=OSError("Connection failed")
    )
    def test_web_discovery_failure(self, mock_urlopen):
        result = discover_web_surface("https://example.com")

        self.assertIsNone(result["status"])
        self.assertEqual(result["url"], "https://example.com")
        self.assertIn("Connection failed", result["error"])


if __name__ == "__main__":
    unittest.main()
