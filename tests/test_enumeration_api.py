import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

from modules.enumeration.api import discover_api, COMMON_API_PATHS


class TestAPIDiscovery(unittest.TestCase):

    @patch("modules.enumeration.api.urllib.request.urlopen")
    def test_json_endpoint(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Type": "application/json"}
        mock_urlopen.return_value.__enter__.return_value = response

        results = discover_api("https://example.com/")

        self.assertEqual(len(results), len(COMMON_API_PATHS))
        self.assertEqual(results[0]["url"], "https://example.com/api")
        self.assertEqual(results[0]["result_type"], "candidate")

    @patch("modules.enumeration.api.urllib.request.urlopen")
    def test_html_endpoint(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Type": "text/html"}
        mock_urlopen.return_value.__enter__.return_value = response

        results = discover_api("https://example.com")

        self.assertEqual(results[0]["result_type"], "not_confirmed")

    @patch("modules.enumeration.api.urllib.request.urlopen")
    def test_protected_endpoint(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://example.com/api", 403, "Forbidden", {}, None
        )

        results = discover_api("https://example.com")

        self.assertEqual(results[0]["status"], 403)
        self.assertEqual(results[0]["result_type"], "protected")

    @patch("modules.enumeration.api.urllib.request.urlopen")
    def test_not_found_endpoint(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://example.com/api", 404, "Not Found", {}, None
        )

        results = discover_api("https://example.com")

        self.assertEqual(results[0]["status"], 404)
        self.assertEqual(results[0]["result_type"], "not_found")

    @patch(
        "modules.enumeration.api.urllib.request.urlopen",
        side_effect=TimeoutError("Request timed out")
    )
    def test_timeout(self, mock_urlopen):
        results = discover_api("https://example.com")

        self.assertEqual(results[0]["result_type"], "timeout")

    @patch(
        "modules.enumeration.api.urllib.request.urlopen",
        side_effect=URLError("Connection refused")
    )
    def test_connection_error(self, mock_urlopen):
        results = discover_api("https://example.com")

        self.assertEqual(results[0]["result_type"], "error")
        self.assertIn("Connection refused", results[0]["error"])


if __name__ == "__main__":
    unittest.main()
