import unittest
from unittest.mock import patch, MagicMock

from modules.enumeration.javascript import (
    discover_javascript,
    fetch_javascript,
    extract_endpoints,
    detect_api_keys
)


class TestJavaScriptDiscovery(unittest.TestCase):

    @patch("modules.enumeration.javascript.urllib.request.urlopen")
    def test_discover_script_urls(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = (
            b'<script src="/static/app.js"></script>'
            b'<script src="https://cdn.example.com/lib.js"></script>'
        )
        mock_urlopen.return_value.__enter__.return_value = response

        results = discover_javascript("https://example.com")

        self.assertEqual(results, [
            "https://example.com/static/app.js",
            "https://cdn.example.com/lib.js"
        ])

    @patch("modules.enumeration.javascript.urllib.request.urlopen")
    def test_fetch_javascript(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = b'fetch("/api/users");'
        mock_urlopen.return_value.__enter__.return_value = response

        result = fetch_javascript("https://example.com/app.js")

        self.assertEqual(result, 'fetch("/api/users");')

    def test_extract_endpoints(self):
        sample = 'fetch("/api/users"); const route = "/admin";'

        results = extract_endpoints(sample)

        self.assertEqual(results, ["/api/users", "/admin"])

    def test_detect_api_keys(self):
        sample = '''
        const api_key = "abc123";
        const API-KEY = "xyz789";
        '''

        results = detect_api_keys(sample)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["value"], "abc123")
        self.assertEqual(results[1]["value"], "xyz789")

    def test_no_api_keys(self):
        results = detect_api_keys('const username = "tester";')

        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
