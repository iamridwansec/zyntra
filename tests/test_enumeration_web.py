import unittest
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from modules.enumeration.web import (
    crawl_web_surface,
    discover_web_surface,
    extract_javascript,
    extract_links,
    discover_page_javascript,
    normalize_urls,
    is_same_host
)


class TestWebEnumeration(unittest.TestCase):

    def test_extract_links(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        self.assertEqual(
            extract_links(html),
            ["/about", "/contact"]
        )

    def test_extract_javascript(self):
        html = '<script src="/app.js"></script>'
        self.assertEqual(extract_javascript(html), ["/app.js"])

    def test_normalize_urls(self):
        results = normalize_urls(
            "https://example.com/page",
            ["/about", "/about#section", "https://other.com"]
        )
        self.assertEqual(
            results,
            ["https://example.com/about", "https://other.com"]
        )

    def test_same_host(self):
        self.assertTrue(
            is_same_host(
                "https://example.com",
                "https://example.com/about"
            )
        )
        self.assertFalse(
            is_same_host(
                "https://example.com",
                "https://other.com"
            )
        )

    def test_discover_page_javascript(self):
        pages = [{
            "url": "https://example.com/",
            "html": '<script src="/app.js"></script>'
        }]
        self.assertEqual(
            discover_page_javascript(pages),
            ["https://example.com/app.js"]
        )

    @patch("modules.enumeration.web.urllib.request.urlopen")
    def test_successful_web_discovery(self, mock_urlopen):
        response = MagicMock()
        response.url = "https://example.com/"
        response.status = 200
        response.headers = {"Content-Type": "text/html"}
        response.read.return_value = b"<html>Test</html>"
        mock_urlopen.return_value.__enter__.return_value = response

        result = discover_web_surface("https://example.com/")

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["html"], "<html>Test</html>")

    @patch(
        "modules.enumeration.web.urllib.request.urlopen",
        side_effect=URLError("Connection failed")
    )
    def test_web_discovery_error(self, mock_urlopen):
        result = discover_web_surface("https://example.com/")

        self.assertIsNone(result["status"])
        self.assertEqual(result["result_type"], "error")

    @patch("modules.enumeration.web.discover_web_surface")
    def test_crawl_same_host(self, mock_discover):
        mock_discover.side_effect = [
            {
                "url": "https://example.com/",
                "status": 200,
                "html": '<a href="/about">About</a>'
            },
            {
                "url": "https://example.com/about",
                "status": 200,
                "html": ""
            }
        ]

        results = crawl_web_surface("https://example.com/")

        self.assertEqual(len(results), 2)
        self.assertEqual(mock_discover.call_count, 2)

    @patch("modules.enumeration.web.discover_web_surface")
    def test_crawl_respects_max_pages(self, mock_discover):
        mock_discover.return_value = {
            "url": "https://example.com/",
            "status": 200,
            "html": (
                '<a href="/one">One</a>'
                '<a href="/two">Two</a>'
            )
        }

        results = crawl_web_surface(
            "https://example.com/",
            max_pages=2
        )

        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
