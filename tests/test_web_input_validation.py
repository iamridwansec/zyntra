import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

from modules.web.input_validation import (
    inspect_input_reflection,
    ReflectionContextParser
)


class TestInputReflection(unittest.TestCase):

    def test_detect_html_text_reflection(self):
        parser = ReflectionContextParser("MARKER")
        parser.feed("<html><body>MARKER</body></html>")

        self.assertIn("html_text", parser.contexts)

    def test_detect_html_attribute_reflection(self):
        parser = ReflectionContextParser("MARKER")
        parser.feed('<input value="MARKER">')

        self.assertIn("html_attribute", parser.contexts)

    def test_detect_script_reflection(self):
        parser = ReflectionContextParser("MARKER")
        parser.feed("<script>const value = 'MARKER';</script>")

        self.assertIn("script", parser.contexts)

    def test_detect_html_comment_reflection(self):
        parser = ReflectionContextParser("MARKER")
        parser.feed("<!-- MARKER -->")

        self.assertIn("html_comment", parser.contexts)

    @patch("modules.web.input_validation.urllib.request.urlopen")
    def test_successful_reflection(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.url = "https://example.com/?q=MARKER"
        response.headers = {"Content-Type": "text/html"}
        response.read.return_value = b"<p>ZYNTRA_REFLECTION_TEST</p>"
        mock_urlopen.return_value.__enter__.return_value = response

        result = inspect_input_reflection(
            "https://example.com/?q=original",
            "q"
        )

        self.assertTrue(result["marker_reflected"])
        self.assertEqual(result["reflection_count"], 1)
        self.assertIn("html_text", result["reflection_contexts"])

    @patch("modules.web.input_validation.urllib.request.urlopen")
    def test_no_reflection(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.url = "https://example.com/"
        response.headers = {"Content-Type": "text/html"}
        response.read.return_value = b"<p>No marker here</p>"
        mock_urlopen.return_value.__enter__.return_value = response

        result = inspect_input_reflection(
            "https://example.com/?q=test",
            "q"
        )

        self.assertFalse(result["marker_reflected"])
        self.assertEqual(result["reflection_count"], 0)
        self.assertEqual(result["reflection_contexts"], [])

    @patch(
        "modules.web.input_validation.urllib.request.urlopen",
        side_effect=URLError("Connection failed")
    )
    def test_connection_error(self, mock_urlopen):
        result = inspect_input_reflection(
            "https://example.com/?q=test",
            "q"
        )

        self.assertEqual(result["status"], "connection_error")
        self.assertEqual(result["error"], "Connection failed")

    def test_reject_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            inspect_input_reflection("ftp://example.com/?q=test", "q")

    def test_reject_missing_parameter(self):
        with self.assertRaises(ValueError):
            inspect_input_reflection("https://example.com/", "")


if __name__ == "__main__":
    unittest.main()
