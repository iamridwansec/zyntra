import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

from modules.web.access_control import (
    classify_response,
    check_resource_access
)


class TestAccessControl(unittest.TestCase):

    def test_classify_successful_response(self):
        self.assertEqual(
            classify_response(200),
            "successful_response"
        )

    def test_classify_redirect_response(self):
        self.assertEqual(
            classify_response(302),
            "redirect_response"
        )

    def test_classify_authentication_challenge(self):
        self.assertEqual(
            classify_response(401),
            "authentication_challenge"
        )

    def test_classify_access_forbidden(self):
        self.assertEqual(
            classify_response(403),
            "access_forbidden"
        )

    def test_classify_http_error(self):
        self.assertEqual(
            classify_response(500),
            "http_error"
        )

    @patch("modules.web.access_control.urllib.request.urlopen")
    def test_successful_access(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.url = "https://example.com/"
        mock_urlopen.return_value.__enter__.return_value = response

        result = check_resource_access("https://example.com/")

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["access_signal"], "successful_response")
        self.assertFalse(result["redirected"])

    @patch("modules.web.access_control.urllib.request.urlopen")
    def test_redirected_access(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.url = "https://example.com/login"
        mock_urlopen.return_value.__enter__.return_value = response

        result = check_resource_access("https://example.com/private")

        self.assertTrue(result["redirected"])
        self.assertEqual(result["final_url"], "https://example.com/login")

    @patch(
        "modules.web.access_control.urllib.request.urlopen",
        side_effect=HTTPError(
            "https://example.com/private",
            403,
            "Forbidden",
            {},
            None
        )
    )
    def test_forbidden_access(self, mock_urlopen):
        result = check_resource_access("https://example.com/private")

        self.assertEqual(result["status_code"], 403)
        self.assertEqual(result["access_signal"], "access_forbidden")

    @patch(
        "modules.web.access_control.urllib.request.urlopen",
        side_effect=URLError("Connection failed")
    )
    def test_connection_error(self, mock_urlopen):
        result = check_resource_access("https://example.com/")

        self.assertIsNone(result["status_code"])
        self.assertEqual(result["access_signal"], "connection_error")
        self.assertEqual(result["error"], "Connection failed")


if __name__ == "__main__":
    unittest.main()
