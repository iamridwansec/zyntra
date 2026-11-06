
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from modules.web.cors import (
    _inspect_request,
    _get_response_header,
    inspect_cors,
    CORS_HEADERS
)


class TestCORS(unittest.TestCase):

    def test_cors_header_list(self):
        self.assertIn("Access-Control-Allow-Origin", CORS_HEADERS)
        self.assertIn("Access-Control-Allow-Credentials", CORS_HEADERS)

    def test_get_response_header(self):
        result = {
            "status": "completed",
            "headers": [
                {
                    "header": "Access-Control-Allow-Origin",
                    "value": "*"
                }
            ]
        }

        self.assertEqual(
            _get_response_header(result, "access-control-allow-origin"),
            "*"
        )

    def test_get_header_from_failed_response(self):
        result = {
            "status": "connection_error",
            "headers": []
        }

        self.assertIsNone(
            _get_response_header(result, "Access-Control-Allow-Origin")
        )

    @patch("modules.web.cors.urllib.request.urlopen")
    def test_inspect_get_request(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.url = "https://example.com/"
        response.headers = {
            "Access-Control-Allow-Origin": "*"
        }
        mock_urlopen.return_value.__enter__.return_value = response

        result = _inspect_request(
            "https://example.com/",
            "GET",
            "https://probe.invalid"
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(
            _get_response_header(result, "Access-Control-Allow-Origin"),
            "*"
        )

        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(
            request.get_header("Origin"),
            "https://probe.invalid"
        )

    @patch("modules.web.cors.urllib.request.urlopen")
    def test_inspect_options_request(self, mock_urlopen):
        response = MagicMock()
        response.status = 204
        response.url = "https://example.com/"
        response.headers = {}
        mock_urlopen.return_value.__enter__.return_value = response

        _inspect_request(
            "https://example.com/",
            "OPTIONS",
            "https://probe.invalid"
        )

        request = mock_urlopen.call_args.args[0]

        self.assertEqual(request.get_method(), "OPTIONS")
        self.assertEqual(
            request.get_header("Access-control-request-method"),
            "GET"
        )
        self.assertEqual(
            request.get_header("Access-control-request-headers"),
            "X-Zyntra-Probe"
        )

    @patch(
        "modules.web.cors.urllib.request.urlopen",
        side_effect=URLError("Connection failed")
    )
    def test_connection_error(self, mock_urlopen):
        result = _inspect_request(
            "https://example.com/",
            "GET",
            "https://probe.invalid"
        )

        self.assertEqual(result["status"], "connection_error")
        self.assertEqual(result["error"], "Connection failed")

    @patch("modules.web.cors._inspect_request")
    def test_wildcard_origin_detection(self, mock_inspect):
        mock_inspect.return_value = {
            "status": "completed",
            "headers": [
                {
                    "header": "Access-Control-Allow-Origin",
                    "present": True,
                    "value": "*"
                },
                {
                    "header": "Access-Control-Allow-Credentials",
                    "present": False,
                    "value": None
                }
            ]
        }

        result = inspect_cors("https://example.com/", "12345678")

        self.assertTrue(
            any(
                item["indicator"] == "wildcard_origin"
                for item in result["risk_indicators"]
            )
        )

    @patch("modules.web.cors._inspect_request")
    def test_wildcard_with_credentials(self, mock_inspect):
        mock_inspect.return_value = {
            "status": "completed",
            "headers": [
                {
                    "header": "Access-Control-Allow-Origin",
                    "present": True,
                    "value": "*"
                },
                {
                    "header": "Access-Control-Allow-Credentials",
                    "present": True,
                    "value": "true"
                }
            ]
        }

        result = inspect_cors("https://example.com/", "12345678")

        indicators = [
            item["indicator"]
            for item in result["risk_indicators"]
        ]

        self.assertIn("wildcard_origin", indicators)
        self.assertIn("wildcard_with_credentials", indicators)

    @patch("modules.web.cors._inspect_request")
    def test_origin_reflection_detection(self, mock_inspect):

        def reflected_response(target, method, origin):
            return {
                "status": "completed",
                "headers": [
                    {
                        "header": "Access-Control-Allow-Origin",
                        "present": True,
                        "value": origin
                    },
                    {
                        "header": "Access-Control-Allow-Credentials",
                        "present": True,
                        "value": "true"
                    }
                ]
            }

        mock_inspect.side_effect = reflected_response

        result = inspect_cors("https://example.com/", "12345678")

        reflection = [
            item for item in result["risk_indicators"]
            if item["indicator"] == "origin_reflection"
        ]

        self.assertEqual(len(reflection), 2)
        self.assertTrue(reflection[0]["credentials_allowed"])

    @patch("modules.web.cors._inspect_request")
    def test_partial_assessment(self, mock_inspect):
        mock_inspect.side_effect = [
            {"status": "completed", "headers": []},
            {"status": "connection_error", "headers": []},
            {"status": "completed", "headers": []},
            {"status": "connection_error", "headers": []}
        ]

        result = inspect_cors("https://example.com/", "12345678")

        self.assertEqual(result["status"], "partial")

    @patch("modules.web.cors._inspect_request")
    def test_complete_assessment(self, mock_inspect):
        mock_inspect.return_value = {
            "status": "completed",
            "headers": []
        }

        result = inspect_cors("https://example.com/", "12345678")

        self.assertEqual(result["status"], "completed")


if __name__ == "__main__":
    unittest.main()
