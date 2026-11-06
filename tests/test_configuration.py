import unittest
from email.message import Message
from modules.web.configuration import (
    analyze_cookies,
    analyze_server_disclosure,
    analyze_https_behavior,
    analyze_tls_certificate
)
from modules.web.configuration import (
    analyze_cookies,
    analyze_server_disclosure,
    analyze_https_behavior
)
from modules.web.configuration import (
    analyze_security_headers_config,
    analyze_security_headers
)
from unittest import mock


class TestCookieAnalysis(unittest.TestCase):

    def test_cookie_security_attributes(self):
        headers = Message()

        headers.add_header(
            "Set-Cookie",
            "session=abc123; Secure; HttpOnly; SameSite=Strict"
        )

        result = analyze_cookies(headers)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "session")
        self.assertTrue(result[0]["secure"])
        self.assertTrue(result[0]["httponly"])
        self.assertEqual(result[0]["samesite"], "Strict")

    def test_missing_cookie_attributes(self):
        headers = Message()

        headers.add_header(
            "Set-Cookie",
            "session=abc123"
        )

        result = analyze_cookies(headers)

        self.assertFalse(result[0]["secure"])
        self.assertFalse(result[0]["httponly"])
        self.assertIsNone(result[0]["samesite"])

    def test_samesite_none_without_secure(self):
        headers = Message()
        headers.add_header(
            "Set-Cookie",
            "session=abc123; SameSite=None"
        )

        result = analyze_cookies(headers)

        issue_codes = [
            issue["code"] for issue in result[0]["issues"]
        ]

        self.assertIn("samesite_none_without_secure", issue_codes)

    def test_secure_cookie_prefix_requires_secure(self):
        headers = Message()
        headers.add_header(
            "Set-Cookie",
            "__Secure-session=abc123; HttpOnly"
        )

        result = analyze_cookies(headers)

        issue_codes = [
            issue["code"] for issue in result[0]["issues"]
        ]

        self.assertIn("secure_prefix_violation", issue_codes)

    def test_host_cookie_prefix_requirements(self):
        headers = Message()
        headers.add_header(
            "Set-Cookie",
            "__Host-session=abc123; HttpOnly; Domain=example.com; Path=/login"
        )

        result = analyze_cookies(headers)

        issue_codes = [
            issue["code"] for issue in result[0]["issues"]
        ]

        self.assertIn("host_prefix_missing_secure", issue_codes)
        self.assertIn("host_prefix_has_domain", issue_codes)
        self.assertIn("host_prefix_invalid_path", issue_codes)



    def test_missing_secure_attribute(self):
        headers = Message()
        headers.add_header("Set-Cookie", "session=abc123; HttpOnly")

        result = analyze_cookies(headers)

        issue_codes = [
            issue["code"] for issue in result[0]["issues"]
        ]

        self.assertIn("missing_secure", issue_codes)

    def test_missing_httponly_attribute(self):
        headers = Message()
        headers.add_header("Set-Cookie", "session=abc123; Secure")

        result = analyze_cookies(headers)

        issue_codes = [
            issue["code"] for issue in result[0]["issues"]
        ]

        self.assertIn("missing_httponly", issue_codes)



class TestSecurityHeaderAnalysis(unittest.TestCase):

    def test_weak_content_security_policy(self):
        headers = Message()
        headers["Content-Security-Policy"] = (
            "default-src * 'unsafe-inline'"
        )

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertIn("csp_wildcard_source", issue_codes)
        self.assertIn("csp_unsafe_inline", issue_codes)

    def test_zero_hsts_max_age(self):
        headers = Message()
        headers["Strict-Transport-Security"] = "max-age=0"

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertIn("hsts_zero_max_age", issue_codes)

    def test_hsts_with_include_subdomains(self):
        headers = Message()
        headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertNotIn(
            "hsts_missing_include_subdomains",
            issue_codes
        )

    def test_hsts_missing_include_subdomains(self):
        headers = Message()
        headers["Strict-Transport-Security"] = "max-age=31536000"

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertIn(
            "hsts_missing_include_subdomains",
            issue_codes
        )

    def test_hsts_negative_max_age(self):
        headers = Message()
        headers["Strict-Transport-Security"] = "max-age=-1"

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertIn("hsts_invalid_max_age", issue_codes)


    def test_invalid_frame_options(self):
        headers = Message()
        headers["X-Frame-Options"] = "INVALID"

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertIn("invalid_x_frame_options", issue_codes)

    def test_missing_security_headers(self):
        headers = Message()

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertIn("missing_x_content_type_options", issue_codes)
        self.assertIn("missing_referrer_policy", issue_codes)
        self.assertIn("missing_permissions_policy", issue_codes)


    def test_csp_wildcard_source(self):
        headers = Message()
        headers["Content-Security-Policy"] = "default-src *"

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertIn("csp_wildcard_source", issue_codes)

    def test_csp_asterisk_not_source(self):
        headers = Message()
        headers["Content-Security-Policy"] = (
            "default-src 'self'; report-uri /reports/*"
        )

        result = analyze_security_headers_config(headers)

        issue_codes = [issue["code"] for issue in result["issues"]]

        self.assertNotIn("csp_wildcard_source", issue_codes)



if __name__ == "__main__":
    unittest.main()
class TestServerDisclosure(unittest.TestCase):

    def test_detect_server_disclosure(self):
        headers = Message()
        headers["Server"] = "Apache/2.4.58"
        headers["X-Powered-By"] = "PHP/8.2"

        result = analyze_server_disclosure(headers)

        self.assertEqual(len(result), 2)

        disclosed_headers = [
            item["header"] for item in result
        ]

        self.assertIn("Server", disclosed_headers)
        self.assertIn("X-Powered-By", disclosed_headers)

        for item in result:
            self.assertIn("severity", item)
            self.assertIn("description", item)
            self.assertIn("recommendation", item)

    def test_no_server_disclosure(self):
        headers = Message()

        result = analyze_server_disclosure(headers)

        self.assertEqual(result, [])

class TestHTTPSBehavior(unittest.TestCase):

    def test_http_redirected_to_https(self):
        result = analyze_https_behavior(
            "http://example.com",
            "https://example.com"
        )

        self.assertEqual(result["original_scheme"], "http")
        self.assertEqual(result["final_scheme"], "https")
        self.assertTrue(result["uses_https"])
        self.assertTrue(result["redirected_to_https"])

    def test_https_without_redirect(self):
        result = analyze_https_behavior(
            "https://example.com",
            "https://example.com"
        )

        self.assertTrue(result["uses_https"])
        self.assertFalse(result["redirected_to_https"])

    def test_http_without_https_redirect(self):
        result = analyze_https_behavior(
            "http://example.com",
            "http://example.com"
        )

        self.assertFalse(result["uses_https"])
        self.assertFalse(result["redirected_to_https"])

    def test_http_redirected_to_different_https_url(self):
        result = analyze_https_behavior(
            "http://example.com",
            "https://www.example.com/login"
        )

        self.assertTrue(result["uses_https"])
        self.assertTrue(result["redirected_to_https"])


class TestTLSCertificate(unittest.TestCase):

    def test_valid_certificate(self):
        with mock.patch(
            "modules.web.configuration.ssl.create_default_context"
        ) as mock_context_factory, mock.patch(
            "modules.web.configuration.socket.create_connection"
        ) as mock_connection:

            context = mock_context_factory.return_value

            tls_context = context.wrap_socket.return_value
            tls_connection = tls_context.__enter__.return_value

            tls_connection.getpeercert.return_value = {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("organizationName", "Example CA"),),),
                "notAfter": "Dec 31 23:59:59 2027 GMT"
            }

            result = analyze_tls_certificate("example.com")

            self.assertTrue(result["verified"])
            self.assertEqual(result["status"], "valid")
            self.assertEqual(result["hostname"], "example.com")

    def test_connection_error(self):
        with mock.patch(
            "modules.web.configuration.socket.create_connection",
            side_effect=OSError("Connection refused")
        ):
            result = analyze_tls_certificate("example.com")

            self.assertFalse(result["verified"])
            self.assertEqual(result["status"], "error")

class TestConfigurationIntegration(unittest.TestCase):

    @mock.patch("modules.web.configuration.urllib.request.urlopen")
    @mock.patch("modules.web.configuration.analyze_tls_certificate")
    def test_https_assessment_includes_tls(self, mock_tls, mock_urlopen):
        mock_tls.return_value = {
            "status": "valid",
            "verified": True
        }

        response = mock.MagicMock()
        response.headers = Message()
        response.status = 200
        response.url = "https://example.com"
        mock_urlopen.return_value.__enter__.return_value = response

        result = analyze_security_headers("https://example.com")

        self.assertEqual(result["tls"]["status"], "valid")
        self.assertTrue(result["tls"]["verified"])
        mock_tls.assert_called_once_with("example.com")

    @mock.patch("modules.web.configuration.urllib.request.urlopen")
    def test_http_assessment_skips_tls(self, mock_urlopen):
        response = mock.MagicMock()
        response.headers = Message()
        response.status = 200
        response.url = "http://example.com"
        mock_urlopen.return_value.__enter__.return_value = response

        result = analyze_security_headers("http://example.com")

        self.assertEqual(result["tls"]["status"], "skipped")
        self.assertFalse(result["tls"]["verified"])
