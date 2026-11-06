import unittest
from unittest.mock import patch

from modules.recon.dns import (
    resolve_ipv4,
    resolve_ipv6,
    resolve_reverse,
    resolve_mx,
    resolve_ns,
    collect_dns
)


class TestDNSResolution(unittest.TestCase):

    @patch("modules.recon.dns.socket.gethostbyname", return_value="93.184.216.34")
    def test_resolve_ipv4(self, mock_resolve):
        self.assertEqual(
            resolve_ipv4("example.com"),
            "93.184.216.34"
        )

    @patch("modules.recon.dns.socket.gethostbyname", side_effect=__import__("socket").gaierror)
    def test_resolve_ipv4_failure(self, mock_resolve):
        self.assertEqual(resolve_ipv4("invalid.example"), "")

    @patch("modules.recon.dns.socket.getaddrinfo")
    def test_resolve_ipv6(self, mock_resolve):
        mock_resolve.return_value = [
            (None, None, None, None, ("2001:db8::1", 0, 0, 0)),
            (None, None, None, None, ("2001:db8::2", 0, 0, 0))
        ]

        self.assertEqual(
            resolve_ipv6("example.com"),
            ["2001:db8::1", "2001:db8::2"]
        )

    @patch("modules.recon.dns.socket.gethostbyaddr")
    def test_resolve_reverse(self, mock_resolve):
        mock_resolve.return_value = (
            "example.com",
            ["alias.example.com"],
            ["93.184.216.34"]
        )

        self.assertEqual(
            resolve_reverse("93.184.216.34"),
            {
                "hostname": "example.com",
                "aliases": ["alias.example.com"],
                "addresses": ["93.184.216.34"]
            }
        )

    @patch("modules.recon.dns.resolve_ipv4", return_value="")
    @patch("modules.recon.dns.resolve_ipv6", return_value=[])
    @patch("modules.recon.dns.resolve_mx", return_value=[])
    @patch("modules.recon.dns.resolve_ns", return_value=[])
    def test_collect_dns_empty_results(
        self, mock_ns, mock_mx, mock_ipv6, mock_ipv4
    ):
        self.assertEqual(
            collect_dns("invalid.example"),
            {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": []
            }
        )


if __name__ == "__main__":
    unittest.main()
