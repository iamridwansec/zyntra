import unittest
import socket
from unittest.mock import patch

from modules.recon.ips import resolve_ips


class TestIPResolution(unittest.TestCase):

    @patch("modules.recon.ips.socket.getaddrinfo")
    def test_resolve_ipv4_and_ipv6(self, mock_resolve):
        mock_resolve.return_value = [
            (socket.AF_INET, None, None, None, ("192.0.2.10", 0)),
            (socket.AF_INET6, None, None, None, ("2001:db8::1", 0, 0, 0)),
            (socket.AF_INET, None, None, None, ("192.0.2.10", 0))
        ]

        result = resolve_ips("example.com")

        self.assertEqual(result["ipv4"], ["192.0.2.10"])
        self.assertEqual(result["ipv6"], ["2001:db8::1"])

    @patch("modules.recon.ips.socket.getaddrinfo", return_value=[])
    def test_no_addresses_found(self, mock_resolve):
        result = resolve_ips("example.com")

        self.assertEqual(result, {
            "ipv4": [],
            "ipv6": []
        })

    @patch(
        "modules.recon.ips.socket.getaddrinfo",
        side_effect=socket.gaierror
    )
    def test_dns_resolution_failure(self, mock_resolve):
        result = resolve_ips("invalid.example")

        self.assertEqual(result, {
            "ipv4": [],
            "ipv6": []
        })

if __name__ == "__main__":
    unittest.main()
