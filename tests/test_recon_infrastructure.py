import unittest
from unittest.mock import patch
import socket

from modules.recon.infrastructure import (
    resolve_hostname,
    map_infrastructure
)


class TestInfrastructure(unittest.TestCase):

    @patch("modules.recon.infrastructure.socket.getaddrinfo")
    def test_resolve_hostname(self, mock_resolve):
        mock_resolve.return_value = [
            (socket.AF_INET, None, None, None, ("192.0.2.10", 0)),
            (socket.AF_INET, None, None, None, ("192.0.2.11", 0))
        ]

        self.assertEqual(
            resolve_hostname("example.com"),
            ["192.0.2.10", "192.0.2.11"]
        )

    @patch(
        "modules.recon.infrastructure.socket.getaddrinfo",
        side_effect=socket.gaierror
    )
    def test_resolve_hostname_failure(self, mock_resolve):
        self.assertEqual(resolve_hostname("invalid.example"), [])

    @patch(
        "modules.recon.infrastructure.resolve_hostname",
        side_effect=[["192.0.2.10"], []]
    )
    def test_map_infrastructure(self, mock_resolve):
        result = map_infrastructure(
            ["example.com", "missing.example"]
        )

        self.assertEqual(result, {
            "example.com": ["192.0.2.10"],
            "missing.example": []
        })


if __name__ == "__main__":
    unittest.main()
