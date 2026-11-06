import unittest
from unittest.mock import patch, mock_open

from modules.recon.subdomains import (
    load_wordlist,
    is_valid_candidate,
    check_subdomain
)


class TestSubdomainDiscovery(unittest.TestCase):

    def test_load_wordlist(self):
        content = "www\nmail\napi\n\n"
        with patch("builtins.open", mock_open(read_data=content)):
            self.assertEqual(
                load_wordlist("wordlist.txt"),
                ["www", "mail", "api"]
            )

    def test_valid_candidate(self):
        self.assertTrue(is_valid_candidate("api"))
        self.assertTrue(is_valid_candidate("api123"))
        self.assertFalse(is_valid_candidate("api.example.com"))
        self.assertFalse(is_valid_candidate("api_test"))

    @patch("modules.recon.subdomains.resolver.resolve")
    def test_existing_subdomain(self, mock_resolve):
        mock_resolve.return_value = [object()]

        self.assertEqual(
            check_subdomain("www.example.com"),
            "www.example.com"
        )

    @patch(
        "modules.recon.subdomains.resolver.resolve",
        side_effect=__import__("dns.resolver", fromlist=["NXDOMAIN"]).NXDOMAIN()
    )
    def test_nonexistent_subdomain(self, mock_resolve):
        self.assertIsNone(check_subdomain("missing.example.com"))


if __name__ == "__main__":
    unittest.main()
