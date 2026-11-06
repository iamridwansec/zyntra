import unittest

from modules.recon.network import parse_ports, discover_ports
from unittest.mock import patch

class TestPortParsing(unittest.TestCase):

    def test_comma_separated_ports(self):
        self.assertEqual(
            parse_ports("22,80,443"),
            [22, 80, 443]
        )

    def test_port_range(self):
        self.assertEqual(
            parse_ports("80-83"),
            [80, 81, 82, 83]
        )


    def test_mixed_ports_and_ranges(self):
        self.assertEqual(
            parse_ports("22,80-82,443"),
            [22, 80, 81, 82, 443]
        )

    def test_duplicate_ports_are_removed(self):
        self.assertEqual(
            parse_ports("22,80,22,443,80"),
            [22, 80, 443]
        )

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("22,invalid,80")

    def test_out_of_range_ports_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("0,80")

        with self.assertRaises(ValueError):
            parse_ports("65536")

    def test_reversed_range_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("100-50")

    def test_empty_selection_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("")

    def test_full_range_requires_confirmation(self):
        with self.assertRaises(ValueError):
            parse_ports("1-65535")

    def test_full_range_with_confirmation(self):
        ports = parse_ports(
            "1-65535",
            confirm_full_scan=True
        )

        self.assertEqual(len(ports), 65535)
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 65535)

    def test_no_ports_returns_skipped_status(self):
        result = discover_ports("127.0.0.1")

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["results"], [])

    @patch("modules.recon.network.check_port", return_value="open")
    def test_selected_ports_return_structured_results(self, mock_check):
        result = discover_ports("127.0.0.1", [80, 443])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["status"], "open")
        self.assertEqual(mock_check.call_count, 2)


if __name__ == "__main__":
    unittest.main()
