import unittest
from unittest.mock import patch

import zyntra


class TestCLI(unittest.TestCase):

    @patch("sys.argv", ["zyntra", "-r", "-e", "-t", "example.com"])
    def test_multiple_modules_are_rejected(self):
        with self.assertRaises(SystemExit) as error:
            zyntra.main()

        self.assertEqual(error.exception.code, 2)

    @patch("sys.argv", ["zyntra", "-r"])
    def test_target_is_required(self):
        with self.assertRaises(SystemExit) as error:
            zyntra.main()

        self.assertEqual(error.exception.code, 2)

    @patch("sys.argv", ["zyntra"])
    @patch("builtins.print")
    def test_no_module_selected(self, mock_print):
        zyntra.main()

        mock_print.assert_any_call("[*] No module selected.")

    @patch(
        "sys.argv",
        ["zyntra", "--export", "ZYN-00000066", "--destination", "/tmp/exports"]
    )
    @patch("zyntra.export_assessment")
    @patch("builtins.print")
    def test_export_dispatches_selected_assessment(
        self, mock_print, mock_export
    ):
        mock_export.return_value = {
            "status": "exported",
            "path": "/tmp/exports/ZYN-00000066/results.json",
            "sha256": "abc123"
        }

        zyntra.main()

        mock_export.assert_called_once_with(
            "ZYN-00000066",
            "/tmp/exports"
        )

    @patch(
        "sys.argv",
        ["zyntra", "--export", "ZYN-00000066"]
    )
    def test_export_requires_destination(self):
        with self.assertRaises(SystemExit) as error:
            zyntra.main()

        self.assertEqual(error.exception.code, 2)

    @patch(
        "sys.argv",
        ["zyntra", "--export", "ZYN-00000066", "--destination", "/tmp/exports", "-t", "example.com"]
    )
    def test_export_rejects_assessment_options(self):
        with self.assertRaises(SystemExit) as error:
            zyntra.main()

        self.assertEqual(error.exception.code, 2)

    @patch("sys.argv", ["zyntra", "-r", "-t", "example.com"])
    @patch("zyntra.dispatch_command")
    def test_recon_dispatches_without_ports(self, mock_dispatch):
        zyntra.main()

        mock_dispatch.assert_called_once_with(
            "recon",
            "example.com",
            ports=None
        )

    @patch("sys.argv", ["zyntra", "-r", "-t", "example.com", "--ports", "80,443"])
    @patch("zyntra.dispatch_command")
    def test_recon_dispatches_selected_ports(self, mock_dispatch):
        zyntra.main()

        mock_dispatch.assert_called_once_with(
            "recon",
            "example.com",
            ports=[80, 443]
        )


if __name__ == "__main__":
    unittest.main()
