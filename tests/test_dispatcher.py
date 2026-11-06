import unittest
from unittest.mock import Mock, patch

from core.dispatcher import dispatch_command


class TestDispatcher(unittest.TestCase):

    @patch("core.dispatcher.run_assessment")
    @patch("core.dispatcher.import_module")
    def test_recon_passes_ports_to_lifecycle(
        self, mock_import, mock_lifecycle
    ):
        module = Mock()
        mock_import.return_value = module

        dispatch_command("recon", "example.com", ports=[80, 443])

        mock_import.assert_called_once()
        mock_lifecycle.assert_called_once_with(
            "recon", module, "example.com", ports=[80, 443]
        )

    @patch("core.dispatcher.run_assessment")
    @patch("core.dispatcher.import_module")
    def test_enumeration_uses_shared_lifecycle(
        self, mock_import, mock_lifecycle
    ):
        module = Mock()
        mock_import.return_value = module

        dispatch_command("enumeration", "example.com")

        mock_lifecycle.assert_called_once_with(
            "enumeration", module, "example.com", ports=None
        )

    @patch("core.dispatcher.run_assessment")
    @patch("core.dispatcher.import_module")
    def test_web_uses_shared_lifecycle(
        self, mock_import, mock_lifecycle
    ):
        module = Mock()
        mock_import.return_value = module

        dispatch_command("web", "https://example.com")

        mock_lifecycle.assert_called_once_with(
            "web", module, "https://example.com", ports=None
        )

    @patch("core.dispatcher.run_assessment")
    def test_unknown_command_does_not_start_lifecycle(
        self, mock_lifecycle
    ):
        result = dispatch_command("unknown", "example.com")

        self.assertIsNone(result)
        mock_lifecycle.assert_not_called()


if __name__ == "__main__":
    unittest.main()
