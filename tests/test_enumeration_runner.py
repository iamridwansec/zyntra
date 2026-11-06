import unittest
from datetime import datetime
from unittest.mock import patch

from core.assessment import Assessment
from modules.recon.target import Target
from modules.enumeration import run


class TestEnumerationRunner(unittest.TestCase):

    def setUp(self):
        self.target = Target("example.com")
        self.assessment = Assessment(
            assessment_id="ZYN-00000001",
            target=self.target,
            started_at=datetime.now()
        )

    @patch("modules.enumeration.discover_vhosts", return_value={
        "status": "skipped",
        "message": "Virtual host discovery skipped."
    })
    @patch("modules.enumeration.discover_page_javascript", return_value=[])
    @patch("modules.enumeration.crawl_web_surface", return_value=[])
    @patch("modules.enumeration.discover_api", return_value=[])
    def test_collection_uses_shared_assessment(
        self, mock_api, mock_crawl, mock_javascript, mock_vhosts
    ):
        result = run(self.target, self.assessment)

        self.assertEqual(result, "completed")
        self.assertEqual(self.assessment.status, "running")
        self.assertIsNone(self.assessment.finished_at)

        mock_api.assert_called_once_with("https://example.com")
        mock_crawl.assert_called_once_with("https://example.com")

    @patch("modules.enumeration.fetch_javascript", side_effect=OSError("Network error"))
    @patch("modules.enumeration.discover_vhosts", return_value={
        "status": "skipped",
        "message": "Virtual host discovery skipped."
    })
    @patch("modules.enumeration.discover_page_javascript", return_value=[
        "https://example.com/app.js"
    ])
    @patch("modules.enumeration.crawl_web_surface", return_value=[])
    @patch("modules.enumeration.discover_api", return_value=[])
    def test_javascript_fetch_failure_returns_partial(
        self,
        mock_api,
        mock_crawl,
        mock_javascript,
        mock_vhosts,
        mock_fetch
    ):
        result = run(self.target, self.assessment)

        self.assertEqual(result, "partial")
        self.assertEqual(self.assessment.status, "running")
        self.assertIsNone(self.assessment.finished_at)
        mock_fetch.assert_called_once_with(
            "https://example.com/app.js"
        )


if __name__ == "__main__":
    unittest.main()
