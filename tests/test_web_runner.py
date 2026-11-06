import unittest
from datetime import datetime
from unittest.mock import patch

import modules.web as web_module
from core.assessment import Assessment
from modules.recon.target import Target


class TestWebRunner(unittest.TestCase):

    def setUp(self):
        self.target = Target("example.com")
        self.assessment = Assessment(
            assessment_id="ZYN-00000001",
            target=self.target,
            started_at=datetime.now()
        )

        self.patches = [
            patch.object(
                web_module,
                "analyze_security_headers",
                return_value={
                    "status": "completed",
                    "findings": [],
                    "header_analysis": [],
                    "cookies": [],
                    "https": {},
                    "server_disclosures": []
                }
            ),
            patch.object(
                web_module,
                "check_resource_access",
                return_value={"status": "completed"}
            ),
            patch.object(
                web_module,
                "inspect_cors",
                return_value={"status": "completed"}
            )
        ]

        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_completed_web_assessment_returns_status(self):
        result = web_module.run(self.target, self.assessment)

        self.assertEqual(result, "completed")
        self.assertEqual(self.assessment.status, "running")
        self.assertIsNone(self.assessment.finished_at)

        categories = {
            observation.category
            for observation in self.assessment.observations
        }
        self.assertIn("security_headers", categories)
        self.assertIn("access_control", categories)
        self.assertIn("input_validation", categories)
        self.assertIn("cors_assessment", categories)

    def test_failed_check_returns_partial_when_others_succeed(self):
        with patch.object(
            web_module,
            "check_resource_access",
            side_effect=OSError("Connection failed")
        ):
            result = web_module.run(self.target, self.assessment)

        self.assertEqual(result, "partial")
        self.assertEqual(self.assessment.status, "running")
        self.assertIsNone(self.assessment.finished_at)


if __name__ == "__main__":
    unittest.main()
