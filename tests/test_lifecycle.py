import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core.lifecycle import run_assessment


class TestAssessmentLifecycle(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

        self.output_patcher = patch(
            "core.lifecycle.ASSESSMENTS_DIR",
            self.output_dir
        )
        self.output_patcher.start()

    def tearDown(self):
        self.output_patcher.stop()
        self.temp_dir.cleanup()

    @patch("core.lifecycle.generate_html_report")
    @patch("core.lifecycle.save_assessment")
    @patch("core.lifecycle.generate_assessment_id", return_value="ZYN-00000099")
    def test_completed_assessment(self, mock_id, mock_save, mock_html):
        module = SimpleNamespace(run=Mock(return_value="completed"))

        assessment = run_assessment("enumeration", module, "example.com")

        module.run.assert_called_once()
        self.assertEqual(assessment.status, "completed")
        self.assertIsNotNone(assessment.finished_at)
        mock_save.assert_called_once()
        mock_html.assert_called_once()

        self.assertEqual(
            mock_save.call_args.args[1],
            self.output_dir / "ZYN-00000099" / "results.json"
        )
        self.assertEqual(
            mock_html.call_args.args[1],
            self.output_dir / "ZYN-00000099" / "report.html"
        )

    @patch("core.lifecycle.generate_html_report")
    @patch("core.lifecycle.save_assessment")
    @patch("core.lifecycle.generate_assessment_id", return_value="ZYN-00000100")
    def test_partial_module_result(self, mock_id, mock_save, mock_html):
        module = SimpleNamespace(run=Mock(return_value="partial"))

        assessment = run_assessment("web", module, "example.com")

        self.assertEqual(assessment.status, "partial")
        self.assertIsNotNone(assessment.finished_at)
        mock_save.assert_called_once()
        mock_html.assert_called_once()

    @patch("core.lifecycle.generate_html_report")
    @patch("core.lifecycle.save_assessment")
    @patch("core.lifecycle.generate_assessment_id", return_value="ZYN-00000101")
    def test_failure_without_observations(self, mock_id, mock_save, mock_html):
        module = SimpleNamespace(
            run=Mock(side_effect=RuntimeError("Module crashed"))
        )

        assessment = run_assessment("web", module, "example.com")

        self.assertEqual(assessment.status, "failed")
        self.assertIsNotNone(assessment.finished_at)
        self.assertTrue(
            any(
                observation.category == "module_execution_error"
                for observation in assessment.observations
            )
        )
        mock_save.assert_called_once()
        mock_html.assert_called_once()

    @patch("core.lifecycle.generate_html_report")
    @patch("core.lifecycle.save_assessment")
    @patch("core.lifecycle.generate_assessment_id", return_value="ZYN-00000102")
    def test_failure_after_collecting_observation(
        self, mock_id, mock_save, mock_html
    ):
        from datetime import datetime
        from core.observation import Observation

        def collect_then_crash(target, assessment):
            assessment.add_observation(
                Observation(
                    category="test_evidence",
                    source="test_module",
                    data={"result": "collected"},
                    timestamp=datetime.now()
                )
            )
            raise RuntimeError("Module crashed after collection")

        module = SimpleNamespace(run=Mock(side_effect=collect_then_crash))

        assessment = run_assessment("web", module, "example.com")

        self.assertEqual(assessment.status, "partial")
        self.assertIsNotNone(assessment.finished_at)
        self.assertEqual(len(assessment.observations), 2)
        mock_save.assert_called_once()
        mock_html.assert_called_once()

    @patch(
        "core.lifecycle.generate_assessment_id",
        return_value="ZYN-00000103"
    )
    def test_real_exports_create_both_files(self, mock_id):
        module = SimpleNamespace(run=Mock(return_value="completed"))

        assessment = run_assessment("enumeration", module, "example.com")

        assessment_dir = self.output_dir / "ZYN-00000103"
        results_path = assessment_dir / "results.json"
        report_path = assessment_dir / "report.html"

        self.assertTrue(results_path.is_file())
        self.assertTrue(report_path.is_file())

        with results_path.open(encoding="utf-8") as file:
            results = json.load(file)

        self.assertEqual(results["assessment_id"], "ZYN-00000103")
        self.assertEqual(results["status"], "completed")
        self.assertIn("findings", results)

        html = report_path.read_text(encoding="utf-8")
        self.assertTrue(html.strip())
        self.assertIn("example.com", html)


if __name__ == "__main__":
    unittest.main()
