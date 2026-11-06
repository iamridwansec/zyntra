import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.exporter import calculate_sha256, export_assessment


class TestAssessmentExporter(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.source = self.root / "assessments"
        self.destination = self.root / "exports"

        self.source.mkdir()
        self.destination.mkdir()

        self.assessment_id = "ZYN-00000001"
        self.assessment_dir = self.source / self.assessment_id
        self.assessment_dir.mkdir()

        self.source_file = self.assessment_dir / "results.json"
        self.report_file = self.assessment_dir / "report.html"

        self.source_data = {
            "assessment_id": self.assessment_id,
            "status": "completed"
        }

        self.source_file.write_text(json.dumps(self.source_data))
        self.report_file.write_text(
            "<html><body>Zyntra assessment</body></html>"
        )

        self.paths_patch = patch(
            "core.exporter.ASSESSMENTS_DIR",
            self.source
        )
        self.paths_patch.start()

    def tearDown(self):
        self.paths_patch.stop()
        self.temp.cleanup()

    def test_exports_both_assessment_files(self):
        result = export_assessment(
            self.assessment_id,
            self.destination
        )

        exported_dir = self.destination / self.assessment_id
        exported_results = exported_dir / "results.json"
        exported_report = exported_dir / "report.html"

        self.assertEqual(result["status"], "exported")
        self.assertTrue(exported_results.is_file())
        self.assertTrue(exported_report.is_file())

        self.assertEqual(
            json.loads(exported_results.read_text()),
            self.source_data
        )

        self.assertEqual(
            exported_report.read_text(),
            self.report_file.read_text()
        )

        self.assertEqual(result["path"], exported_results)
        self.assertEqual(result["report_path"], exported_report)

    def test_both_exports_have_verified_hashes(self):
        result = export_assessment(
            self.assessment_id,
            self.destination
        )

        self.assertEqual(
            result["sha256"],
            calculate_sha256(
                self.destination / self.assessment_id / "results.json"
            )
        )

        self.assertEqual(
            result["report_sha256"],
            calculate_sha256(
                self.destination / self.assessment_id / "report.html"
            )
        )

    def test_invalid_assessment_id_is_rejected(self):
        with self.assertRaises(ValueError):
            export_assessment("../invalid", self.destination)

    def test_missing_assessment_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            export_assessment("ZYN-00000099", self.destination)

    def test_missing_report_is_rejected_without_partial_export(self):
        self.report_file.unlink()

        with self.assertRaises(FileNotFoundError):
            export_assessment(self.assessment_id, self.destination)

        self.assertFalse(
            (self.destination / self.assessment_id).exists()
        )

    def test_existing_export_is_skipped(self):
        existing_dir = self.destination / self.assessment_id
        existing_dir.mkdir()

        result = export_assessment(
            self.assessment_id,
            self.destination
        )

        self.assertEqual(result["status"], "skipped")

    def test_invalid_json_is_rejected(self):
        self.source_file.write_text("{invalid json")

        with self.assertRaises(ValueError):
            export_assessment(self.assessment_id, self.destination)

        self.assertFalse(
            (self.destination / self.assessment_id).exists()
        )

    def test_mismatched_assessment_id_is_rejected(self):
        self.source_file.write_text(json.dumps({
            "assessment_id": "ZYN-00000099",
            "status": "completed"
        }))

        with self.assertRaises(ValueError):
            export_assessment(self.assessment_id, self.destination)

        self.assertFalse(
            (self.destination / self.assessment_id).exists()
        )

    def test_original_assessment_files_remain_unchanged(self):
        original_results = self.source_file.read_bytes()
        original_report = self.report_file.read_bytes()

        export_assessment(
            self.assessment_id,
            self.destination
        )

        self.assertEqual(self.source_file.read_bytes(), original_results)
        self.assertEqual(self.report_file.read_bytes(), original_report)


if __name__ == "__main__":
    unittest.main()
