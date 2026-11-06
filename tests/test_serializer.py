import json
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from core.serializer import save_assessment


class TestAssessmentSerializer(unittest.TestCase):

    def test_json_preserves_original_secret_evidence(self):
        secret = "PRIVATE_API_KEY_123"
        timestamp = datetime(2026, 11, 4, 10, 0, 0)

        assessment = SimpleNamespace(
            assessment_id="ZYN-00000001",
            target=SimpleNamespace(
                value="example.com",
                target_type="domain",
                hostname="example.com"
            ),
            started_at=timestamp,
            finished_at=timestamp,
            status="completed",
            observations=[
                SimpleNamespace(
                    category="potential_secret",
                    source="javascript",
                    data={
                        "finding": {
                            "type": "api_key",
                            "name": "API_KEY",
                            "value": secret
                        }
                    },
                    timestamp=timestamp
                )
            ]
        )

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "results.json"

            save_assessment(assessment, output_path)

            exported_data = json.loads(
                output_path.read_text(encoding="utf-8")
            )

        exported_finding = exported_data["observations"][0]["data"]["finding"]

        self.assertEqual(exported_finding["value"], secret)
        self.assertEqual(exported_finding["name"], "API_KEY")


    def test_json_includes_derived_findings_and_original_observations(self):
        timestamp = datetime(2026, 11, 4, 10, 0, 0)
        issue = {
            "code": "missing_content_type_options",
            "severity": "medium",
            "description": "The X-Content-Type-Options header is missing.",
            "recommendation": "Set X-Content-Type-Options to nosniff."
        }

        assessment = SimpleNamespace(
            assessment_id="ZYN-00000002",
            target=SimpleNamespace(
                value="example.com",
                target_type="domain",
                hostname="example.com"
            ),
            started_at=timestamp,
            finished_at=timestamp,
            status="completed",
            observations=[
                SimpleNamespace(
                    category="header_analysis",
                    source="web",
                    data={"issues": [issue]},
                    timestamp=timestamp
                )
            ]
        )

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "results.json"
            save_assessment(assessment, output_path)
            exported_data = json.loads(
                output_path.read_text(encoding="utf-8")
            )

        self.assertEqual(len(exported_data["observations"]), 1)
        self.assertEqual(
            exported_data["observations"][0]["data"]["issues"][0],
            issue
        )
        self.assertEqual(len(exported_data["findings"]), 1)
        self.assertEqual(
            exported_data["findings"][0]["category"],
            "security_headers"
        )
        self.assertEqual(
            exported_data["findings"][0]["severity"],
            "medium"
        )
        self.assertEqual(
            exported_data["findings"][0]["status"],
            "potential"
        )
        self.assertEqual(
            exported_data["findings"][0]["evidence"]["issue"],
            issue
        )



    def test_json_serializes_mixed_observation_data(self):
        timestamp = datetime(2026, 11, 4, 10, 0, 0)

        tls_data = {
            "status": "valid",
            "verified": True,
            "subject": (("commonName", "example.com"),),
            "issuer": (("organizationName", "Example CA"),),
            "alternative_names": ["example.com", "www.example.com"],
            "error": None
        }

        assessment = SimpleNamespace(
            assessment_id="ZYN-00000003",
            target=SimpleNamespace(
                value="example.com",
                target_type="domain",
                hostname="example.com"
            ),
            started_at=timestamp,
            finished_at=timestamp,
            status="completed",
            observations=[
                SimpleNamespace(
                    category="tls_analysis",
                    source="web",
                    data=tls_data,
                    timestamp=timestamp
                ),
                SimpleNamespace(
                    category="web_crawl",
                    source="enumeration",
                    data={
                        "pages": [
                            {
                                "url": "https://example.com",
                                "status": 200,
                                "html": "<html></html>"
                            }
                        ],
                        "error": None
                    },
                    timestamp=timestamp
                )
            ]
        )

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "results.json"
            save_assessment(assessment, output_path)
            exported_data = json.loads(
                output_path.read_text(encoding="utf-8")
            )

        exported_tls = exported_data["observations"][0]["data"]

        self.assertIs(exported_tls["verified"], True)
        self.assertIsNone(exported_tls["error"])
        self.assertEqual(
            exported_tls["subject"],
            [["commonName", "example.com"]]
        )
        self.assertEqual(
            exported_tls["alternative_names"],
            ["example.com", "www.example.com"]
        )
        self.assertEqual(
            exported_data["observations"][1]["data"]["pages"][0]["status"],
            200
        )

if __name__ == "__main__":
    unittest.main()
