import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from core.reporting import (
    print_assessment_summary,
    generate_html_report
)


class TestAssessmentReporting(unittest.TestCase):

    def setUp(self):
        started = datetime(2026, 11, 3, 10, 0, 0)

        self.assessment = SimpleNamespace(
            assessment_id="ZYN-00000001",
            target=SimpleNamespace(
                value="example.com",
                target_type="domain"
            ),
            started_at=started,
            finished_at=started + timedelta(seconds=12),
            status="completed",
            observations=[
                SimpleNamespace(
                    category="dns",
                    source="recon",
                    data={"records": ["192.0.2.1"]},
                    timestamp=started
                ),
                SimpleNamespace(
                    category="dns",
                    source="recon",
                    data={"records": ["192.0.2.2"]},
                    timestamp=started
                ),
                SimpleNamespace(
                    category="network",
                    source="recon",
                    data={"status": "completed"},
                    timestamp=started
                ),
            ]
        )

    def test_summary_includes_assessment_details(self):
        output = StringIO()

        with redirect_stdout(output):
            print_assessment_summary(self.assessment)

        result = output.getvalue()

        self.assertIn("ZYN-00000001", result)
        self.assertIn("example.com", result)
        self.assertIn("domain", result)
        self.assertIn("completed", result)
        self.assertIn("12", result)

    def test_summary_counts_observation_categories(self):
        output = StringIO()

        with redirect_stdout(output):
            print_assessment_summary(self.assessment)

        result = output.getvalue()

        self.assertIn("Total observations: 3", result)
        self.assertIn("dns: 2", result)
        self.assertIn("network: 1", result)

    def test_summary_handles_empty_observations(self):
        self.assessment.observations = []
        output = StringIO()

        with redirect_stdout(output):
            print_assessment_summary(self.assessment)

        self.assertIn("Total observations: 0", output.getvalue())

    def test_html_report_is_generated(self):
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.html"

            result = generate_html_report(
                self.assessment,
                output_path
            )

            self.assertTrue(output_path.is_file())
            self.assertEqual(result, output_path)

            html = output_path.read_text()

            self.assertIn("ZYN-00000001", html)
            self.assertIn("example.com", html)
            self.assertIn("completed", html)
            self.assertIn("dns", html)
            self.assertIn("network", html)

    def test_html_report_escapes_untrusted_content(self):
        self.assessment.target.value = "<script>alert('xss')</script>"

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.html"

            generate_html_report(
                self.assessment,
                output_path
            )

            html = output_path.read_text()

            self.assertNotIn(
                "<script>alert('xss')</script>",
                html
            )
            self.assertIn("&lt;script&gt;", html)


    def test_html_report_escapes_untrusted_observation_data(self):
        self.assessment.observations[0].data = {
            "response": "<script>alert('xss')</script>"
        }

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.html"

            generate_html_report(
                self.assessment,
                output_path
            )

            html = output_path.read_text()

            self.assertNotIn(
                "<script>alert('xss')</script>",
                html
            )
            self.assertIn("&lt;script&gt;", html)


    def test_html_report_redacts_potential_secret_values(self):
        secret = "PRIVATE_API_KEY_123"

        self.assessment.observations.append(
            SimpleNamespace(
                category="potential_secret",
                source="javascript",
                data={
                    "javascript_url": "https://example.com/app.js",
                    "finding": {
                        "type": "api_key",
                        "name": "API_KEY",
                        "value": secret
                    }
                },
                timestamp=self.assessment.started_at
            )
        )

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.html"

            generate_html_report(self.assessment, output_path)

            report = output_path.read_text()

            self.assertNotIn(secret, report)
            self.assertIn("[REDACTED]", report)
            self.assertIn("API_KEY", report)
            self.assertIn("api_key", report)
            self.assertIn(
                "https://example.com/app.js",
                report
            )
            self.assertIn(
                '&quot;value&quot;: &quot;[REDACTED]&quot;',
                report
            )

        self.assertEqual(
            self.assessment.observations[-1].data["finding"]["value"],
            secret
        )



    def test_html_report_includes_security_findings(self):
        self.assessment.observations.append(
            SimpleNamespace(
                category="header_analysis",
                source="web",
                data={
                    "issues": [{
                        "description": "Content Security Policy is missing",
                        "severity": "medium",
                        "recommendation": "Configure a suitable Content-Security-Policy."
                    }]
                },
                timestamp=self.assessment.started_at
            )
        )

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.html"
            generate_html_report(self.assessment, output_path)
            report = output_path.read_text()

        self.assertIn("Security Findings", report)
        self.assertIn("F-001", report)
        self.assertIn("Content Security Policy is missing", report)
        self.assertIn("medium", report)
        self.assertIn("high", report)
        self.assertIn("potential", report)
        self.assertIn("Configure a suitable Content-Security-Policy.", report)
        self.assertIn("browser-side security", report)
        self.assertIn("header_analysis", report)

    def test_html_report_escapes_untrusted_finding_content(self):
        payload = "<script>alert('finding')</script>"

        self.assessment.observations.append(
            SimpleNamespace(
                category="header_analysis",
                source="web",
                data={
                    "issues": [{
                        "description": payload,
                        "severity": "medium",
                        "recommendation": payload
                    }]
                },
                timestamp=self.assessment.started_at
            )
        )

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.html"
            generate_html_report(self.assessment, output_path)
            report = output_path.read_text()

        self.assertNotIn(payload, report)
        self.assertIn("&lt;script&gt;", report)


if __name__ == "__main__":
    unittest.main()
