import unittest
from types import SimpleNamespace

from core.findings import Finding, build_findings


class TestFindingModel(unittest.TestCase):

    def setUp(self):
        self.finding = Finding(
            finding_id="F-001",
            title="Missing security header",
            category="security_headers",
            severity="low",
            confidence="high",
            status="potential",
            evidence={"header": "Referrer-Policy"},
            impact="May expose additional referrer information.",
            remediation="Configure an appropriate Referrer-Policy header."
        )

    def test_finding_stores_all_fields(self):
        self.assertEqual(self.finding.finding_id, "F-001")
        self.assertEqual(self.finding.title, "Missing security header")
        self.assertEqual(self.finding.category, "security_headers")
        self.assertEqual(self.finding.severity, "low")
        self.assertEqual(self.finding.confidence, "high")
        self.assertEqual(self.finding.status, "potential")
        self.assertEqual(
            self.finding.evidence,
            {"header": "Referrer-Policy"}
        )

    def test_related_observations_defaults_to_empty_list(self):
        self.assertEqual(self.finding.related_observations, [])

    def test_related_observations_are_independent(self):
        another = Finding(
            finding_id="F-002",
            title="Test finding",
            category="test",
            severity="informational",
            confidence="low",
            status="potential",
            evidence={},
            impact="No established impact.",
            remediation="Review the configuration."
        )

        self.finding.related_observations.append(0)

        self.assertEqual(self.finding.related_observations, [0])
        self.assertEqual(another.related_observations, [])

    def test_invalid_severity_is_rejected(self):
        with self.assertRaises(ValueError):
            Finding(
                finding_id="F-003",
                title="Invalid severity",
                category="test",
                severity="extreme",
                confidence="high",
                status="potential",
                evidence={},
                impact="Test",
                remediation="Test"
            )

    def test_invalid_confidence_is_rejected(self):
        with self.assertRaises(ValueError):
            Finding(
                finding_id="F-004",
                title="Invalid confidence",
                category="test",
                severity="low",
                confidence="certain",
                status="potential",
                evidence={},
                impact="Test",
                remediation="Test"
            )

    def test_invalid_status_is_rejected(self):
        with self.assertRaises(ValueError):
            Finding(
                finding_id="F-005",
                title="Invalid status",
                category="test",
                severity="low",
                confidence="high",
                status="unverified",
                evidence={},
                impact="Test",
                remediation="Test"
            )


class TestFindingsBuilder(unittest.TestCase):

    def test_classifies_security_header_issue(self):
        assessment = SimpleNamespace(
            observations=[
                SimpleNamespace(
                    category="header_analysis",
                    data={
                        "issues": [{
                            "code": "missing_referrer_policy",
                            "description": "Referrer-Policy is missing.",
                            "severity": "Low",
                            "recommendation": "Configure Referrer-Policy."
                        }]
                    }
                )
            ]
        )

        findings = build_findings(assessment)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "F-001")
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].confidence, "high")
        self.assertEqual(findings[0].status, "potential")
        self.assertEqual(findings[0].related_observations, [0])
        self.assertEqual(
            findings[0].evidence["issue"],
            {
                "code": "missing_referrer_policy",
                "description": "Referrer-Policy is missing.",
                "severity": "Low",
                "recommendation": "Configure Referrer-Policy."
            }
        )
        self.assertEqual(
            findings[0].impact,
            "The observed header configuration may weaken "
            "browser-side security or privacy protections."
        )
        self.assertEqual(
            findings[0].remediation,
            "Configure Referrer-Policy."
        )

    def test_classifies_cookie_issue(self):
        assessment = SimpleNamespace(
            observations=[
                SimpleNamespace(
                    category="cookie_analysis",
                    data=[{
                        "name": "session",
                        "secure": False,
                        "httponly": True,
                        "samesite": "None",
                        "issues": [{
                            "code": "samesite_none_without_secure",
                            "description": "SameSite=None requires Secure."
                        }]
                    }]
                )
            ]
        )

        findings = build_findings(assessment)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "cookie_security")
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].confidence, "high")
        self.assertEqual(findings[0].status, "potential")
        self.assertEqual(
            findings[0].evidence["cookie_name"],
            "session"
        )
        self.assertEqual(
            findings[0].evidence["cookie_attributes"],
            {
                "secure": False,
                "httponly": True,
                "samesite": "None"
            }
        )
        self.assertEqual(
            findings[0].evidence["issue"]["code"],
            "samesite_none_without_secure"
        )
        self.assertTrue(findings[0].impact.strip())
        self.assertTrue(findings[0].remediation.strip())
        self.assertEqual(
            findings[0].remediation,
            "Add the Secure attribute when using SameSite=None."
        )

    def test_classifies_server_disclosure(self):
        assessment = SimpleNamespace(
            observations=[
                SimpleNamespace(
                    category="server_disclosure",
                    data=[{
                        "header": "Server",
                        "value": "Apache",
                        "severity": "Low",
                        "description": "Server software disclosed.",
                        "recommendation": "Reduce version disclosure."
                    }]
                )
            ]
        )

        findings = build_findings(assessment)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].confidence, "high")
        self.assertEqual(findings[0].status, "potential")
        self.assertEqual(findings[0].category, "server_disclosure")
        self.assertEqual(
            findings[0].evidence["header"],
            "Server"
        )
        self.assertEqual(
            findings[0].evidence["value"],
            "Apache"
        )
        self.assertIn(
            "does not prove",
            findings[0].impact
        )
        self.assertEqual(
            findings[0].remediation,
            "Reduce version disclosure."
        )


    def test_all_server_disclosures_preserve_evidence_and_remediation(self):
        cases = [
            {
                "header": "Server",
                "value": "Apache",
                "severity": "Low",
                "description": "The server response reveals server software information.",
                "recommendation": "Consider minimizing or removing detailed Server header information."
            },
            {
                "header": "X-Powered-By",
                "value": "PHP",
                "severity": "Low",
                "description": "The response reveals the technology powering the application.",
                "recommendation": "Remove unnecessary technology-identifying response headers."
            },
            {
                "header": "X-AspNet-Version",
                "value": "4.0.30319",
                "severity": "Low",
                "description": "The response reveals the ASP.NET version.",
                "recommendation": "Suppress unnecessary framework version information."
            },
            {
                "header": "X-Generator",
                "value": "Example CMS",
                "severity": "Informational",
                "description": "The response reveals the software used to generate the content.",
                "recommendation": "Remove unnecessary generator information from response headers."
            }
        ]

        assessment = SimpleNamespace(
            observations=[
                SimpleNamespace(
                    category="server_disclosure",
                    data=cases
                )
            ]
        )

        findings = build_findings(assessment)

        self.assertEqual(len(findings), 4)

        for finding, case in zip(findings, cases):
            with self.subTest(header=case["header"]):
                self.assertEqual(finding.severity, case["severity"].lower())
                self.assertEqual(finding.confidence, "high")
                self.assertEqual(finding.status, "potential")
                self.assertEqual(
                    finding.evidence,
                    {
                        "observation_category": "server_disclosure",
                        "header": case["header"],
                        "value": case["value"]
                    }
                )
                self.assertEqual(finding.title, case["description"])
                self.assertEqual(finding.remediation, case["recommendation"])
                self.assertIn("does not prove", finding.impact)

    def test_finding_ids_are_sequential(self):
        assessment = SimpleNamespace(
            observations=[
                SimpleNamespace(
                    category="header_analysis",
                    data={
                        "issues": [
                            {
                                "description": "Issue one",
                                "severity": "Low",
                                "recommendation": "Fix one"
                            },
                            {
                                "description": "Issue two",
                                "severity": "Medium",
                                "recommendation": "Fix two"
                            }
                        ]
                    }
                )
            ]
        )

        findings = build_findings(assessment)

        self.assertEqual(
            [finding.finding_id for finding in findings],
            ["F-001", "F-002"]
        )

    def test_unrelated_observations_are_not_findings(self):
        assessment = SimpleNamespace(
            observations=[
                SimpleNamespace(
                    category="dns",
                    data={"records": ["192.0.2.1"]}
                ),
                SimpleNamespace(
                    category="potential_secret",
                    data={
                        "finding": {
                            "name": "API_KEY",
                            "value": "DO_NOT_EXPOSE"
                        }
                    }
                )
            ]
        )

        findings = build_findings(assessment)

        self.assertEqual(findings, [])


    def test_all_cookie_issues_have_specific_remediation(self):
        cases = {
            "missing_secure": (
                "Set the Secure attribute so the cookie is sent only over HTTPS."
            ),
            "missing_httponly": (
                "Set HttpOnly unless client-side JavaScript access is explicitly required."
            ),
            "samesite_none_without_secure": (
                "Add the Secure attribute when using SameSite=None."
            ),
            "secure_prefix_violation": (
                "Add the Secure attribute to satisfy the __Secure- cookie prefix."
            ),
            "host_prefix_missing_secure": (
                "Add the Secure attribute to satisfy the __Host- cookie prefix."
            ),
            "host_prefix_has_domain": (
                "Remove the Domain attribute from the __Host- cookie."
            ),
            "host_prefix_invalid_path": (
                "Set the Path attribute to / for the __Host- cookie."
            ),
        }

        observations = [
            SimpleNamespace(
                category="cookie_analysis",
                data=[{
                    "name": "test_cookie",
                    "secure": False,
                    "httponly": False,
                    "samesite": None,
                    "issues": [{
                        "code": code,
                        "description": f"Test issue: {code}"
                    }]
                }]
            )
            for code in cases
        ]

        findings = build_findings(
            SimpleNamespace(observations=observations)
        )

        self.assertEqual(len(findings), len(cases))

        for finding, (code, expected) in zip(findings, cases.items()):
            with self.subTest(issue=code):
                self.assertEqual(finding.remediation, expected)

    def test_unknown_cookie_issue_is_ignored(self):
        assessment = SimpleNamespace(
            observations=[
                SimpleNamespace(
                    category="cookie_analysis",
                    data=[{
                        "name": "session",
                        "issues": [{
                            "code": "unknown_issue",
                            "description": "Unknown issue."
                        }]
                    }]
                )
            ]
        )

        self.assertEqual(build_findings(assessment), [])


if __name__ == "__main__":
    unittest.main()
