import unittest
from datetime import datetime
from unittest.mock import patch

from core.assessment import Assessment
from modules.recon.runner import run
from modules.recon.target import Target


class TestReconRunner(unittest.TestCase):

    @patch("modules.recon.runner.discover_web_surface", return_value={
        "url": "https://example.com",
        "status": 200,
        "content_type": "text/html",
        "content_length": "1024",
        "location": "",
        "allow": "",
        "error": ""
    })
    @patch("modules.recon.runner.discover_ports", return_value={
        "status": "skipped",
        "requested_ports": [],
        "results": [],
        "reason": "No ports selected."
    })
    @patch("modules.recon.runner.resolve_ips", return_value={
        "ipv4": [],
        "ipv6": []
    })
    @patch("modules.recon.runner.map_infrastructure", return_value={})
    @patch("modules.recon.runner.discover_subdomains", return_value=[])
    @patch("modules.recon.runner.identify_technologies", return_value={
        "url": "https://example.com",
        "status": 200,
        "server": "test-server",
        "powered_by": "",
        "error": ""
    })
    @patch("modules.recon.runner.collect_rdap", return_value={
        "status": None,
        "data": {}
    })
    @patch("modules.recon.runner.collect_whois", return_value={
        "status": 1,
        "data": ""
    })
    @patch("modules.recon.runner.collect_dns", return_value={
        "A": ["192.0.2.10"],
        "AAAA": [],
        "MX": [],
        "NS": []
    })
    def test_domain_collection_uses_shared_assessment(
        self,
        mock_dns,
        mock_whois,
        mock_rdap,
        mock_technologies,
        mock_subdomains,
        mock_infrastructure,
        mock_ips,
        mock_ports,
        mock_web
    ):
        target = Target("example.com")
        assessment = Assessment(
            assessment_id="ZYN-00000001",
            target=target,
            started_at=datetime.now()
        )

        result = run(target, assessment)

        self.assertEqual(result, "completed")
        self.assertEqual(assessment.status, "running")
        self.assertIsNone(assessment.finished_at)

        categories = [
            observation.category
            for observation in assessment.observations
        ]

        self.assertIn("dns", categories)
        self.assertIn("ip_addresses", categories)
        self.assertIn("network", categories)
        self.assertIn("web_surface", categories)


if __name__ == "__main__":
    unittest.main()
