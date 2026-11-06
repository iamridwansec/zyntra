import unittest
from datetime import datetime

from core.observation import Observation
from modules.evidence.correlator import correlate_observations


class TestEvidenceCorrelation(unittest.TestCase):

    def setUp(self):
        self.timestamp = datetime.now()

    def make_observation(self, category, data):
        return Observation(
            category=category,
            source="test",
            data=data,
            timestamp=self.timestamp
        )

    def test_correlates_matching_javascript_observations(self):
        observations = [
            self.make_observation("js_endpoint", {
                "javascript_url": "https://example.com/app.js",
                "endpoint": "/api/users"
            }),
            self.make_observation("potential_secret", {
                "javascript_url": "https://example.com/app.js",
                "finding": {
                    "type": "api_key",
                    "name": "API_KEY",
                    "value": "SECRET_VALUE"
                }
            })
        ]

        result = correlate_observations(observations)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["endpoint_count"], 1)
        self.assertEqual(result[0]["potential_secret_count"], 1)

    def test_does_not_correlate_different_javascript_files(self):
        observations = [
            self.make_observation("js_endpoint", {
                "javascript_url": "https://example.com/app.js"
            }),
            self.make_observation("potential_secret", {
                "javascript_url": "https://example.com/config.js"
            })
        ]

        self.assertEqual(correlate_observations(observations), [])

    def test_ignores_unmatched_observations(self):
        observations = [
            self.make_observation("js_endpoint", {
                "javascript_url": "https://example.com/app.js"
            })
        ]

        self.assertEqual(correlate_observations(observations), [])

    def test_correlates_multiple_javascript_files(self):
        observations = [
            self.make_observation("js_endpoint", {
                "javascript_url": "https://example.com/app.js"
            }),
            self.make_observation("potential_secret", {
                "javascript_url": "https://example.com/app.js",
                "finding": {"value": "SECRET_ONE"}
            }),
            self.make_observation("js_endpoint", {
                "javascript_url": "https://example.com/admin.js"
            }),
            self.make_observation("potential_secret", {
                "javascript_url": "https://example.com/admin.js",
                "finding": {"value": "SECRET_TWO"}
            })
        ]

        result = correlate_observations(observations)

        self.assertEqual(len(result), 2)

    def test_does_not_expose_secret_values(self):
        observations = [
            self.make_observation("js_endpoint", {
                "javascript_url": "https://example.com/app.js"
            }),
            self.make_observation("potential_secret", {
                "javascript_url": "https://example.com/app.js",
                "finding": {"value": "PRIVATE_SECRET"}
            })
        ]

        result = correlate_observations(observations)

        self.assertNotIn("PRIVATE_SECRET", str(result))


if __name__ == "__main__":
    unittest.main()
