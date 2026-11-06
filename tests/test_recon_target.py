import unittest

from modules.recon.target import Target


class TestTargetClassification(unittest.TestCase):

    def test_domain_target(self):
        target = Target("example.com")

        self.assertEqual(target.target_type, "domain")
        self.assertEqual(target.hostname, "example.com")

    def test_ipv4_target(self):
        target = Target("192.168.1.10")

        self.assertEqual(target.target_type, "ip")
        self.assertEqual(target.hostname, "192.168.1.10")

    def test_ipv6_target(self):
        target = Target("2001:db8::1")

        self.assertEqual(target.target_type, "ip")
        self.assertEqual(target.hostname, "2001:db8::1")

    def test_url_target(self):
        target = Target("https://example.com/path")

        self.assertEqual(target.target_type, "url")
        self.assertEqual(target.hostname, "example.com")

    def test_http_url_target(self):
        target = Target("http://example.com")

        self.assertEqual(target.target_type, "url")
        self.assertEqual(target.hostname, "example.com")

    def test_whitespace_is_removed(self):
        target = Target("  example.com  ")

        self.assertEqual(target.value, "example.com")
        self.assertEqual(target.hostname, "example.com")


if __name__ == "__main__":
    unittest.main()
