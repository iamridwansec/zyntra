from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


@dataclass
class Target:
    value: str
    target_type: str = "unknown"
    hostname: str = ""

    def __post_init__(self):
        self.value = self.value.strip()
        self.target_type = self.detect_type()
        self.hostname = self.extract_hostname()

    def detect_type(self):
        if self.value.startswith(("http://", "https://")):
            return "url"

        try:
            ip_address(self.value)
            return "ip"
        except ValueError:
            pass

        return "domain"

    def extract_hostname(self):
        if self.target_type == "url":
            return urlparse(self.value).hostname or ""

        return self.value
