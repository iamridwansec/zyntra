import re
import urllib.request
from urllib.parse import urljoin


def discover_javascript(base_url):
    request = urllib.request.Request(
        base_url,
        headers={"User-Agent": "Zyntra/0.1.0"}
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        html = response.read().decode("utf-8", errors="ignore")

    scripts = re.findall(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE
    )

    javascript_urls = []

    for script in scripts:
        javascript_urls.append(urljoin(base_url, script))

    return javascript_urls

def fetch_javascript(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Zyntra/0.1.0"}
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        content = response.read().decode("utf-8", errors="ignore")

    return content

def extract_endpoints(javascript):
    pattern = r'["\'](/[^"\']+)["\']'
    return re.findall(pattern, javascript)


def detect_api_keys(javascript):
    pattern = r'(?i)(api[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']'

    findings = []

    for match in re.finditer(pattern, javascript):
        findings.append({
            "type": "api_key",
            "name": match.group(1),
            "value": match.group(2)
        })

    return findings
