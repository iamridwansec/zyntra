import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def analyze_cookies(response_headers):
    cookie_headers = response_headers.get_all("Set-Cookie", []) or []
    cookies = []

    for cookie_header in cookie_headers:
        parts = [part.strip() for part in cookie_header.split(";")]

        cookie_name = parts[0].split("=", 1)[0].strip()

        attributes = {}

        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                attributes[key.strip().lower()] = value.strip()
            else:
                attributes[part.strip().lower()] = True

        cookies.append({
            "name": cookie_name,
            "secure": "secure" in attributes,
            "httponly": "httponly" in attributes,
            "samesite": attributes.get("samesite")
        })

    return cookies

def analyze_https_behavior(original_url, final_url):
    original_scheme = urlparse(original_url).scheme.lower()
    final_scheme = urlparse(final_url).scheme.lower()

    return {
        "original_scheme": original_scheme,
        "final_scheme": final_scheme,
        "uses_https": final_scheme == "https",
        "redirected_to_https": (
            original_scheme == "http" and final_scheme == "https"
        )
    }

def analyze_server_disclosure(response_headers):
    disclosure_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Generator"
    ]

    disclosures = []

    for header in disclosure_headers:
        value = response_headers.get(header)

        if value:
            disclosures.append({
                "header": header,
                "value": value
            })

    return disclosures


def analyze_security_headers(target_url):
    request = urllib.request.Request(
        target_url,
        headers={"User-Agent": "Zyntra/0.1.0"}
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response_headers = response.headers
            status = response.status
            final_url = response.url

    except HTTPError as error:
        response_headers = error.headers
        status = error.code
        final_url = error.url

    except URLError as error:
        return {
            "status": "error",
            "error": str(error.reason),
            "headers": [],
            "cookies": []
        }

    findings = []

    for header in SECURITY_HEADERS:
        value = response_headers.get(header)

        findings.append({
            "header": header,
            "present": value is not None,
            "value": value
        })

    cookies = analyze_cookies(response_headers)

    https_analysis = analyze_https_behavior(target_url, final_url)

    server_disclosures = analyze_server_disclosure(response_headers)

    return {
        "status": "completed",
        "http_status": status,
        "url": final_url,
        "findings": findings,
        "cookies": cookies,
        "https": https_analysis,
        "server_disclosures": server_disclosures
    }
