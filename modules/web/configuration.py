import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
import socket
import ssl


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

        if not parts or "=" not in parts[0]:
            continue

        cookie_name = parts[0].split("=", 1)[0].strip()

        attributes = {}

        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                attributes[key.strip().lower()] = value.strip()
            else:
                attributes[part.strip().lower()] = True

        secure = "secure" in attributes
        httponly = "httponly" in attributes
        samesite = attributes.get("samesite")
        issues = []

        if not secure:
            issues.append({
                "code": "missing_secure",
                "description": "Cookie does not include the Secure attribute."
            })

        if not httponly:
            issues.append({
                "code": "missing_httponly",
                "description": "Cookie does not include the HttpOnly attribute."
            })


        if samesite and samesite.lower() == "none" and not secure:
            issues.append({
                "code": "samesite_none_without_secure",
                "description": "SameSite=None requires the Secure attribute."
            })

        if cookie_name.startswith("__Secure-") and not secure:
            issues.append({
                "code": "secure_prefix_violation",
                "description": "__Secure- cookies must include Secure."
            })

        if cookie_name.startswith("__Host-"):
            if not secure:
                issues.append({
                    "code": "host_prefix_missing_secure",
                    "description": "__Host- cookies must include Secure."
                })

            if "domain" in attributes:
                issues.append({
                    "code": "host_prefix_has_domain",
                    "description": "__Host- cookies must not include Domain."
                })

            if attributes.get("path") != "/":
                issues.append({
                    "code": "host_prefix_invalid_path",
                    "description": "__Host- cookies must use Path=/."
                })

        cookies.append({
            "name": cookie_name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "issues": issues
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


def analyze_tls_certificate(hostname, port=443):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=5) as connection:
            with context.wrap_socket(
                connection,
                server_hostname=hostname
            ) as tls_connection:

                certificate = tls_connection.getpeercert()

                return {
                    "status": "valid",
                    "verified": True,
                    "hostname": hostname,
                    "port": port,
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "expires": certificate.get("notAfter")
                }

    except ssl.SSLCertVerificationError as error:
        return {
            "status": "invalid",
            "verified": False,
            "hostname": hostname,
            "port": port,
            "error": str(error)
        }

    except (OSError, ssl.SSLError) as error:
        return {
            "status": "error",
            "verified": False,
            "hostname": hostname,
            "port": port,
            "error": str(error)
        }

def analyze_server_disclosure(response_headers):
    disclosure_headers = {
        "Server": {
            "severity": "Low",
            "description": "The server response reveals server software information.",
            "recommendation": "Consider minimizing or removing detailed Server header information."
        },
        "X-Powered-By": {
            "severity": "Low",
            "description": "The response reveals the technology powering the application.",
            "recommendation": "Remove unnecessary technology-identifying response headers."
        },
        "X-AspNet-Version": {
            "severity": "Low",
            "description": "The response reveals the ASP.NET version.",
            "recommendation": "Suppress unnecessary framework version information."
        },
        "X-Generator": {
            "severity": "Informational",
            "description": "The response reveals the software used to generate the content.",
            "recommendation": "Remove unnecessary generator information from response headers."
        }
    }

    disclosures = []

    for header, rule in disclosure_headers.items():
        value = response_headers.get(header)

        if value:
            disclosures.append({
                "header": header,
                "value": value,
                "severity": rule["severity"],
                "description": rule["description"],
                "recommendation": rule["recommendation"]
            })

    return disclosures


def analyze_security_headers_config(response_headers):
    issues = []

    def add_issue(code, description, severity, recommendation):
        issues.append({
            "code": code,
            "severity": severity,
            "description": description,
            "recommendation": recommendation
        })


    # Content Security Policy
    csp = response_headers.get("Content-Security-Policy")

    if csp:
        directives = [
            directive.strip().lower()
            for directive in csp.split(";")
        ]

        for directive in directives:
            parts = directive.split()

            if len(parts) < 2:
                continue

            directive_name = parts[0]
            source_values = parts[1:]

            if "*" in source_values:
                add_issue(
                    "csp_wildcard_source",
                    f"CSP directive '{directive_name}' permits any source.",
                    "High",
                    "Restrict resource sources to explicitly trusted origins."
                )
                break


        if "'unsafe-inline'" in csp.lower():
            add_issue(
                "csp_unsafe_inline",
                "CSP permits unsafe inline execution.",
                "High",
                "Avoid unsafe-inline and use nonces or hashes for approved inline scripts."
            )

    # HTTP Strict Transport Security
    hsts = response_headers.get("Strict-Transport-Security")

    if hsts:
        max_age = None
        directives = {}

        for directive in hsts.split(";"):
            key, separator, value = directive.strip().partition("=")
            key = key.strip().lower()

            if key:
                directives[key] = value.strip() if separator else True

        if "max-age" in directives:
            try:
                max_age = int(directives["max-age"])
                if max_age < 0:
                    max_age = None
            except (ValueError, TypeError):
                max_age = None

        if max_age is None:
            add_issue(
                "hsts_invalid_max_age",
                "HSTS is missing a valid max-age directive.",
                "Medium",
                "Configure a valid non-negative integer max-age directive."
            )

        elif max_age == 0:
            add_issue(
                "hsts_zero_max_age",
                "HSTS max-age is zero, disabling its protection.",
                "High",
                "Configure a positive max-age value to enable HSTS protection."
            )

        if "includesubdomains" not in directives:
            add_issue(
                "hsts_missing_include_subdomains",
                "HSTS does not include subdomains.",
                "Informational",
                "Consider adding includeSubDomains if all subdomains support HTTPS."
            )

    # X-Frame-Options
    frame_options = response_headers.get("X-Frame-Options")

    if frame_options:
        if frame_options.strip().upper() not in ("DENY", "SAMEORIGIN"):
            add_issue(
                "invalid_x_frame_options",
                "X-Frame-Options contains an invalid policy value.",
                "Medium",
                "Use DENY or SAMEORIGIN, or configure an appropriate Content-Security-Policy frame-ancestors directive."
            )


    # Other important security headers
    missing_headers = {
        "X-Content-Type-Options": {
            "code": "missing_x_content_type_options",
            "severity": "Medium",
            "recommendation": "Configure X-Content-Type-Options: nosniff."
        },
        "Referrer-Policy": {
            "code": "missing_referrer_policy",
            "severity": "Low",
            "recommendation": "Configure a Referrer-Policy appropriate for the application's privacy requirements, such as strict-origin-when-cross-origin."
        },
        "Permissions-Policy": {
            "code": "missing_permissions_policy",
            "severity": "Low",
            "recommendation": "Define a Permissions-Policy that restricts browser features to those the application requires."
        }
    }

    for header, rule in missing_headers.items():
        if not response_headers.get(header):
            add_issue(
                rule["code"],
                f"{header} is missing.",
                rule["severity"],
                rule["recommendation"]
            )


    return {
        "issues": issues
    }


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

    if https_analysis["uses_https"]:
        hostname = urlparse(final_url).hostname
        tls_analysis = analyze_tls_certificate(hostname)
    else:
        tls_analysis = {
            "status": "skipped",
            "verified": False,
            "reason": "Target did not use HTTPS."
        }

    server_disclosures = analyze_server_disclosure(response_headers)

    header_analysis = analyze_security_headers_config(response_headers)

    return {
        "status": "completed",
        "http_status": status,
        "url": final_url,
        "findings": findings,
        "header_analysis": header_analysis,
        "cookies": cookies,
        "https": https_analysis,
        "tls": tls_analysis,
        "server_disclosures": server_disclosures
    }
