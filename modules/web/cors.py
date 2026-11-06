
import urllib.request
from urllib.error import HTTPError, URLError


CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age"
]


def _inspect_request(target_url, method, origin):
    request_headers = {
        "User-Agent": "Zyntra/0.1.0",
        "Origin": origin
    }

    if method == "OPTIONS":
        request_headers.update({
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Zyntra-Probe"
        })

    request = urllib.request.Request(
        target_url,
        headers=request_headers,
        method=method
    )

    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            headers = response.headers
            status_code = response.status
            final_url = response.url

    except HTTPError as error:
        headers = error.headers
        status_code = error.code
        final_url = error.url

    except (URLError, TimeoutError, OSError) as error:
        reason = getattr(error, "reason", str(error))

        return {
            "status": "connection_error",
            "method": method,
            "request_origin": origin,
            "target": target_url,
            "error": str(reason),
            "headers": []
        }

    findings = []

    for header in CORS_HEADERS:
        value = headers.get(header)

        findings.append({
            "header": header,
            "present": value is not None,
            "value": value
        })

    return {
        "status": "completed",
        "method": method,
        "request_origin": origin,
        "target": final_url,
        "http_status": status_code,
        "headers": findings
    }


def _get_response_header(result, header_name):
    if result["status"] != "completed":
        return None

    for item in result["headers"]:
        if item["header"].lower() == header_name.lower():
            return item["value"]

    return None


def inspect_cors(target_url, assessment_id):
    assessment_slug = assessment_id.lower()

    primary_origin = (
        f"https://zyntra-{assessment_slug}.invalid"
    )

    control_origin = (
        f"https://control-{assessment_slug}.invalid"
    )

    methods = ("GET", "OPTIONS")

    responses = {
        method: _inspect_request(
            target_url, method, primary_origin
        )
        for method in methods
    }

    control_responses = {
        method: _inspect_request(
            target_url, method, control_origin
        )
        for method in methods
    }

    risk_indicators = []

    for method in methods:
        primary = responses[method]
        control = control_responses[method]

        if primary["status"] != "completed":
            continue

        allow_origin = _get_response_header(
            primary, "Access-Control-Allow-Origin"
        )

        allow_credentials = _get_response_header(
            primary, "Access-Control-Allow-Credentials"
        )

        if allow_origin == "*":
            risk_indicators.append({
                "indicator": "wildcard_origin",
                "method": method,
                "severity": "informational",
                "description": (
                    "The server returns a wildcard origin policy. "
                    "Credentialed browser access is not permitted "
                    "with this wildcard response."
                )
            })

            if (
                allow_credentials
                and allow_credentials.lower() == "true"
            ):
                risk_indicators.append({
                    "indicator": "wildcard_with_credentials",
                    "method": method,
                    "severity": "informational",
                    "classification": "browser_rejected_combination",
                    "description": (
                        "Wildcard origin and credential allowance "
                        "are returned together. Browsers reject "
                        "this combination for credentialed CORS "
                        "requests. This is a policy misconfiguration, "
                        "not proof of credentialed cross-origin access."
                    )
                })

        primary_reflected = (
            allow_origin == primary_origin
        )

        control_reflected = (
            _get_response_header(
                control, "Access-Control-Allow-Origin"
            ) == control_origin
        )

        if primary_reflected and control_reflected:
            primary_credentials = (
                allow_credentials is not None
                and allow_credentials.lower() == "true"
            )

            control_credentials = (
                _get_response_header(
                    control,
                    "Access-Control-Allow-Credentials"
                )
            )

            credentials_allowed = (
                primary_credentials
                and control_credentials is not None
                and control_credentials.lower() == "true"
            )

            risk_indicators.append({
                "indicator": "origin_reflection",
                "method": method,
                "severity": "low",
                "classification": "arbitrary_origin_reflection_observed",
                "credentials_allowed": credentials_allowed,
                "evidence": {
                    "primary_origin": primary_origin,
                    "primary_response": allow_origin,
                    "control_origin": control_origin,
                    "control_response": control_origin
                },
                "description": (
                    "The server reflected two distinct supplied "
                    "origins. This indicates arbitrary origin "
                    "reflection. Further assessment is required "
                    "to establish whether sensitive resources "
                    "are exposed through browser-based requests."
                )
            })

    completed = sum(
        responses[method]["status"] == "completed"
        and control_responses[method]["status"] == "completed"
        for method in methods
    )

    if completed == 2:
        status = "completed"
    elif completed > 0:
        status = "partial"
    else:
        status = "connection_error"

    return {
        "status": status,
        "target": target_url,
        "assessment_id": assessment_id,
        "probe_origin": primary_origin,
        "control_origin": control_origin,
        "responses": responses,
        "control_responses": control_responses,
        "risk_indicators": risk_indicators
    }
