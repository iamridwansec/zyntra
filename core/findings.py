"""Finding data model and conservative observation classification."""

from dataclasses import dataclass, field


VALID_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}

VALID_CONFIDENCE_LEVELS = {
    "low",
    "medium",
    "high",
}

VALID_STATUSES = {
    "potential",
    "confirmed",
}

COOKIE_SEVERITIES = {
    "missing_secure": "low",
    "missing_httponly": "low",
    "samesite_none_without_secure": "medium",
    "secure_prefix_violation": "medium",
    "host_prefix_missing_secure": "medium",
    "host_prefix_has_domain": "medium",
    "host_prefix_invalid_path": "medium",
}


COOKIE_REMEDIATIONS = {
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


@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    evidence: object
    impact: str
    remediation: str
    related_observations: list = field(default_factory=list)

    def __post_init__(self):
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")

        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            raise ValueError(f"Invalid confidence: {self.confidence}")

        if self.status not in VALID_STATUSES:
            raise ValueError(f"Invalid finding status: {self.status}")


def _normalize_severity(value):
    severity = str(value).lower()

    if severity not in VALID_SEVERITIES:
        return None

    return severity


def build_findings(assessment):
    """Build potential findings from supported assessment observations."""

    findings = []

    def add_finding(
        title,
        category,
        severity,
        evidence,
        impact,
        remediation,
        observation_index,
    ):
        severity = _normalize_severity(severity)

        if severity is None:
            return

        finding = Finding(
            finding_id=f"F-{len(findings) + 1:03d}",
            title=title,
            category=category,
            severity=severity,
            confidence="high",
            status="potential",
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            related_observations=[observation_index],
        )

        findings.append(finding)

    for observation_index, observation in enumerate(
        assessment.observations
    ):
        data = observation.data

        if observation.category == "header_analysis":
            if not isinstance(data, dict):
                continue

            for issue in data.get("issues", []):
                if not isinstance(issue, dict):
                    continue

                add_finding(
                    title=issue.get("description", "Security header issue"),
                    category="security_headers",
                    severity=issue.get("severity"),
                    evidence={
                        "observation_category": observation.category,
                        "issue": issue,
                    },
                    impact=(
                        "The observed header configuration may weaken "
                        "browser-side security or privacy protections."
                    ),
                    remediation=issue.get(
                        "recommendation",
                        "Review and correct the security header configuration.",
                    ),
                    observation_index=observation_index,
                )

        elif observation.category == "cookie_analysis":
            if not isinstance(data, list):
                continue

            for cookie in data:
                if not isinstance(cookie, dict):
                    continue

                for issue in cookie.get("issues", []):
                    if not isinstance(issue, dict):
                        continue

                    code = issue.get("code")
                    severity = COOKIE_SEVERITIES.get(code)

                    if severity is None:
                        continue

                    add_finding(
                        title=issue.get(
                            "description",
                            "Cookie security configuration issue",
                        ),
                        category="cookie_security",
                        severity=severity,
                        evidence={
                            "observation_category": observation.category,
                            "cookie_name": cookie.get("name"),
                            "cookie_attributes": {
                                "secure": cookie.get("secure"),
                                "httponly": cookie.get("httponly"),
                                "samesite": cookie.get("samesite"),
                            },
                            "issue": issue,
                        },
                        impact=(
                            "The cookie configuration may reduce protection "
                            "against certain client-side or transport-related "
                            "risks, depending on how the cookie is used."
                        ),
                        remediation=COOKIE_REMEDIATIONS.get(
                            code,
                            "Review the cookie attributes and configure appropriate security protections.",
                        ),
                        observation_index=observation_index,
                    )

        elif observation.category == "server_disclosure":
            if not isinstance(data, list):
                continue

            for disclosure in data:
                if not isinstance(disclosure, dict):
                    continue

                add_finding(
                    title=disclosure.get(
                        "description",
                        "Server technology information disclosed",
                    ),
                    category="server_disclosure",
                    severity=disclosure.get("severity"),
                    evidence={
                        "observation_category": observation.category,
                        "header": disclosure.get("header"),
                        "value": disclosure.get("value"),
                    },
                    impact=(
                        "Disclosed technology information may help an "
                        "attacker identify software or versions for further "
                        "investigation. Disclosure alone does not prove "
                        "an exploitable vulnerability."
                    ),
                    remediation=disclosure.get(
                        "recommendation",
                        "Remove unnecessary technology-identifying headers.",
                    ),
                    observation_index=observation_index,
                )

    return findings
