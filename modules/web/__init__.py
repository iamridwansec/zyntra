from datetime import datetime
from urllib.parse import urlsplit, parse_qsl

from modules.recon.target import Target
from core.observation import Observation
from .configuration import analyze_security_headers
from .access_control import check_resource_access
from .input_validation import inspect_input_reflection
from .cors import inspect_cors


def add_observation(assessment, category, source, data):
    observation = Observation(
        category=category,
        source=source,
        data=data,
        timestamp=datetime.now()
    )
    assessment.add_observation(observation)


def run(target, assessment):
    if not isinstance(target, Target):
        target = Target(target)

    if target.target_type == "domain":
        target_url = f"https://{target.hostname}"
    elif target.target_type == "url":
        target_url = target.value
    elif target.target_type == "ip":
        target_url = f"http://{target.hostname}"
    else:
        print("[!] Unsupported target type.")
        return

    print(f"[+] Web assessment target: {target_url}")

    module_statuses = {}

    # 1. Configuration intelligence
    print("[*] Running configuration analysis...")

    try:
        result = analyze_security_headers(target_url)

        if result["status"] == "completed":
            categories = {
                "security_headers": result["findings"],
                "header_analysis": result["header_analysis"],
                "cookie_analysis": result["cookies"],
                "https_analysis": result["https"],
                "server_disclosure": result["server_disclosures"]
            }


            for category, data in categories.items():
                add_observation(
                    assessment,
                    category,
                    "configuration_intelligence",
                    data
                )

            module_statuses["configuration"] = "completed"

        else:
            add_observation(
                assessment,
                "configuration_error",
                "configuration_intelligence",
                result
            )
            module_statuses["configuration"] = "failed"

    except Exception as error:
        add_observation(
            assessment,
            "configuration_error",
            "configuration_intelligence",
            {"error": str(error)}
        )
        module_statuses["configuration"] = "failed"

    # 2. Access control
    print("[*] Running access control assessment...")

    try:
        access_result = check_resource_access(target_url)

        add_observation(
            assessment,
            "access_control",
            "access_control_assessment",
            access_result
        )

        module_statuses["access_control"] = "completed"

    except Exception as error:
        add_observation(
            assessment,
            "access_control_error",
            "access_control_assessment",
            {"error": str(error)}
        )
        module_statuses["access_control"] = "failed"

    # 3. Input reflection
    print("[*] Running input reflection assessment...")

    query_parameters = parse_qsl(
        urlsplit(target_url).query,
        keep_blank_values=True
    )

    parameter_names = list(dict.fromkeys(
        name for name, value in query_parameters if name
    ))

    if not parameter_names:
        input_result = {
            "status": "skipped",
            "reason": "No query parameters were present in the target URL."
        }

        add_observation(
            assessment,
            "input_validation",
            "input_validation_assessment",
            input_result
        )

        module_statuses["input_validation"] = "skipped"

    else:
        input_results = []

        for parameter in parameter_names:
            try:
                result = inspect_input_reflection(
                    target_url,
                    parameter
                )
            except Exception as error:
                result = {
                    "status": "error",
                    "parameter": parameter,
                    "error": str(error)
                }

            input_results.append(result)

        add_observation(
            assessment,
            "input_validation",
            "input_validation_assessment",
            {
                "status": "completed",
                "results": input_results
            }
        )

        if all(
            item["status"] == "completed"
            for item in input_results
        ):
            module_statuses["input_validation"] = "completed"
        else:
            module_statuses["input_validation"] = "partial"

    # 4. CORS assessment
    print("[*] Running CORS assessment...")

    try:
        cors_result = inspect_cors(
            target_url,
            assessment.assessment_id
        )

        add_observation(
            assessment,
            "cors_assessment",
            "cors_assessment",
            cors_result
        )

        module_statuses["cors"] = cors_result["status"]

    except Exception as error:
        add_observation(
            assessment,
            "cors_error",
            "cors_assessment",
            {"error": str(error)}
        )
        module_statuses["cors"] = "failed"

    # Determine overall assessment status
    successful_statuses = ("completed", "skipped")

    if all(
        status in successful_statuses
        for status in module_statuses.values()
    ):
        assessment_status = "completed"

    elif any(
        status in ("completed", "partial", "skipped")
        for status in module_statuses.values()
    ):
        assessment_status = "partial"

    else:
        assessment_status = "failed"


    print("\n[+] Module results:")

    for module, status in module_statuses.items():
        print(f"    {module}: {status}")

    print(f"\n[+] Observations: {len(assessment.observations)}")
    print(f"[+] Assessment status: {assessment_status}")
    return assessment_status
