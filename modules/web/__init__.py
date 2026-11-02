from datetime import datetime

from modules.recon.target import Target
from core.assessment import Assessment
from core.observation import Observation
from core.ids import generate_assessment_id
from core.serializer import save_assessment

from .configuration import analyze_security_headers
from .access_control import check_resource_access

def run(target):
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

    assessment = Assessment(
        assessment_id=generate_assessment_id(),
        target=target,
        started_at=datetime.now()
    )

    print(f"[+] Assessment ID: {assessment.assessment_id}")
    print(f"[+] Web assessment target: {target_url}")

    result = analyze_security_headers(target_url)

    if result["status"] != "completed":
        print(f"[!] Configuration analysis failed: {result['error']}")
        assessment.status = "failed"
    else:
        categories = {
            "security_headers": result["findings"],
            "cookie_analysis": result["cookies"],
            "https_analysis": result["https"],
            "server_disclosure": result["server_disclosures"]
        }

        for category, data in categories.items():
            observation = Observation(
                category=category,
                source="configuration_intelligence",
                data=data,
                timestamp=datetime.now()
            )

            assessment.add_observation(observation)

        access_result = check_resource_access(target_url)

        access_observation = Observation(
            category="access_control",
            source="access_control_assessment",
            data=access_result,
            timestamp=datetime.now()
        )

        assessment.add_observation(access_observation)

        assessment.status = "completed"

    print(f"[+] Observations: {len(assessment.observations)}")

    save_path = (
        f"data/assessments/"
        f"{assessment.assessment_id}/results.json"
    )

    save_assessment(assessment, save_path)

    print(f"[+] Assessment status: {assessment.status}")
    print(f"[+] Results saved to: {save_path}")

