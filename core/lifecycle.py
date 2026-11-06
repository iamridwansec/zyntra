from datetime import datetime

from config.paths import ASSESSMENTS_DIR
from core.assessment import Assessment
from core.ids import generate_assessment_id
from core.observation import Observation
from core.reporting import (
    generate_html_report,
    print_assessment_summary
)
from core.serializer import save_assessment
from modules.recon.target import Target


def run_assessment(command, module, target_value, ports=None):
    if not isinstance(target_value, str) or not target_value.strip():
        raise ValueError("A valid target is required.")

    target = Target(target_value)

    assessment = Assessment(
        assessment_id=generate_assessment_id(),
        target=target,
        started_at=datetime.now()
    )

    print(f"[+] Assessment ID: {assessment.assessment_id}")
    print(f"[+] Target: {target.value}")
    print(f"[+] Target type: {target.target_type}")

    try:
        if command == "recon":
            result = module.run(target, assessment, ports=ports)
        else:
            result = module.run(target, assessment)

        if result == "partial":
            assessment.mark_partial()
        elif result == "failed":
            assessment.fail()
        else:
            assessment.complete()

    except Exception as error:
        had_evidence = bool(assessment.observations)

        assessment.add_observation(
            Observation(
                category="module_execution_error",
                source=command,
                data={
                    "error_type": type(error).__name__,
                    "message": str(error)
                },
                timestamp=datetime.now()
            )
        )

        if had_evidence:
            assessment.mark_partial()
        else:
            assessment.fail()

        print(f"[!] {command} execution failed: {error}")

    print_assessment_summary(assessment)
    print(f"[+] Assessment status: {assessment.status}")
    print(f"[+] Assessment finished: {assessment.finished_at}")

    assessment_dir = ASSESSMENTS_DIR / assessment.assessment_id
    results_path = assessment_dir / "results.json"
    report_path = assessment_dir / "report.html"

    save_assessment(assessment, results_path)
    generate_html_report(assessment, report_path)

    print(f"[+] Results saved to: {results_path}")
    print(f"[+] Report saved to: {report_path}")

    return assessment
