"""Export individual Zyntra assessments without overwriting existing exports."""

import hashlib
import json
import re
import shutil
from pathlib import Path

from config.paths import ASSESSMENTS_DIR


def calculate_sha256(file_path):
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def export_assessment(assessment_id, destination):
    if not isinstance(assessment_id, str) or not re.fullmatch(
        r"ZYN-\d{8}", assessment_id
    ):
        raise ValueError("Invalid assessment ID format.")

    source_dir = ASSESSMENTS_DIR / assessment_id
    source_results = source_dir / "results.json"
    source_report = source_dir / "report.html"

    if not source_results.is_file():
        raise FileNotFoundError(
            f"Assessment results not found: {assessment_id}"
        )

    if not source_report.is_file():
        raise FileNotFoundError(
            f"Assessment HTML report not found: {assessment_id}"
        )

    try:
        assessment_data = json.loads(source_results.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Assessment file contains invalid JSON.") from error

    if not isinstance(assessment_data, dict):
        raise ValueError("Assessment file must contain a JSON object.")

    if assessment_data.get("assessment_id") != assessment_id:
        raise ValueError("Assessment ID does not match its directory.")

    destination_root = Path(destination).expanduser().resolve()

    if not destination_root.is_dir():
        raise FileNotFoundError(
            f"Destination directory does not exist: {destination_root}"
        )

    destination_dir = destination_root / assessment_id

    try:
        destination_dir.mkdir()
    except FileExistsError:
        return {
            "status": "skipped",
            "reason": "Assessment already exists at destination.",
            "path": destination_dir
        }

    destination_results = destination_dir / "results.json"
    destination_report = destination_dir / "report.html"

    try:
        shutil.copy2(source_results, destination_results)
        shutil.copy2(source_report, destination_report)

        results_hash = calculate_sha256(source_results)
        report_hash = calculate_sha256(source_report)

        if results_hash != calculate_sha256(destination_results):
            raise IOError("Results SHA-256 verification failed.")

        if report_hash != calculate_sha256(destination_report):
            raise IOError("HTML report SHA-256 verification failed.")

    except Exception:
        shutil.rmtree(destination_dir, ignore_errors=True)
        raise

    return {
        "status": "exported",
        "path": destination_results,
        "report_path": destination_report,
        "sha256": results_hash,
        "report_sha256": report_hash
    }
