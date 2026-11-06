from pathlib import Path
import json
import html
"""Shared terminal reporting for Zyntra assessments."""

from collections import Counter

from core.findings import build_findings


def print_assessment_summary(assessment):
    """Print a concise summary of an assessment."""

    print("\n" + "=" * 60)
    print("                 ZYNTRA ASSESSMENT SUMMARY")
    print("=" * 60)

    print(f"Assessment ID:      {assessment.assessment_id}")
    print(f"Target:             {assessment.target.value}")
    print(f"Target type:        {assessment.target.target_type}")
    print(f"Status:             {assessment.status}")
    print(f"Started:            {assessment.started_at}")
    print(f"Finished:           {assessment.finished_at or 'Not finished'}")

    if assessment.finished_at:
        duration = (
            assessment.finished_at - assessment.started_at
        ).total_seconds()
        print(f"Duration:           {duration:.2f} seconds")
    else:
        print("Duration:           Not available")

    observations = assessment.observations
    print(f"\nTotal observations: {len(observations)}")

    if observations:
        print("\nObservations by category:")

        category_counts = Counter(
            observation.category for observation in observations
        )

        for category, count in sorted(category_counts.items()):
            print(f"  {category}: {count}")
    else:
        print("  No observations recorded.")

    print("=" * 60)



def generate_html_report(assessment, output_path):
    """Generate a self-contained HTML report for an assessment."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    escape = html.escape

    observations = assessment.observations
    category_counts = Counter(
        str(observation.category) for observation in observations
    )

    observation_sections = []

    for index, observation in enumerate(observations, start=1):
        category = escape(str(observation.category))
        source = escape(str(observation.source))
        timestamp = escape(str(observation.timestamp))

        report_data = observation.data

        if observation.category == "potential_secret":
            report_data = json.loads(json.dumps(
                observation.data,
                default=str
            ))

            finding = report_data.get("finding")

            if isinstance(finding, dict) and "value" in finding:
                finding["value"] = "[REDACTED]"

        serialized_data = json.dumps(
            report_data,
            indent=2,
            ensure_ascii=False,
            default=str
        )

        safe_data = escape(serialized_data)

        observation_sections.append(f"""
        <article class="observation">
            <h3>Observation {index}: {category}</h3>
            <p><strong>Source:</strong> {source}</p>
            <p><strong>Timestamp:</strong> {timestamp}</p>
            <details>
                <summary>View recorded data</summary>
                <pre>{safe_data}</pre>
            </details>
        </article>
        """)

    if observation_sections:
        observations_html = "\n".join(observation_sections)
    else:
        observations_html = (
            '<p class="empty">No observations were recorded.</p>'
        )

    category_rows = []

    for category, count in sorted(category_counts.items()):
        category_rows.append(
            f"<tr><td>{escape(category)}</td><td>{count}</td></tr>"
        )

    if category_rows:
        categories_html = "\n".join(category_rows)
    else:
        categories_html = (
            '<tr><td colspan="2">No categories recorded.</td></tr>'
        )

    findings = build_findings(assessment)
    finding_sections = []

    for finding in findings:
        evidence = json.dumps(
            finding.evidence,
            indent=2,
            ensure_ascii=False,
            default=str
        )

        finding_sections.append(f"""
        <article class="finding">
            <h3>{escape(str(finding.finding_id))}: {escape(str(finding.title))}</h3>
            <p><strong>Category:</strong> {escape(str(finding.category))}</p>
            <p><strong>Severity:</strong> {escape(str(finding.severity))}</p>
            <p><strong>Confidence:</strong> {escape(str(finding.confidence))}</p>
            <p><strong>Status:</strong> {escape(str(finding.status))}</p>
            <details>
                <summary>View evidence</summary>
                <pre>{escape(evidence)}</pre>
            </details>
            <p><strong>Potential impact:</strong>
                {escape(str(finding.impact))}</p>
            <p><strong>Recommended remediation:</strong>
                {escape(str(finding.remediation))}</p>
        </article>
        """)

    if finding_sections:
        findings_html = "\n".join(finding_sections)
    else:
        findings_html = (
            '<p class="empty">No potential findings were generated '
            'from the supported checks.</p>'
        )

    started = escape(str(assessment.started_at))
    finished = escape(
        str(assessment.finished_at)
        if assessment.finished_at
        else "Not finished"
    )

    if assessment.finished_at:
        duration = (
            assessment.finished_at - assessment.started_at
        ).total_seconds()
        duration_text = f"{duration:.2f} seconds"
    else:
        duration_text = "Not available"

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Zyntra security assessment report">
    <title>Zyntra Report - {escape(str(assessment.assessment_id))}</title>
    <style>
        :root {{
            color-scheme: dark;
            font-family: Arial, Helvetica, sans-serif;
            background: #10151d;
            color: #e5e7eb;
        }}
        body {{
            margin: 0;
            padding: 32px 18px;
        }}
        main {{
            max-width: 1000px;
            margin: auto;
        }}
        header {{
            border-bottom: 1px solid #334155;
            padding-bottom: 24px;
            margin-bottom: 28px;
        }}
        h1, h2 {{
            color: #f8fafc;
        }}
        h1 {{
            letter-spacing: 2px;
        }}
        .subtitle, .muted {{
            color: #94a3b8;
        }}
        .panel, .observation, .finding {{
            background: #1b2430;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 18px;
        }}
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }}
        .metadata p {{
            overflow-wrap: anywhere;
        }}
        .status {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 6px;
            background: #263b50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        pre {{
            background: #0b1017;
            color: #cbd5e1;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }}
        summary {{
            cursor: pointer;
            color: #7dd3fc;
        }}
        .empty {{
            color: #94a3b8;
        }}
        footer {{
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid #334155;
            color: #94a3b8;
            font-size: 0.9rem;
        }}
        @media print {{
            :root {{
                color-scheme: light;
                background: white;
                color: black;
            }}
            body {{
                padding: 0;
            }}
            .panel, .observation, .finding {{
                background: white;
                color: black;
                border: 1px solid #bbb;
                break-inside: avoid;
            }}
            h1, h2, h3 {{
                color: black;
            }}
            pre {{
                white-space: pre-wrap;
                color: black;
                background: #f1f5f9;
            }}
        }}
    </style>
</head>
<body>
<main>
    <header>
        <h1>ZYNTRA</h1>
        <p class="subtitle">Security Assessment Report</p>
        <p>Assessment ID: {escape(str(assessment.assessment_id))}</p>
    </header>

    <section class="panel">
        <h2>Assessment Overview</h2>
        <div class="metadata">
            <p><strong>Target:</strong><br>
                {escape(str(assessment.target.value))}</p>
            <p><strong>Target type:</strong><br>
                {escape(str(assessment.target.target_type))}</p>
            <p><strong>Status:</strong><br>
                <span class="status">{escape(str(assessment.status))}</span></p>
            <p><strong>Started:</strong><br>{started}</p>
            <p><strong>Finished:</strong><br>{finished}</p>
            <p><strong>Duration:</strong><br>
                {escape(duration_text)}</p>
        </div>
    </section>

    <section class="panel">
        <h2>Observation Summary</h2>
        <p>Total observations: <strong>{len(observations)}</strong></p>
        <table>
            <thead>
                <tr><th>Category</th><th>Count</th></tr>
            </thead>
            <tbody>
                {categories_html}
            </tbody>
        </table>
    </section>

    <section>
        <h2>Security Findings</h2>
        <p class="muted">
            These findings are potential issues derived from assessment
            observations. They require appropriate validation before being
            treated as confirmed vulnerabilities.
        </p>
        {findings_html}
    </section>

    <section>
        <h2>Recorded Observations</h2>
        {observations_html}
    </section>

    <footer>
        Generated by Zyntra Security Assessment &amp; Intelligence Framework.
        Observations are recorded assessment data and are not automatically
        confirmed vulnerabilities.
    </footer>
</main>
</body>
</html>
"""

    output_path.write_text(report, encoding="utf-8")
    return output_path
