# Assessment Lifecycle

Zyntra uses one shared assessment lifecycle for reconnaissance,
enumeration and web assessment.

## Lifecycle sequence

1. Validate the supplied target.
2. Construct the target model.
3. Generate an assessment ID.
4. Create the shared assessment object.
5. Dispatch the selected module.
6. Collect observations into the shared assessment.
7. Finalize the assessment status.
8. Print the assessment summary.
9. Save `results.json`.
10. Generate `report.html`.

## Assessment statuses

- `running`: collection is in progress.
- `completed`: the module completed its work.
- `partial`: useful evidence was collected, but some work failed or was
  incomplete.
- `failed`: the assessment could not collect useful module evidence.

An assessment is finalized only once.

## Observations and findings

Observations are the collected evidence records. They may include successful
results, informational results, skipped checks and execution errors.

Findings are derived from supported observation categories. They provide
severity, confidence, status, evidence, impact and remediation.

Automated detection does not automatically confirm exploitability. Findings
remain `potential` unless separate validation justifies confirmation.

## Assessment files

Every assessment has exactly two primary output files:

- `results.json`: original observations and derived findings. Detected secret
  values remain in this evidence file.
- `report.html`: human-readable report with detected secret values redacted.

The HTML renderer escapes untrusted content. Redaction is applied to the
report representation without modifying the original assessment observations.

## Assessment IDs

Assessment IDs use the format `ZYN-` followed by eight digits. The counter
file is stored in the configured persistent data directory.

For portable use, set `ZYNTRA_DATA_DIR` before launching the application.
This keeps the assessment counter and assessment records together.

## Export behavior

The exporter validates the assessment ID and source JSON, requires both
assessment output files, and refuses to overwrite an existing destination
assessment directory.

Both files are copied and verified using SHA-256. The original assessment
files are not modified.
