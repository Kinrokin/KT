# KT Continuous Governance (Runbook-Grade)

This offering is a repeatable, evidence-producing governance loop: status -> certify -> report -> archive.

SKU: `SKU_CG`  
Lane: `continuous_gov.v1`

## Business outcome (what you can say)
- “We can prove drift/regression status over time using replayable run artifacts, not a manual narrative.”

## Customer Inputs
- A pinned KT checkout to operate (tag or commit).
- Operator schedule (cadence) and policy for what constitutes a failure.
- (Optional) HMAC key management for canonical lane verification.
 - For drift/regression comparisons: a baseline run directory (or agreement that the first run becomes baseline).

## Operator Workflow
1) Status (pins + hashes):
- `python -m tools.operator.kt_cli --profile v1 status`

2) Certify (sweep harness):
- `python -m tools.operator.kt_cli --profile v1 certify --lane ci_sim`
- `python -m tools.operator.kt_cli --profile v1 certify --lane canonical_hmac` (requires HMAC keys)

3) Report (human-facing summary of a run):
- `python -m tools.operator.kt_cli --profile v1 report --run <run_dir>`

## Outputs
- Per run: a new directory under `KT_PROD_CLEANROOM/exports/_runs/...` with WORM logs, summaries, and a one-line verdict.
- Optional zipped delivery pack (operator chooses packaging tool; no repo mutation).

For continuous governance diffs, the lane emits:
- `reports/drift_report.json`
- `reports/regression_report.json`
- `reports/trend_snapshot.json`
- `reports/diff_summary.md`

## Convenience Wrapper (Windows, No Installs)
- `powershell -ExecutionPolicy Bypass -File KT_PROD_CLEANROOM/tools/operator/kt.ps1 --profile v1 status`

## Typical Timeline (planning estimate)
- Setup: 1–2 business days.
- Cadence: weekly/monthly runs with fixed thresholds and an agreed escalation path.

## Pricing Logic (framework; no numbers)
- Retainer (cadence) + per-run fee; optional quarterly “deep dive” review.

## Acceptance Criteria
- Each run is fail-closed on mismatch/ambiguity.
- No repo mutation occurs during runs (worktree remains clean).
- Evidence roots are WORM (create-once).
