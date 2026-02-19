# KT Continuous Governance (Runbook-Grade)

This offering is a repeatable, evidence-producing governance loop: status -> certify -> report -> archive.

## Customer Inputs
- A pinned KT checkout to operate (tag or commit).
- Operator schedule (cadence) and policy for what constitutes a failure.
- (Optional) HMAC key management for canonical lane verification.

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

## Convenience Wrapper (Windows, No Installs)
- `powershell -ExecutionPolicy Bypass -File KT_PROD_CLEANROOM/tools/operator/kt.ps1 --profile v1 status`

## Acceptance Criteria
- Each run is fail-closed on mismatch/ambiguity.
- No repo mutation occurs during runs (worktree remains clean).
- Evidence roots are WORM (create-once).
