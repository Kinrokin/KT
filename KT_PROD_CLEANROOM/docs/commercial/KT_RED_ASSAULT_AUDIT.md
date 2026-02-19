# KT Red Assault Audit (Verification)

This offering verifies that the red-assault mechanism and its reports are present, schema-valid, and consistent with the sealed state.

## Inputs
- A pinned KT checkout (e.g. `KT_V1_SEALED_20260217`).
- Access to existing seal-pack evidence directories (read-only).

## Verification (Preferred)
Run the full sweep harness (it performs perimeter validation and canonical meta-evaluation):
- `python -m tools.verification.run_sweep_audit --sweep-id OPERATOR_VERIFY`

Then verify seal-pack red-assault artifacts by reading the existing reports:
- `.../FL4_SEAL/<pack_id>/red_assault_report.json`
- `.../FL4_SEAL/<pack_id>/seal_verify_report.json`

## Outputs
- WORM sweep artifacts under `KT_PROD_CLEANROOM/exports/_runs/.../sweeps/<id>/`
- A one-line operator verdict (from operator CLI or local handoff pack)

## Acceptance Criteria
- `red_assault_report.json` indicates pass (e.g., `all_passed=true`) and has a stable `red_assault_id`.
- Seal verify report indicates `PASS` and references the red-assault output by hash.

