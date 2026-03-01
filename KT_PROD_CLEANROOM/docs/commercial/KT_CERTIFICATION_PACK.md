# KT Certification Pack (Operator Deliverable)

This offering produces an auditor-grade evidence pack proving a specific KT state passes the governed sweep harness.

SKU: `SKU_CERT`  
Lane: `certify.canonical_hmac`

## Business outcome (what you can say without hand-waving)
- “This pinned system state was evaluated under a governed harness and produced a replayable evidence bundle with a mechanical PASS/FAIL verdict.”

## Canonical Anchors (KT V1)
- Sealed tag: `KT_V1_SEALED_20260217`
- Sealed commit: `7b7f6e71d43c0aa60d4bc91be47e679491883871`
- Law bundle hash: `cd593dee1cc0b4c30273c90331124c3686f510ff990005609b3653268e66d906`
- Suite registry id: `e7a37cdc2a84b042dc1f594d1f84b4ba0a843c49de4925a06e6117fbac1eff17`

## Customer Inputs (Required)
- A repository checkout to certify (typically `KT_V1_SEALED_20260217`).
- A clean operator machine with Python available.
- Permission to write evidence under `KT_PROD_CLEANROOM/exports/_runs/...` (WORM).
- For canonical-lane PASS:
  - `KT_HMAC_KEY_SIGNER_A` and `KT_HMAC_KEY_SIGNER_B` present in environment (do not share; length checks only).

## Operator Command (Preferred)
- `python -m tools.operator.kt_cli --profile v1 certify --lane ci_sim`
- `python -m tools.operator.kt_cli --profile v1 certify --lane canonical_hmac`

Windows wrapper (no installs):
- `powershell -ExecutionPolicy Bypass -File KT_PROD_CLEANROOM/tools/operator/kt.ps1 --profile v1 certify --lane ci_sim`

## Outputs (Delivered)
Each command creates a new WORM run directory under `KT_PROD_CLEANROOM/exports/_runs/...` containing:
- `verdict.txt` (one line; paste-safe)
- `certify_report.json` (machine summary)
- `sweep_summary.json` + test logs (from the sweep harness)
- validation reports (receipts/work orders/council packet), if enabled by sweep harness

For client delivery, the operator factory also emits the standard delivery bundle artifacts (ZIP + sha256 + replay wrappers + manifest):
- See `KT_PROD_CLEANROOM/docs/commercial/KT_DELIVERY_BUNDLE_SPEC.md`

## Typical Timeline (planning estimate)
- 1–3 business days once the pinned scope and execution environment (offline, WORM outputs) are ready.

## Pricing Logic (framework; no numbers)
- Fixed fee for a defined pinned scope + optional per-additional-run fee if multiple releases/states are certified.

## Acceptance Criteria
- Repo worktree clean at start of run.
- Law bundle recompute matches `LAW_BUNDLE_FL3.sha256`.
- Suite registry validates; `suite_registry_id` matches expected.
- Sweep harness final status `PASS`.
- In canonical lane: meta-evaluator canonical pass (`PASS`) with HMAC.
- Evidence pack is WORM-correct (no overwrite; no delete).
