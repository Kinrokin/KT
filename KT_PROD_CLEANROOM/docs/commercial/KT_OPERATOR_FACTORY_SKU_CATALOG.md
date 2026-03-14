# KT Operator Factory — SKU Catalog (v1)

This catalog maps the **operator factory lanes** to **commercial SKUs**.
It is intentionally mechanical: an SKU is accepted only when the referenced **WORM run directory** and **delivery bundle artifacts** exist and validate.

Documentary-only commercial surface.
Current-tense claims in this document are bound by `KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json`.
Active truth source: `kt_truth_ledger:ledger/current/current_pointer.json`.
Verifier source: `KT_PROD_CLEANROOM/reports/public_verifier_manifest.json`.

## What clients buy (plain language)
- **Risk reduction** via governed, repeatable verification runs (not ad-hoc testing).
- **Audit defensibility** via replayable evidence, hash receipts, and tamper-evident run roots.
- **Regulatory survivability** via fail-closed gates (no “best effort” runs presented as proof).
- **Board-level reporting inputs** via one-line verdicts + structured summaries.
- **Insurance leverage** via consistent, replayable evidence packs (underwriter-friendly).

## What this is not
- Not legal advice; not a compliance framework authoring service by default.
- Not a promise of “model safety”; it is **evidence about a pinned system state** under a defined scope.
- Not network-based model fetching; operator lanes are offline by default.

## Shared deliverable contract (applies to every SKU)
Every run writes a new WORM run directory under:
- `KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/<UTC_TS>_<SKU_OR_PURPOSE>/`

Minimum bundle expectations (exact names may vary by lane; acceptance is based on the lane’s manifest + linter PASS):
- `verdict.txt` (one line; paste-safe)
- `reports/one_line_verdict.txt`
- `evidence/run_protocol.json` (+ optional `.md`)
- `evidence/secret_scan_report.json` (must be `PASS`)
- `delivery/KT_DELIVERY_<run_id>.zip`
- `delivery/delivery_manifest.json`
- `hashes/KT_DELIVERY_<run_id>.zip.sha256`
- `evidence/replay.sh` and `evidence/replay.ps1`

Reference spec:
- `KT_PROD_CLEANROOM/docs/commercial/KT_DELIVERY_BUNDLE_SPEC.md`

## SKU ladder (commercial packaging)
- **Level 1**: `SKU_CERT` (baseline integrity proof)
- **Level 2**: `SKU_CERT` + `SKU_RA` (baseline + adversarial validation)
- **Level 3**: `SKU_CERT` + `SKU_RA` + `SKU_CG` (add drift/regression governance)
- **Level 4**: add `SKU_OVERLAY` (domain overlays: composable scope/policy layers)
- **Level 5**: `SKU_FORGE` (train → validate → promote/block → deliver, governed)

## SKU_CERT — Certification Pack (Point-in-Time Proof)
- **Lane**: `certify.canonical_hmac`
- **Primary command**: `python -m tools.operator.kt_cli --profile v1 certify --lane canonical_hmac`
- **Wiring check (non-audit)**: `python -m tools.operator.kt_cli --profile v1 certify --lane ci_sim`

**Client question answered:** “Can we independently verify the integrity status of this pinned KT system state?”

**Inputs (client/operator)**
- Pinned repo checkout (tag/commit agreed).
- Offline execution environment and permission to write WORM outputs under `KT_PROD_CLEANROOM/exports/_runs/**`.
- For canonical lane: env vars `KT_HMAC_KEY_SIGNER_A` and `KT_HMAC_KEY_SIGNER_B` present (presence/length checks only; never printed).

**Deliverables**
- One WORM run directory with:
  - sweep PASS/FAIL evidence (`sweeps/<id>/sweep_summary.json` + logs)
  - delivery ZIP + sha256 + replay wrappers
  - `delivery/delivery_manifest.json` containing pins + verdict + artifact sha256 roots

**Acceptance criteria (mechanical)**
- `evidence/secret_scan_report.json` is `PASS`.
- delivery linter is `PASS` (see `delivery/delivery_lint_report.json` if present).
- sweep summary is `PASS` for the agreed sweep id(s).
- pinned anchors recorded in the delivery manifest match the contract (sealed tag/commit, law bundle hash, suite registry id, determinism anchor).

**Typical timeline**
- 1–3 business days once environment + keys are ready and a pinned scope is agreed.

**Pricing logic (framework; no numbers)**
- Fixed base fee for the defined scope + per-run pricing if multiple certified states are requested.
- Optional expedite fee for <48h turnaround.

## SKU_RA — Red Assault (Adversarial Evaluation + Failure Library)
- **Lane**: `red_assault.v1`
- **Command shape**: `python -m tools.operator.kt_cli --profile v1 red-assault --pack-id <id> --pressure-level <low|med|high> --sample-count <n> --seed <int>`

**Client question answered:** “How does this system behave under adversarial pressure (prompt injection, format breaks, policy theater) within a bounded pack?”

**Inputs**
- A pinned repo checkout and an agreed red-assault pack id (hash-referenced / governed).
- Agreed pressure level + sample count (bounded; no open-ended fuzzing).

**Deliverables**
- Standard delivery bundle plus:
  - `reports/red_assault_summary.json`
  - `reports/failure_taxonomy.json`
  - `reports/top_failures.jsonl`

**Acceptance criteria**
- secret scan `PASS`, delivery linter `PASS`.
- red-assault reports present and schema-valid for the lane.
- any excluded dual-use content is referenced by hash only (no payload embedding in canonical surfaces).

**Typical timeline**
- +2–5 business days depending on pack size, sampling, and review cadence.

**Pricing logic**
- Base SKU_RA fee + scale factor for `sample_count` and pressure level (compute + analysis).

## SKU_CG — Continuous Governance (Drift + Regression Diffs Over Time)
- **Lane**: `continuous_gov.v1`
- **Command shape**: `python -m tools.operator.kt_cli --profile v1 continuous-gov --baseline-run <path> --window <N|list> --thresholds <json>`

**Client question answered:** “Did anything regress or drift across time/runs, and can we prove the answer with artifacts?”

**Inputs**
- Baseline run directory (must be under allowed WORM roots).
- Window definition (N recent runs or explicit run list).
- Thresholds (metric deltas; fail-closed on NaNs).

**Deliverables**
- Standard delivery bundle plus:
  - `reports/drift_report.json`
  - `reports/regression_report.json`
  - `reports/trend_snapshot.json`
  - `reports/diff_summary.md`

**Acceptance criteria**
- secret scan `PASS`, delivery linter `PASS`.
- baseline run manifests readable and schema-compatible with current lane.
- trend computations contain no NaNs; mismatches fail-closed.

**Typical timeline**
- Setup: 1–2 days; ongoing: weekly/monthly cadence with fixed runbooks.

**Pricing logic**
- Retainer-style cadence pricing + per-run fee; optional quarterly “deep dive” report.

## SKU_OVERLAY — Domain Overlay Pack (Composable Scope + Policy Layers)
- **Lane**: `overlay_apply.v1`
- **Command shape**: `python -m tools.operator.kt_cli --profile v1 overlay-apply --overlay-id <id> [--overlay-id <id> ...] --target-lane <certify|red_assault|continuous_gov|forge> --strict`

**Client question answered:** “Can we tailor evaluation scope and reporting to our jurisdiction/industry constraints without changing the core system?”

**Inputs**
- Overlay ids from the overlay registry (hash-verified):
  - `KT_PROD_CLEANROOM/AUDITS/OVERLAYS/OVERLAY_REGISTRY.json`

**Deliverables**
- Standard delivery bundle plus:
  - `reports/overlay_resolution.json`
  - `reports/overlay_diff.json`
  - `reports/overlay_effect_summary.json`

**Acceptance criteria**
- strict mode: missing overlay id or hash mismatch fails-closed.
- overlay resolution report lists every applied overlay id + sha256.

**Typical timeline**
- 1–3 business days per overlay (including review + acceptance of the overlay’s scope).

**Pricing logic**
- Per-overlay fee + optional bundle discount for a defined vertical pack set.

## SKU_FORGE — Adapter Forge (Train → Validate → Promote/Block → Deliver)
- **Lane**: `forge.v1`
- **Command shape**: `python -m tools.operator.kt_cli --profile v1 forge --failure-source <path> --holdout-pack <path> --train-config <json|path> --adapter-id <id> --seed <int>`

**Client question answered:** “Can we remediate known failures via controlled adaptation without breaking governance, and can we prove promotion decisions mechanically?”

**Inputs**
- Failure source (from a prior run’s exemplars or pressure outputs).
- Holdout pack definition (pinned).
- Training config (seeded; hash-backed).
- Offline base model + adapter storage if real training is enabled; otherwise stub rehearsal is used.

**Deliverables**
- Standard delivery bundle plus:
  - `forge/train_config.json`
  - `forge/train_data_manifest.json`
  - `forge/adapter_metadata.json`
  - `forge/before_after_metrics.json`
  - `forge/promotion_gate.json`
  - `reports/forge_summary.json`

**Acceptance criteria**
- Promotion is **blocked** if any required dependency gate fails (promotion is constitutional, not discretionary).
- Stub mode is acceptable only when explicitly labeled `PRACTICE` / `REHEARSAL` in the run protocol.

**Typical timeline**
- Rehearsal (stub): 2–5 business days.
- Real training + validation: 2–6+ weeks depending on compute, data readiness, and the number of iterations.

**Pricing logic**
- Per-iteration pricing (baseline → train → validate → gate → deliver), plus pass-through compute/hardware if applicable.
