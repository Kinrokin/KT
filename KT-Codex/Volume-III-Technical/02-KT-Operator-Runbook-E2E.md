---
title: "KT Operator Runbook (E2E) - V2"
volume: "Volume III - Technical Stack and Pipeline"
chapter: "Chapter 2"
author_role: "Program Manager"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:INTERNAL:KT_CLIENT_READY_PACK", "SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Volume III - Technical Stack and Pipeline
### Chapter 2 - KT Operator Runbook (E2E)

#### Chapter intent (plain-English)
This runbook is the operator-facing, fail-closed, offline workflow to execute KT end-to-end and produce auditor-grade evidence. It is a client of existing tools and must not mutate sealed anchors or governance surfaces. [SRC:USER_PACKET]

#### Pins (immutable anchors; read-only verification)
These anchors are treated as immutable facts for KT V1. Operators must verify them read-only and must not modify them as part of routine operations. [SRC:NEEDS_VERIFICATION]

- Sealed tag: `KT_V1_SEALED_20260217`
- Sealed commit: `7b7f6e71d43c0aa60d4bc91be47e679491883871`
- Law bundle hash (V1): `cd593dee1cc0b4c30273c90331124c3686f510ff990005609b3653268e66d906`
- Suite registry id (V1): `e7a37cdc2a84b042dc1f594d1f84b4ba0a843c49de4925a06e6117fbac1eff17`
- Determinism expected root hash (V1): `c574cd28deba7020b1ff41f249c02f403cbe8e045cb961222183880977bdb10e`
- Archived authoritative V1 reseal receipt (do not edit): `KT_PROD_CLEANROOM/reports/kt_archive_manifest.json` entry `vault_receipt_epic24_v1_reseal_under_current_law_fix_post_canonical_hmac_20260217t225856z`

#### Evidence posture (plain-English)
Evidence is the deliverable. Every meaningful action must emit WORM artifacts under `KT_PROD_CLEANROOM/exports/_runs/**` (and allowlisted export roots where explicitly permitted). Any write outside allowed roots is a governance defect. [SRC:USER_PACKET]

```text
[Diagram Spec]
type: kt_operator_e2e_runbook_v2
lanes:
  - ci_simulation
  - canonical_hmac
gates:
  - pins_gate
  - preflight_fl4_seal_mode
  - sweep_pre
  - e2e_proof_loop
  - sweep_post
outputs:
  - run_root (WORM)
  - delivery_bundle (zip + sha256)
  - one_line_verdict
```

---

#### A) Go/No-Go checklist (fail-closed)
Plain-English: do not start if any gate is not strictly satisfied.

- Offline only: no network access permitted. [SRC:USER_PACKET]
- No installs: do not add dependencies (no package installs). [SRC:USER_PACKET]
- Clean worktree required: `git status --porcelain=v1` must be empty.
- Sealed anchor check: `git rev-list -n 1 KT_V1_SEALED_20260217` must equal the sealed commit.
- Pin check: `KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256` must match law recompute.
- IO Guard check: FL4 preflight must PASS in guarded mode (violations must be empty).
- Canonical certify check: if running canonical HMAC lane, HMAC signer keys must be present in the environment (never print values; only presence and length). [SRC:USER_PACKET]
- WORM discipline: do not reuse output directories; each run uses a new timestamped run root.

Hard stop conditions:
- Any mismatch of anchors or pins.
- Any attempt to write outside allowlisted roots.
- Any missing required artifact or validator.

---

#### B) Kaggle notebook suite 00-10 map (offline operator view)
Plain-English: this is the recommended offline notebook progression for a clean, repeatable evaluation and certification loop. This chapter is a map; the notebook skeleton is specified in Chapter 6. [SRC:USER_PACKET]

- 00: Environment and inputs (offline assertions, path wiring, no installs).
- 01: Intake manifest (freeze scope, record pins, compute input hashes).
- 02: Base snapshot discovery (local-only, fail-closed if missing).
- 03: Adapter discovery and name mapping (sanitized identifiers; no registry mutation).
- 04: Suite selection (registry-driven; no ad-hoc suites).
- 05: Evaluation run (deterministic seed; evidence root emitted).
- 06: Metamorphic variants (seeded transforms; manifest + hashes).
- 07: Red assault run (report only; no sensitive payloads stored in canonical surfaces). [SRC:USER_PACKET]
- 08: Certification packaging (delivery zip + manifest + hashes).
- 09: Replay check (second run, byte-identical evidence roots where required).
- 10: Operator handoff (verdict line + pointers + acceptance checklist).

---

#### C) Adapter lifecycle (factory lane; governed)
Plain-English: adapters are treated as governed artifacts with explicit admission, evaluation, and promotion states. [SRC:USER_PACKET]

- Intake:
  - Inputs: dataset pointer(s), constraints, suite registry id, target base snapshot id. [SRC:USER_PACKET]
  - Outputs: intake manifest, dataset hash manifest, plan of record.
- Train (optional; offline-safe):
  - Rule: training outputs must be written under new run roots and must not mutate certified outputs. [SRC:USER_PACKET]
  - Output: adapter artifact directory + hash manifest.
- Evaluate:
  - Rule: evaluation uses the suite registry and produces schema-bound reports.
  - Output: suite results, risk register deltas, one-line verdict.
- Promote / Quarantine:
  - Rule: promotion is a governed operation; do not update registries without explicit governed step. [SRC:USER_PACKET]
  - Output: promotion receipt or quarantine receipt (hash-bound).

---

#### D) Router hat-plane pattern (runtime demo surface)
Plain-English: hat-plane demos are read-and-run surfaces that demonstrate orchestration and routing receipts without mutating the certified factory lane. [SRC:USER_PACKET]

- Guardrails:
  - Refuse writes outside the run root.
  - Refuse any attempt to mint receipts or modify law surfaces unless explicitly authorized by a separate sealing work order. [SRC:USER_PACKET]
- Evidence:
  - Router run report (schema-bound if available).
  - Routing receipts (hash-bound).
  - One-line verdict with run root pointer.

---

#### E) Max-pressure dials (safe, bounded)
Plain-English: these dials increase evaluation coverage while staying deterministic and auditable. [SRC:USER_PACKET]

- Repeats: increase repeats per case to measure variance (must remain seeded).
- Metamorphic transforms: increase variants per case (whitespace, punctuation, format, order perturbations) while keeping payloads safe and non-sensitive.
- Tournament settings: increase contenders, rounds, and cross-suite coverage.
- Denial policy: tighten fail-closed gating on missing artifacts, schema mismatches, and drift.

---

#### F) Concrete E2E scenarios (health, finance, legal) - structure only
Plain-English: these are scenario templates; operators must supply domain data under explicit boundaries. No domain-specific sensitive payloads are stored in canonical surfaces. [SRC:USER_PACKET]

- Health scenario (bounded):
  - Objective: evaluate assistant behavior under privacy constraints and safety constraints for medical-adjacent guidance. [SRC:USER_PACKET]
  - Inputs: de-identified case summaries, policy boundaries, allowed disclaimers.
  - Outputs: evaluation report, refusal quality summary, risk deltas.
- Finance scenario (bounded):
  - Objective: evaluate for non-advisory posture, correct risk framing, and stable refusal behavior when asked for forbidden actions. [SRC:USER_PACKET]
  - Inputs: synthetic transaction summaries, compliance constraints, allowed disclaimers.
  - Outputs: evaluation report, policy adherence signals, escalation notes.
- Legal scenario (bounded):
  - Objective: evaluate for non-legal-advice posture, accurate uncertainty handling, and consistent citation stubs. [SRC:USER_PACKET]
  - Inputs: synthetic fact patterns, jurisdiction stubs, allowed disclaimers.
  - Outputs: evaluation report, citation stub coverage, refusal and escalation metrics.

---

#### G) Data needed to evaluate + gaps (operator checklist)
Plain-English: evaluation quality is limited by what is provided. Record what is missing instead of guessing. [SRC:USER_PACKET]

Required (minimum):
- System identifier (commit SHA or sealed tag).
- Suite registry id and suite selection.
- Determinism anchor (expected root hash).
- Dataset pointers and dataset hash manifest(s) (local paths and sha256).
- Adapter pointers (local paths and sha256) if adapters are evaluated.

Common gaps to record explicitly:
- Missing base snapshot (offline-only constraint).
- Missing HMAC keys for canonical lane certification.
- Missing validator schemas or registry wiring.

---

#### H) Replay instructions + acceptance criteria (copy-ready)
Plain-English: a third party should be able to run these offline and reach the same PASS/FAIL outcome. [SRC:USER_PACKET]

Baseline verification:
```text
git status --porcelain=v1
git rev-list -n 1 KT_V1_SEALED_20260217
cat KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256
python -m tools.verification.run_sweep_audit --sweep-id OPERATOR_VERIFY
```

Operator CLI (client of tools):
```text
python -m tools.operator.kt_cli --profile v1 status
python -m tools.operator.kt_cli --profile v1 certify --lane ci_sim
python -m tools.operator.kt_cli --profile v1 certify --lane canonical_hmac
python -m tools.operator.kt_cli --profile v1 hat-demo
python -m tools.operator.kt_cli --profile v1 report --run <RUN_DIR>
```

Acceptance criteria:
- Worktree remains clean before and after operator runs.
- Run roots are new per invocation and are WORM-safe (no overwrites).
- Sweeps PASS (CI simulation expected-fail behavior must match harness rules).
- Preflight PASS under IO Guard with zero violations.
- Delivery bundle includes: verdict line, sweep summaries, hashes, and replay instructions.

#### Sources (stubs)
- [SRC:INTERNAL:KT_CLIENT_READY_PACK]
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]
