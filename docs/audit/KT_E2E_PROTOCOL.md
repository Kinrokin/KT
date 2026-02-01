# KT E2E PROTOCOL (canonical → seal → scale)

This is the “be-all/end-all” protocol for taking the repository from “current state” to a **repeatable, audit-grade, fail-closed E2E** under **FL4 MRT-0 (AdapterType.A-only)**.

It is grounded in concrete repo surfaces:
- Audit maps: `docs/audit/*_MAP.md` (this directory)
- Canonical factory runner: `KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py`
- Canonical growth orchestrator: `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py`
- Canonical seal runner: `KT_PROD_CLEANROOM/tools/verification/preflight_fl4.py`

---

## 0) Non‑negotiables (binding)

1) Fail‑closed is law.
- Any missing artifact, schema mismatch, hash mismatch, or probe disagreement must halt (non‑zero exit).
- Debugging may **surface cause**, but may never bypass gates.

2) Repo is frozen unless the comprehensive audit passes.
- “Fixing” is not allowed during the seal run.
- Only add‑only changes (schemas/tools/tests/docs) are allowed; no edits to frozen organs (spine/router/StateVault core/SRR‑AIR schema heads/runtime registry schema).

3) Canonical lane is **MRT‑0 AdapterType.A-only** (policy bundles, not weights).
- Canonical runs must hard‑fail if weight artifacts appear (e.g., `*.safetensors`, `*.pt`, `*.bin`, `*.ckpt`, `*.onnx`, `*.gguf`, etc.).

4) Preflight must run full battery and must fail on dirty repo.
- The canonical seal runner enforces clean tree via `git status --porcelain` inside `KT_PROD_CLEANROOM/tools/verification/preflight_fl4.py`.

---

## 1) Ground truth (where we are right now)

### 1.1 What is wired today (already real)

Factory lane (FL4 MRT‑0):
- Job directory shape + required artifacts are enforced in `KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py`.
- Hypothesis “genotype” is policy bundles (`kt.policy_bundle.v1`) emitted by:
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/train.py`
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/hypotheses.py`
- Eval emits `kt.factory.eval_report.v2` with:
  - `utility_floor_score`, `utility_floor_pass`
  - `metric_bindings[]`, `metric_probes[]`, `probe_policy`
  - schema validation in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/fl3_factory_eval_report_v2_schema.py`
- Promotion is atomic and content-addressed:
  - `KT_PROD_CLEANROOM/tools/verification/fl4_promote.py`
  - promoted index schema `kt.promoted_index.v1`
- Determinism artifacts exist and are schema-bound:
  - `kt.supported_platforms.v1` in `KT_PROD_CLEANROOM/AUDITS/FL4_SUPPORTED_PLATFORMS.json`
  - `kt.determinism_contract.v1` in `KT_PROD_CLEANROOM/AUDITS/FL4_DETERMINISM_CONTRACT.json`
  - canary runner in `KT_PROD_CLEANROOM/tools/verification/fl4_determinism_canary.py`

Growth lane:
- Canonical execution API: `run_epoch_from_plan` in `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py`.
- Crucible runner writes per-run coverage: `crucible_coverage.json` in `KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py`.
- Growth E2E gate exists: `KT_PROD_CLEANROOM/tools/verification/growth_e2e_gate.py`.

Seal runner:
- `KT_PROD_CLEANROOM/tools/verification/preflight_fl4.py` runs:
  - temple tests + cleanroom tests (pytest)
  - meta evaluator + red assault + rollback drill
  - growth gate
  - determinism canary
  - one sovereign factory job + verify + promote (if PROMOTE)
  - packages evidence into the chosen `--out-dir`

See also:
- `docs/audit/ADAPTER_SYSTEM_MAP.md`
- `docs/audit/EPOCH_EXECUTION_FLOW.md`
- `docs/audit/EVALUATION_LOGIC_MAP.md`

### 1.2 What is *not* guaranteed unless explicitly executed

Some capabilities exist as code/schemas but are not “done” unless they are:
- executed in canonical preflight, and
- present in the evidence pack, and
- verified by meta-evaluator / validators.

Examples of “exists but must be proven by evidence”:
- Breeding and VRR lanes (run_kind paths) — require explicit canonical jobspecs and runtime execution.
- Any “trait vector” beyond:
  - policy-bundle categorical genotype
  - scalar utility floor score
  - categorical fitness region

---

## 2) Canonical E2E step ordering (the only safe order)

This order prevents “semantic trait creep” before the base lane is sealed.

### STEP 1 — Lock the execution surface (prove no silent drift)

**Goal:** same repo + same env contract → same behavior.

Already enforced today (partial):
- Supported platform matrix enforced by `preflight_fl4.py`:
  - Linux required
  - Python version scope required (from `KT_PROD_CLEANROOM/AUDITS/FL4_SUPPORTED_PLATFORMS.json`)

Optional add-only improvement (recommended):
- Add an explicit `kt.env_lock.v1` artifact written by `preflight_fl4.py` capturing required env vars and rejecting forbidden prefixes.
- This is contract, not convention.

Acceptance gates:
- fail if required env var missing
- fail if forbidden env var present
- fail if canonical env var values differ

### STEP 2 — Lane split (canonical vs lab) and enforce mechanically

**Binding:** canonical factory lane = MRT‑0 AdapterType.A-only.

Enforcement hooks:
- meta-evaluator + preflight should fail canonical runs if weight artifacts appear in job_dir or promoted_dir.
- factory train phase already documents MRT‑0 (“no gradients, no weights”) in:
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/train.py`

Acceptance tests (canonical):
- a canonical job_dir cannot contain weight artifacts.
- any lab-lane weight run cannot promote into the canonical promoted index (must be prevented by contract and/or tooling segregation).

### STEP 3 — Job-dir contract + manifests (non-bypassable)

**Goal:** every canonical job_dir is self-describing and integrity-checkable.

Already wired:
- `kt.hash_manifest.v1` and `kt.factory.job_dir_manifest.v1` are written by:
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/manifests.py`
- `run_job.py` enforces required outputs and writes manifests.

Enforcement:
- meta-evaluator recomputes hashes and fails on mismatch.

### STEP 4 — Determinism truthfulness (contracts + canary)

**Goal:** determinism is a scoped, truthful claim.

Already wired:
- `KT_PROD_CLEANROOM/AUDITS/FL4_SUPPORTED_PLATFORMS.json` (schema `kt.supported_platforms.v1`)
- `KT_PROD_CLEANROOM/AUDITS/FL4_DETERMINISM_CONTRACT.json` (schema `kt.determinism_contract.v1`)
- determinism canary tool:
  - `KT_PROD_CLEANROOM/tools/verification/fl4_determinism_canary.py`

Enforcement:
- canary must PASS to allow promotion (canonical rule in FL4 promotion tooling).

### STEP 5 — Metabolic loop proof (causal dependence)

**Goal:** outputs must change when controlled inputs change, while remaining schema-valid and deterministic.

Canonical perturbation that is legal and bounded:
- change jobspec seed
- change dataset manifest seed/content (if your harvest lane exposes a deterministic knob)

Acceptance:
- hash_manifest root hash changes between perturbations
- all schemas still validate

### STEP 6 — Reality veto v0 (utility pack, pinned)

Already wired:
- Utility pack lives at `KT_PROD_CLEANROOM/AUDITS/UTILITY_PACK_V1/*`
- Pack manifest schema: `kt.utility_pack_manifest.v1`
- Factory eval report v2 includes `utility_pack_id` and `utility_pack_hash`
- Meta-evaluator verifies:
  - eval_report binds to the pinned utility pack
  - utility pack file hashes match the manifest

### STEP 7 — Metric ontology binding + independent probes

Already wired in eval_report v2:
- `metric_bindings[]`
- `metric_probes[]`
- `probe_policy.fail_on_disagreement`

Schema enforcement:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/fl3_factory_eval_report_v2_schema.py`

### STEP 8 — Atomic promotion (materialization + re-verify + index update)

Already wired:
- `KT_PROD_CLEANROOM/tools/verification/fl4_promote.py`:
  - pre-verifies job_dir
  - copies into a temp dir
  - writes `promoted_manifest.json`
  - re-verifies promoted copy
  - atomic rename into final content-addressed dir
  - atomic `promoted_index.json` rewrite
  - emits `kt.fl4.promotion_report.v1` (either stdout or `--out`)

Important current truth:
- Promotion updates `promoted_index.json` but there is no separate “ledger append” artifact in this tool today.

### STEP 9 — Anti-theater seeded fuzz suite (deterministic)

Design requirement:
- generate structurally valid but semantically empty/Goodharted variants
- they must fail via utility floor and/or probe disagreement and/or contract violations

Ground truth:
- anti-theater tests exist under `KT_PROD_CLEANROOM/tests/fl3/` (search `test_fl4_anti_theater`).
- Ensure canonical preflight executes them if you require “preflight runs fuzz” as a binding invariant.

### STEP 10 — preflight_fl4 (single command seal runner)

Canonical invocation:
- `python -m tools.verification.preflight_fl4 --out-dir <OUT_DIR> --registry-path <RUNTIME_REGISTRY.json>`

Preflight writes:
- `preflight_summary.json` (schema `kt.fl4.preflight_summary.v1`) — current keys include:
  - `git_sha`, `out_dir`, `registry_path`, `job_id`
- `promotion_report.json` (schema `kt.fl4.promotion_report.v1`) if promotion occurs
- evidence job dir copy at `<OUT_DIR>/job_dir/` (subset of artifacts for offline inspection)
- law and contracts copies:
  - `determinism_contract.json`
  - `supported_platforms.json`
  - `law_bundle.json`
  - `law_bundle_hash.txt`

---

## 3) Recursive pass (“do it again, but perfected”)

### A) Replay from receipts alone (already applicable)

Require deterministic replay of these decisions:
- utility floor verdict
- metric probe agreement verdict
- promotion decision verdict (PROMOTE vs REJECT)

### B) No hidden state audit

Binding tests:
- promotion must not consult outside (job_dir + law bundle + registry + canary artifact)
- meta-evaluator must be offline-safe (no network, no wall clock dependence for scoring)

### C) Canonicalization tests (hash equality across serializations)

Apply now to:
- hash manifests
- job dir manifests
- promoted index
- eval report numeric surfaces

Repo reality today:
- file hashing in `manifests.py` normalizes newlines for UTF‑8 text files; binary files are raw-hashed.

---

## 4) Artifact contracts (schemas) — existing canonical IDs

Factory lane:
- `kt.policy_bundle.v1` — `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.policy_bundle.v1.json`
- `kt.factory.eval_report.v2` — `.../kt.factory.eval_report.v2.json`
- `kt.signal_quality.v1` — `.../kt.signal_quality.v1.json`
- `kt.fitness_region.v1` — `.../kt.fitness_region.v1.json`
- `kt.factory.phase_trace.v1` — `.../kt.factory.phase_trace.v1.json`
- `kt.hash_manifest.v1` — `.../kt.hash_manifest.v1.json`
- `kt.factory.job_dir_manifest.v1` — `.../kt.factory.job_dir_manifest.v1.json`
- `kt.promoted_index.v1` — `.../kt.promoted_index.v1.json`
- `kt.canary_artifact.v1` — `.../kt.canary_artifact.v1.json`

Growth lane:
- Coverage proof is emitted as `crucible_coverage.json` (not currently represented as a JSON Schema ID in the snippet we audited; it is contract-validated by the coverage validator).

Contracts/law pins:
- `kt.supported_platforms.v1` — `.../kt.supported_platforms.v1.json`
- `kt.determinism_contract.v1` — `.../kt.determinism_contract.v1.json`
- `kt.utility_pack_manifest.v1` — `.../kt.utility_pack_manifest.v1.json`

---

## 5) Node list (canonical order) with intents + “semantic axes”

This is a pragmatic “node” ordering that matches real execution surfaces.

### Node 0 — Provider audit (tooling)
- Intent: ensure provider registry/import surfaces are sane (offline-safe).
- Output: provider audit report (in growth gate output).
- Semantic axes: none.

### Node 1 — Growth milestone preflight
- Intent: validate milestone plan + crucible specs + budgets before running.
- Semantic axes: none.

### Node 2 — Growth milestone run (crucibles)
- Intent: enforce coverage + governance constraints on the growth system.
- Outputs:
  - per-run `crucible_coverage.json` + `micro_steps.json`
  - epoch-local logs (`stdout.json`, `stderr.log`) and summary
- Semantic axes: coverage categories (domains/subdomains/tools/etc.) exist as evidence fields; selection is PASS/FAIL gating, not a trait vector.

### Node 3 — Harvest (factory)
- Intent: produce schema-bound dataset manifest (`kt.factory.dataset.v1`).
- Semantic axes: dataset fields only (no trait learning).

### Node 4 — Trace (factory)
- Intent: produce reasoning trace (`kt.reasoning_trace.v1`) as a promotion prerequisite.
- Semantic axes: trace coverage is a hard gate if the eval report demands it.

### Node 5 — Judge (factory)
- Intent: produce `kt.factory.judgement.v1` (rule-based, schema-bound).
- Semantic axes: judgement fields (not a learned trait system).

### Node 6 — Train (MRT‑0; policy bundles)
- Intent: deterministic hypothesis generation; no weights.
- Output: `hypotheses/policy_bundles.jsonl` containing `kt.policy_bundle.v1`.
- Semantic axes (genotype):
  - `prompt_transform_style`
  - `reasoning_directive`
  - `uncertainty_policy`
  - `guardrail_strength`
  - `scoring_bias`

### Node 7 — Eval (utility floor + probes)
- Intent: compute a scalar utility score with hash-bound metric ontology and independent probes.
- Output: `kt.factory.eval_report.v2`.
- Semantic axes: primarily scalar utility score; probe delta is a correctness gate, not an “axis”.

### Node 8 — Signal quality
- Intent: compute simple risk/strike measures for gating.
- Output: `kt.signal_quality.v1`.
- Semantic axes: `risk_estimate`, `governance_strikes` (numeric).

### Node 9 — Derived artifacts (immune/epi/fitness region)
- Intent: compute addendum-derived gating artifacts.
- Output: `kt.fitness_region.v1` plus supporting derived receipts.
- Semantic axes: categorical region A/B/C.

### Node 10 — Promotion decision + materialization
- Intent: PROMOTE vs REJECT and (if PROMOTE) content-addressed package + index update.
- Output: `kt.factory.promotion.v1`, `kt.promoted_index.v1`, `kt.promoted_manifest.v1`.
- Semantic axes: none; this is a governance transaction.

### Node 11 — Meta-verification nodes
- Intent: sovereign enforcement (schema, hashes, SRR/AIR exclusivity, canary, rollback).
- Tools:
  - `tools.verification.fl3_meta_evaluator`
  - `tools.verification.fl3_red_assault`
  - `tools.verification.fl3_rollback_drill`
  - `tools.verification.fl4_determinism_canary`

---

## 6) Coding-agent handoff prompt template (mandatory safety clause)

Copy/paste as the header for any coding agent working in this repo:

```text
KT SAFETY CLAUSE (MANDATORY)
You are working inside KingsTheorem (KT). Treat the repository as FROZEN unless a comprehensive audit explicitly authorizes changes.
Fail-closed is law: add diagnostics to surface cause, but never bypass gates.
Canonical lane is FL4 MRT-0 AdapterType.A-only: no neural weights. Any weight artifacts (e.g., *.safetensors) must hard-fail canonical runs.
Do not change frozen organs: spine/router/StateVault core/SRR-AIR schema heads/runtime registry schema/Policy-C head.
No manual edits to law bundle pins or determinism contracts. Use only the official derivation tooling where present.

COMPREHENSIVE AUDIT (REQUIRED BEFORE CLAIMING PASS/SEALED)
Run the canonical battery (or `tools.verification.preflight_fl4`) and produce an evidence pack that includes:
- preflight_summary.json
- law_bundle.json + law_bundle_hash.txt
- supported_platforms.json + determinism_contract.json
- growth_e2e_gate_report.json
- canary_artifact.json
- meta_evaluator_receipt.json + red_assault_report.json + rollback_drill_report.json
- job_dir evidence copy (OUT_DIR/job_dir)
- promotion_report.json (if promoted)

TASK DISCIPLINE
1) Fix only the smallest root cause. No speculative improvements.
2) Prefer add-only tests that reproduce the failure.
3) Any change must identify: invariants affected, why unavoidable, and which tests prove safety.
```

