# EVALUATION_LOGIC_MAP (forensic)

This document answers: what evaluation logic exists, what it outputs (boolean vs score vs multi-axis), and what downstream decisions consume it.

## 1) Factory lane evaluation (FL4 MRT-0)

### 1.1 Eval report v2 (utility floor + probes)
- Schema validator: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/fl3_factory_eval_report_v2_schema.py`
- Schema file: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.factory.eval_report.v2.json`
- Output file (job dir): `eval_report.json`

Signal types:
- Scalar score: `utility_floor_score` (float in [0,1])
- Boolean gate: `utility_floor_pass`
- Boolean gate: probe agreement enforced by `probe_policy.fail_on_disagreement`

This is “numeric metrics exist”, but it is not a multi-axis trait vector.

### 1.2 Signal quality
- Producer: `KT_PROD_CLEANROOM/tools/training/fl3_factory/signal.py::build_signal_quality(...)`
- Schema: `kt.signal_quality.v1`

Signal types:
- `risk_estimate` (float)
- `governance_strikes` (int)
- `status` (string)

Used for gating tournament entrants and deriving fitness region.

### 1.3 Fitness region (A/B/C)
- Producer: `KT_PROD_CLEANROOM/tools/training/fl3_factory/derived.py::compute_fitness_region(...)`
- Output: `fitness_region.json` (`kt.fitness_region.v1`)

Signal type:
- categorical region A/B/C derived from risk/strikes and immune snapshot counts.

Used as a hard precondition for promotion in `promote.py`.

## 2) Growth lane evaluation (crucibles + coverage)

### 2.1 Crucible outcomes
- Produced by the crucible runner (PASS/FAIL/FAIL_CLOSED/etc.)
- Aggregated by `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py::run_epoch(...)`

Signal type:
- primarily categorical outcomes + fail-closed contract checks.

### 2.2 Coverage validation
- Produced as `crucible_coverage.json` (multi-field evidence)
- Validated by coverage validator; non-gating only in `KERNEL_COVERAGE_BASELINE`

Signal type:
- pass/fail gating of coverage proof for governance kernels.

## 3) Policy-C “pressure tensor” (multi-axis exists, but is not a selection surface here)

- `KT_PROD_CLEANROOM/policy_c/pressure_tensor.py` defines `kt.policy_c.pressure_tensor.v1` with axes:
  - `time`, `universe`, `language`, `hop`, `step`, `paradox`, `puzzle`

This is a multi-axis structure, but this audit does not find it used as the primary factory selection metric in FL4 MRT-0. It is a defined signal type that may be used by other lanes or future milestones.

## 4) FL3.2 multi-axis cognitive fitness (separate lane)

The repo contains tools/schemas for multi-axis “cognitive fitness” receipts (anchors, discovery battery, evidence hashes).

Key point for forensic truth:
- This lane exists and is schema-bound.
- It is not the surface used to promote FL4 MRT-0 policy-bundle packages (promotion is based on eval_report v2 + trace + fitness_region).

