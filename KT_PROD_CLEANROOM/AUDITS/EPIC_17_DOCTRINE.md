# EPIC_17 — Suite Pack + Validators Doctrine (FL3)

Status: **BINDING (when law bundle includes this doc + artifacts)**  
Mode: **FAIL-CLOSED · DETERMINISTIC · OFFLINE · ADD-ONLY**  
Scope: **Evaluation tooling + measurement artifacts only** (no runtime/hat mutation)

## One-line mandate
**No fitness claim is admissible unless it is computed from an authorized suite definition and a law-bound validator catalog under a deterministic axis scoring policy.**

## Measurement primitives (law-bound)

### 1) Validator Catalog (`kt.validator_catalog.v1`)
- Canonical list of validator implementations by `validator_id`.
- Validators are deterministic and offline.
- Catalog is content-addressed via `validator_catalog_id` (canonical hash surface).

### 2) Axis Scoring Policy (`kt.axis_scoring_policy.v1`)
- Defines:
  - axes (e.g. `format`, `safety`, `governance`, `task_quality`)
  - gate validator IDs (hard gates)
  - soft validator weights (continuous fitness)
  - verdict thresholds (`PROMOTE` / `HOLD` / `QUARANTINE`)
- Policy is content-addressed via `axis_scoring_policy_id`.

### 3) Suite Definition (`kt.suite_definition.v1`)
- Measurement contract that binds:
  - suite identity (`suite_id`, `suite_version`)
  - cases (prompts + expected behavior + validator IDs)
  - references to the validator catalog + axis scoring policy **by both ref and id**
- Suite is content-addressed via `suite_definition_id`.
- Suite file bytes are hash-bound for authorization via the Suite Registry (EPIC_16).

### 4) Suite Outputs (`kt.suite_outputs.v1`)
- Immutable outputs for a single subject (base or adapter) against a suite.
- Contains per-case `output_sha256` binding to the exact emitted text.
- Content-addressed via `suite_outputs_id`.

### 5) Suite Eval Report (`kt.suite_eval_report.v1`)
- Per-case, per-validator deterministic results.
- `status=PASS` iff all cases pass all validators; else `FAIL`.
- Content-addressed via `suite_eval_report_id`.

### 6) Axis Fitness Report (`kt.axis_fitness_report.v1`)
- Axis rollups + hard gate outcome + verdict decision.
- Content-addressed via `axis_fitness_report_id`.

## Enforcement tool (deterministic)
`python -m tools.eval.run_suite_eval`:
- Inputs: `kt.suite_definition.v1` + `kt.suite_outputs.v1`
- Loads validator catalog + scoring policy from the suite definition refs and verifies ids match (fail-closed).
- Writes WORM outputs:
  - `suite_eval_report.json`
  - `axis_fitness_report.json`

## Non-negotiable invariants
- **No network I/O** in suite evaluation tools.
- **No wall-clock entropy** in hashed surfaces (use FL4 deterministic time contract semantics).
- **Create-once or byte-identical no-op** for evidence artifacts (WORM).
- **Suite authorization remains EPIC_16**: suites consumed by admission/tournament must be in `SUITE_REGISTRY_FL3.json`.

## What EPIC_17 explicitly does *not* do
- It does not modify factory training, tournament law, merge law, or promotion spine behavior.
- It does not run models; it evaluates *already-produced* suite outputs deterministically.

