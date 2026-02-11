# CRUCIBLE_OUTPUT_SCHEMA (forensic)

This document enumerates what the growth crucible runner emits, where it is written, and what is used as a learning/pressure signal.

Scope:
- `KT_PROD_CLEANROOM/tools/growth/crucible_runner.py` (subprocess wrapper)
- `KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py` (core runner)
- `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py` (expects and validates outputs)

## 1) Subprocess wrapper output (epoch-local stdout.json)

`KT_PROD_CLEANROOM/tools/growth/crucible_runner.py` prints JSON to stdout (captured by the orchestrator and written to epoch-local `stdout.json`).

Shape: a JSON array of records, each including:
- `run_id`
- `crucible_id`
- `kernel_target`
- `outcome`
- `output_contract_pass`
- `replay_status`, `replay_pass`
- `governance_status`, `governance_pass`
- `artifacts_dir` (string path)
- `notes`

The wrapper intentionally does not print kernel stdout/stderr.

## 2) Epoch-local logs (always present)

Created by `epoch_orchestrator.run_epoch(...)` per crucible:
- `.../epochs/<epoch_id>/<crucible_id>/stdout.json`
- `.../epochs/<epoch_id>/<crucible_id>/stderr.log`
- `.../epochs/<epoch_id>/<crucible_id>/run_record.json`

These are the primary forensic surface when a run fails before per-run artifacts are materialized.

## 3) Per-run artifacts directory (run_root)

Created by the core runner under:
- `.../c019_runs/<kernel_target>/<run_id>/...`

`epoch_orchestrator` expects this directory to exist and fail-closes when it does not.

Expected files (from the orchestrator’s artifact contract):
- `runner_record.json` (per-run receipt/record)
- `governance_verdict.json` (required by governance kernels; fail-closed if missing)
- `crucible_coverage.json` (required by governance kernels; fail-closed if missing)
- `micro_steps.json` (observability artifact emitted even on FAIL_CLOSED)
- `_runtime_artifacts/state_vault.jsonl` (optional depending on kernel)

## 4) crucible_coverage.json

Written by `KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py` as:
- `cov_path = run_root / "crucible_coverage.json"`

The file contains a structured coverage proof object (keys observed in code):
- `expected`:
  - `thresholds` (min unique domain/subdomain/microdomain, etc.)
  - `rotation_ruleset_id`
- `observed`:
  - `domains`, `subdomains`, `microdomains`, `reasoning_modes`, `modalities`, `tools`
  - `counts` (unique_* counts, cross-domain edges, distances, paradox events)
  - `dominance` (entropy, top share, etc.)
- `sequence` (domain sequence)
- `proof.receipts[]` (hash receipts)
- `proof.fail_closed` (bool)
- `verdict` (coverage_pass / rotation_pass / notes)

Validation behavior (fail-closed):
- In `KERNEL_COVERAGE_BASELINE`, coverage failures are non-gating (printed to stderr).
- In other kernels (including governance baseline), coverage failures raise `RunnerError`.

## 5) micro_steps.json

Written by the core runner as `run_root/micro_steps.json` with keys:
- `schema` (MICRO_STEPS_V1)
- `run_id`, `crucible_id`, `kernel_target`
- `steps[]` (MAP/CONSTRAIN/RESOLVE/EVAL)
- `hashes` (prompt_hash, head_hash, ledger_hash, stdout_hash)

This is an observability surface, not a selection score.

## 6) PASS/FAIL signal used for pressure

At the growth lane level, the selection/pressure signal is:
- crucible outcomes (PASS/FAIL/FAIL_CLOSED/INFEASIBLE/REFUSE)
- plus the presence and validity of `crucible_coverage.json` under the required kernels.

There is no multi-axis “cognitive trait vector” produced by crucibles in this lane; the multi-field coverage report is evidence, not a trait embedding.

