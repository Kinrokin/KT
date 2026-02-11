# EPOCH_EXECUTION_FLOW (forensic)

This document maps the concrete growth-lane execution flow in code: plan → crucible runner subprocess → artifacts → aggregation → epoch summary.

Scope: `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py` plus the crucible runner entrypoints.

## 1) Canonical entrypoint

- Canonical API: `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py::run_epoch_from_plan(...)`
  - Calls `run_epoch(...)` with:
    - `plan_path`
    - `resume` (default `False` for canonical tooling invocation)
    - `artifacts_root` (optional override; otherwise defaults to growth artifacts root)
    - `mode` (`normal|shadow|salvage`) which toggles salvage behavior.

There are also thin CLIs in:
- `KT_PROD_CLEANROOM/tools/growth/run_epoch_escalation.py`
- `KT_PROD_CLEANROOM/tools/growth/run_autonomous_escalation.py`

## 2) Plan loading and crucible list

In `run_epoch(...)`:
- Loads plan via `_load_plan(plan_path)`.
- Pulls:
  - `kernel_target = plan.kernel_identity.kernel_target`
  - `plan.crucible_order` (ordered list of crucible IDs)
  - `plan.crucible_specs[cid]` (relative path to spec file)
- Reads each crucible spec file and validates budgets against the plan caps.

## 3) Epoch directory (epochs/<epoch_id>/...)

`run_epoch(...)` chooses an epoch root:
- `base_root = artifacts_root if provided else (_growth_artifacts_root() / "epochs")`
- `epoch_root = base_root / plan.epoch_id`

Within each epoch, each crucible gets an epoch-local directory:
- `run_dir = epoch_root / <crucible_id>`
- Epoch-local files:
  - `run_record.json`
  - `stdout.json` (stdout captured from the runner subprocess)
  - `stderr.log` (stderr captured from the runner subprocess)

These files are always written even on FAIL_CLOSED so the epoch is diagnosable.

## 4) Subprocess invocation (C019 crucible runner)

For each crucible:
- Builds a command via `_runner_command(...)` unless `runner_cmd_override` is provided.
- Then launches `_run_subprocess_capped(...)` which:
  - uses `subprocess.Popen(...)`
  - caps stdout/stderr bytes
  - caps wall-clock time
  - caps RSS (best-effort via `psutil` if available)

The command default points at:
- `KT_PROD_CLEANROOM/tools/growth/crucible_runner.py` (a wrapper that imports and calls `crucibles/crucible_runner.py::run_crucible_file(...)`).

## 5) Run-root (c019_runs/<kernel>/<run_id>/...)

After the subprocess returns, the orchestrator expects the crucible runner to have created a per-run artifact directory (run root):

- `run_root = _growth_artifacts_root() / "c019_runs" / kernel_target / <run_id>`

This directory is required for non-coverage kernels because it must include `crucible_coverage.json` (and potentially governance artifacts).

Fail-closed invariants in `epoch_orchestrator`:
- If `run_root` does not exist → epoch FAIL_CLOSED.
- If `run_root/crucible_coverage.json` is missing → epoch FAIL_CLOSED.

## 6) Aggregation and epoch summary

`run_epoch(...)` aggregates per-crucible outcomes into a returned `summary` dict (also written on disk as part of the epoch artifacts).

The summary includes:
- `epoch_id`, `epoch_profile`
- `kernel_identity.kernel_target`
- `crucibles_total/passed/failed`
- per-crucible `run_id` and `outcome`

## 7) Where "pressure" lives

Growth lane "pressure" is currently expressed as:
- running specific crucibles (milestones) and requiring PASS
- running pressure epochs and requiring an OPERATIONAL verdict
- enforcing coverage evidence via `crucible_coverage.json`

It is not (in the current code paths) selecting between competing adapters; it is enforcing contract-based pressure on the growth system itself.

