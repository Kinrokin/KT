# W5.0 C019 Verification — Crucible DSL + Runner (Tooling-Only)

Concept: `C019` — Crucible DSL + Runner

Scope proven here (tooling-only):
- Declarative crucible specs (`.yaml` / `.json`) are schema-validated and reject unknown fields (fail-closed).
- Deterministic hashing exists for crucible specs, budgets, and run IDs.
- Runner invokes kernels only via `subprocess` and passes exactly `{"input":"<string>"}` to the kernel via stdin.
- Runner enforces external caps (time, stdout/stderr bytes, memory best-effort via RSS) fail-closed.
- Runner writes append-only run ledger + per-run artifact directories.

## Implementation Files
- `KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_dsl_schemas.py`
- `KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_loader.py`
- `KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py`

## Ledger / Artifacts
- `KT_PROD_CLEANROOM/tools/growth/ledgers/c019_crucible_runs.jsonl`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/c019_runs/`

## Proof Artifacts
- `KT_PROD_CLEANROOM/tools/growth/docs/C019_EXECUTION_PATH_PROOF.md`
- `KT_PROD_CLEANROOM/tools/growth/docs/CONSTITUTIONAL_GUARD_REPORT_C019.md`

## Tests (Low-RAM)
Command executed:
- `python -m unittest -q KT_PROD_CLEANROOM/tools/growth/crucibles/tests/test_crucible_runner.py`

Result:
- PASS

Notes:
- These unit tests validate schema fail-closed behavior and runner cap enforcement without running a real kernel.
