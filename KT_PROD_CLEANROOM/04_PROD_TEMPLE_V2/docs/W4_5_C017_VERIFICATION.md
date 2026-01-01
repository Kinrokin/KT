# W4.5 C017 Verification — Thermodynamics / Budget (Deterministic Global Ceilings)

Concept: **C017 — Thermodynamics / Budget**

Scope:
- Adds deterministic budget allocation + incremental consumption enforcement as a non-intelligent “physics” layer.
- Enforces fail-closed refusals for ceilings (tokens/steps/branches/bytes/duration fuse) before organ actions.
- No network; thermodynamics is pure (no writes/events). Persistence/events remain Spine-owned via C005+C008.

## Files (Implementation)

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/budget_engine.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/budget_schemas.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/duration_fuse.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/memory_meter.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/step_meter.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/token_meter.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/tests/test_budget_engine.py`

## Wiring / Topology Evidence

- Runtime allowlist + organ mapping + Import Truth matrix:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` (thermodynamics root allowlisted; organ = Thermodynamics / Budget)
- Canonical execution path dispatch (Spine-only) + incremental pre-check enforcement:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`
- Execution path proof:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C017_EXECUTION_PATH_PROOF.md`

## Constitutional Guarantees (C017)

- **Global supremacy (single request-domain):** ceilings are allocated once per Spine run and enforced before organ actions.
- **Fail-closed enforcement:** any refusal halts via `SpineError` (no fallback, no silent debt).
- **Deterministic accounting:** allocation/consumption is schema-validated, hash-stable, and order-independent.
- **No nested allocation:** allocation is one-per-domain; pre-checks consume against that single allocation.
- **No network / no provider coupling:** thermodynamics imports no provider SDKs and performs no IO.
- **No state mutation / no persistence:** thermodynamics does not write the State Vault or emit governance events directly.

## Tests (Low-RAM, No Bytecode)

Ran with `PYTHONDONTWRITEBYTECODE=1`.

- C017 tests:
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/tests -p "test_*.py"` → **PASS** (9 tests)
- V2 baseline tests (regression check):
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests -p "test_*.py"` → **PASS** (21 tests)

## S3 Constitutional Guard

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C017.md` → **PASS**
