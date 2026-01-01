# W4.5 C014 Verification — Council Router Engine (Dry-Run, Bounded, Fail-Closed)

Concept: **C014 — Council Router Engine**

Scope:
- Adds a schema-bounded Council Router organ with deterministic `plan()` and bounded `execute()` semantics.
- Integrates Council routing into the canonical runtime path **Entry → Spine → CouncilRouter.(plan|execute)**.

Non-goals (explicitly out of scope for C014):
- No live provider SDKs
- No network calls
- No fabricated model outputs (“no silent mocks”)
- No raw prompt / raw model output persistence

## Files (Implementation)

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/council_schemas.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/council_router.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/base_provider.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/dry_run_provider.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/tests/test_council_router.py`

## Wiring / Topology Evidence

- Runtime registry allowlists `council` root + organ mapping + Import Truth row:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Spine dispatch is the only runtime entry to CouncilRouter:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`
- Execution path proof:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C014_EXECUTION_PATH_PROOF.md`

## Constitutional Guarantees (C014)

- **Schemas-first:** request/plan/result objects reject unknown fields and enforce explicit bounds (provider counts, token caps, string sizes).
- **Fail-closed:** live mode is refused with explicit refusal codes; no “best effort” provider fallback exists.
- **No silent mocks:** DRY_RUN execution returns `status=DRY_RUN` and does not fabricate outputs.
- **No network:** tests hard-block `socket` / `socket.create_connection` and the CouncilRouter path remains green.
- **No state mutation:** CouncilRouter does not write to the State Vault and does not mutate RuntimeContext (tests assert byte-identical context before/after).
- **Import Truth preserved:** `council` is an explicit runtime root with a minimal import matrix row; Council code imports schemas only.

## Tests (Low-RAM, No Bytecode)

Ran with `PYTHONDONTWRITEBYTECODE=1`.

- C014 tests:
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/tests -p "test_*.py"` → **PASS** (12 tests)
- V2 baseline tests (regression check):
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests -p "test_*.py"` → **PASS** (21 tests)

## S3 Constitutional Guard

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C014.md` → **PASS**

