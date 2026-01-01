# W4.5 C016 Verification — Teacher/Student & Curriculum Boundary (One-Way, Receipt-Only)

Concept: **C016 — Teacher/Student & Curriculum Boundary**

Scope:
- Adds a schema-validated curriculum package ingestion boundary that produces **hash-only receipts** and refusal codes.
- Enforces **Teacher → Student one-way flow** by rejecting Student-derived fields, policy overrides, and executable-content fields.
- No learning, no providers, no network.

## Files (Implementation)

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/curriculum/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/curriculum/curriculum_schemas.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/curriculum/curriculum_ingest.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/curriculum/tests/test_curriculum_boundary.py`

## Wiring / Topology Evidence

- Runtime allowlist + organ mapping + Import Truth matrix:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` (curriculum root allowlisted; organ = Curriculum Boundary)
- Canonical execution path dispatch (Spine-only):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`
- Execution path proof:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C016_EXECUTION_PATH_PROOF.md`

## Constitutional Guarantees (C016)

- **One-way boundary (Teacher → Student only):**
  - Unknown/forbidden fields are rejected with explicit refusal codes (student→teacher markers, policy overrides, executable-content fields).
- **Receipt-only / no content persistence:**
  - Outputs contain only hashes + refusal codes; no curriculum contents are logged or written.
- **No runtime learning / no training artifacts:**
  - External training frameworks are forbidden (guarded + refusal path in ingestion).
- **No network:**
  - Tests hard-block `socket` and prove ingestion does not attempt network calls.
- **No cross-organ invocation:**
  - Ingestion does not import or invoke Council (C014) or Cognition (C015).

## Tests (Low-RAM, No Bytecode)

Ran with `PYTHONDONTWRITEBYTECODE=1`.

- C016 tests:
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/curriculum/tests -p "test_*.py"` → **PASS** (8 tests)
- V2 baseline tests (regression check):
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests -p "test_*.py"` → **PASS** (21 tests)

## S3 Constitutional Guard

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C016.md` → **PASS**

