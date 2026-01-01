# C016 Execution Path Proof — Curriculum Boundary (Spine-only)

This is a **static proof** (no execution) that curriculum ingestion is reachable only through the canonical runtime path:

**Entry → Spine → CurriculumIngest.accept_payload(...)**

## Canonical Entry → Spine

- Entry loads the runtime registry, installs Import Truth, asserts invariants, then resolves the canonical Spine callable:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py:19`

## Spine-only dispatch for curriculum ingestion

- Spine defers organ imports until after Import Truth installation and invariants assertion:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py:67`
- Spine matches curriculum packages by schema ID:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py:403`
- Spine calls curriculum ingestion via `CurriculumIngest.accept_payload(...)` (receipt-only; no persistence):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py:409`
- Spine emits a hash-only governance event for ingestion (no curriculum contents):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py:420`

## No alternate entrypoints

- No `__main__` guards were added under runtime `src/` for C016.
- Import Truth allows `curriculum/` only as a runtime root declared in:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json:18`

