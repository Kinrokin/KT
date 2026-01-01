# W4.5 C012 Verification — Temporal Fork & Deterministic Replay (Dry-Run, Metadata-Only)

Concept: **C012 — Temporal Fork & Deterministic Replay Engine**

Scope:
- Adds a Temporal organ that can (a) create a metadata-only fork snapshot and (b) perform deterministic replay over a fork reference.
- Integrates Temporal into the canonical runtime path **Entry → Spine → TemporalEngine.(create_fork|replay)** (dry-run; provider-free; no network).

## Files (Implementation)

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_schemas.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/tests/test_temporal_engine.py`

## Wiring / Topology Evidence

- Execution path proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C012_EXECUTION_PATH_PROOF.md`
- Runtime registry updated to include Temporal root + organ mapping + import-matrix row: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Spine invokes TemporalEngine only when `envelope.input` declares one of:
  - `temporal.fork.request`
  - `temporal.replay.request`
  via `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`

## Constitutional Guarantees (C012)

- **Schemas-first:** all temporal request/response payloads are schema-validated; unknown fields rejected; explicit size bounds enforced.
- **Fail-closed:** malformed temporal payloads halt the temporal path; runtime-registry hash mismatch halts (no auto-upgrade/fallback).
- **Determinism:** fork/replay hashes use canonical JSON hashing (`schemas.schema_hash.sha256_json`); identical inputs yield identical hashes.
- **No network:** Temporal organ contains no network code and is covered by the no-network dry-run posture (tests hard-block `socket`).
- **No state mutation:** TemporalEngine is pure (no vault imports, no persistence); `context` is treated as read-only (tested).
- **Governance discipline:** Spine may emit hash-only governance events via `src/governance/event_logger.py`; TemporalEngine does not write to the vault.
- **Import Truth preserved:** Temporal is an explicit allowlisted runtime root with an organ import-matrix row; Spine imports it only after Import Truth is installed.

## Tests (Low-RAM, No Bytecode)

Ran with `PYTHONDONTWRITEBYTECODE=1`.

- V2 suite: `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests -p "test_*.py"` — **PASS** (21 tests)
- C012 tests: `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/tests -p "test_*.py"` — **PASS** (7 tests)

## S3 Constitutional Guard

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C012.md` — **PASS**

