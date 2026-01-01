# W4.5 C015 Verification — Cognitive Engine (Deterministic, Bounded, No-Network)

Concept: **C015 — Cognitive Engine (Crucible Engine / cognition sandbox)**

Scope:
- Adds a deterministic, bounded cognition sandbox with `plan()` and `execute()` APIs.
- Integrates cognition into the canonical runtime path **Entry → Spine → CognitiveEngine.(plan|execute)**.

Non-goals (explicitly out of scope for C015):
- No learning / training
- No network or provider SDKs
- No chain-of-thought / reasoning trace return or persistence
- No direct State Vault writes (governance events are emitted only via Spine)

## Files (Implementation)

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_schemas.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/planners/__init__.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/planners/step_planner.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py`

## Wiring / Topology Evidence

- Runtime registry allowlists `cognition` root (mapped to **Crucible Engine**) under runtime import roots:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Spine dispatch is the only runtime entry to CognitiveEngine:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`
- Execution path proof:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C015_EXECUTION_PATH_PROOF.md`

## Constitutional Guarantees (C015)

- **Schemas-first:** request/plan/step_result/result reject unknown fields and enforce explicit bounds (steps/branching/depth, list sizes, string limits).
- **Determinism:** identical inputs yield identical plan/result hashes; no randomness, no time reads.
- **Stateless:** no caches or cross-invocation state; results are derived solely from request/plan hashes.
- **No chain-of-thought leakage:** outputs are hash/ID/numeric summaries only; no reasoning text is returned.
- **No network:** cognition introduces no network code; tests hard-block `socket` to enforce fail-closed behavior.
- **No state mutation:** cognition does not write to the State Vault and does not mutate RuntimeContext (tests assert byte-identical context before/after).
- **Governance discipline:** Spine emits hash-only governance events for cognition plan/execute decisions via `governance.event_logger` (no direct vault writes from cognition).

## Tests (Low-RAM, No Bytecode)

Ran with `PYTHONDONTWRITEBYTECODE=1`.

- C015 tests:
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests -p "test_*.py"` → **PASS** (14 tests)
- V2 baseline tests (regression check):
  - `python -m unittest discover -s KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests -p "test_*.py"` → **PASS** (21 tests)

## S3 Constitutional Guard

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C015.md` → **PASS**
