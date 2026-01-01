# W4.5 C001 VERIFICATION - Invariants Gate Module

This file is part of the sealed V2 substrate documentation for C001.

Canonical evidence source (authoritative copy for W4 lab):
- `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C001_VERIFICATION.md`

---

# W4.5 C001 VERIFICATION - Invariants Gate Module

Concept: C001 - Invariants Gate (fail-closed preconditions)  
Phase: W4.5.2 (implementation + unit tests)  
S1 Triple-Diff: NOT TRIGGERED  
S2 State Vault Schema Primacy: GREEN (already implemented)  
S3 Constitutional Guard: GREEN (PASS)

## What Was Implemented

### Runtime module
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py`

Exposes:
- `InvariantsGate.assert_runtime_invariants(context)`

Enforces (fail-closed):
- Context shape: required keys present; no unknown top-level keys
- Schema binding: `schema_id` + `schema_version_hash` must match `schemas.state_vault_schema`
- Constitution binding: `constitution_version_hash` must match `core.invariants_gate.CONSTITUTION_VERSION_HASH`
- Envelope contract: envelope must be `{"input": <str>}` with strict max size (64KB)
- Context size bound: canonical JSON <= 128KB
- Runtime purity: rejects raw-content key markers in context
- Training/runtime wall: fails closed if any training-marker module is loaded (`curriculum`, `epoch`, `dataset`, etc.)
- Provider isolation: fails closed if any provider SDK module is loaded (openai/groq/anthropic/google.generativeai/etc.)
- Negative Space: fails closed if any runtime namespace is sourced from `/tests/`, `/tools/`, or `/docs/` (shadowing prevention)
- Secrets locators (belt-and-suspenders): scans loaded runtime module source prefixes (<=256KB) for private-key blocks or obvious key-literal patterns

### Minimal wiring
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/entrypoint.py`
  - single call-site: `InvariantsGate.assert_runtime_invariants(context)`

NOTE: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/orchestrator.py` does not yet exist in V2; Spine-side wiring is deferred until the V2 Spine module exists.

## Evidence Paths

- Implementation:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/entrypoint.py`
- S2 (schema primacy):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/STATE_VAULT_SCHEMA_SPEC.md`
- S3 (guard + report):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT.md`

## Unit Tests

Test file:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py`

Command run:
- `python KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py`

Results:
- PASS (4 tests)
  - Missing required fields -> FAIL (ContractViolationError)
  - Invalid schema hash -> FAIL (ContractViolationError)
  - Runtime import bleed -> FAIL (ConstitutionalCrisisError)
  - Happy path -> PASS

## Safeguards Status

- S1: Not triggered for C001 (no historical code re-implantation in this concept).
- S2: GREEN (schema primacy artifacts present; no changes required for C001).
- S3: GREEN (guard PASS after each file change; report path above).

