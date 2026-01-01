# C001 INVARIANTS SUBSTRATE SEAL (V2)

Sealed at (UTC): 2025-12-27T11:13:22Z

## Declaration (Non-Negotiable)

C001 (Invariants Gate Module) is hereby sealed as a non-negotiable substrate of the KT V2 runtime.

Any change to C001 (including its call-sites, its enforcement surface, or any file listed as part of the C001 substrate set) requires:

1) explicit new constitutional authorization  
2) a new `V2_RELEASE_MANIFEST.jsonl` entry for the changed file(s)  
3) a new concept-scoped verification report proving all invariants remain PASS  

No hotfixes. No silent edits. Fail-closed.

## Sealed Artifacts

Release manifest (append-only):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

Verification evidence (must remain unchanged unless reauthorized):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C001_VERIFICATION.md`
- `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C001_VERIFICATION.md`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT.md`

Plan (historical intent; immutable once sealed):
- `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_C001_PLAN.md`

## Invariants Enforced (C001 Surface)

The C001 gate is fail-closed. If any invariant is violated, the system must halt by exception.

Invariant IDs (implemented by `src/core/invariants_gate.py`; see verification doc for details):

- C001-CTX-001: Context shape strict (required keys; no unknown top-level keys)
- C001-SCHEMA-001: Schema binding (schema_id + schema_version_hash must match `schemas/state_vault_schema.py`)
- C001-CONST-001: Constitution binding (constitution_version_hash must match `core/invariants_gate.py`)
- C001-ENV-001: Envelope contract (exactly `{"input": <str>}`)
- C001-SIZE-001: Input size bound (max 64KB UTF-8)
- C001-SIZE-002: Context size bound (max 128KB canonical JSON)
- C001-PURITY-001: Raw-content key markers forbidden in context
- C001-WALL-001: Training/runtime wall (fail if training-marker modules are loaded)
- C001-WALL-002: Provider SDK wall (fail if provider SDK modules are loaded)
- C001-NEGSPACE-001: Negative Space shadowing prevention (fail if runtime namespaces are resolved from non-runtime paths)
- C001-SECRETS-001: Secrets locator hard stop (prefix scan of loaded runtime modules)

## Change Control

Editing any of the following without new authorization is prohibited:

- C001 runtime module: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py`
- C001 call-site: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/entrypoint.py`
- C001 tests: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py`
- S3 guard: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py`

