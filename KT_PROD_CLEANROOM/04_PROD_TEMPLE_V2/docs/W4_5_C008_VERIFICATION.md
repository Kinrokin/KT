# W4.5 C008 VERIFICATION — State Vault Append-Only Discipline

Concept ID: C008  
Scope: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/` only  
Posture: append-only, hash-chained, schema-validated, fail-closed, streaming-safe

## What C008 Enforces

- State Vault is append-only JSONL (no mutation/rewrite/compaction).
- Every persisted record is schema-validated via C002 registry (unknown keys/version drift rejected).
- Every record is hash-chained (`parent_hash` continuity) and tamper-evident via replay recomputation.
- Replay is deterministic and fail-closed on any corruption (truncation, reorder, mid-file tamper, drift, hash mismatch).
- Partial writes are treated as corruption (vault must end with newline; otherwise halt).

## Evidence (Code Paths)

Runtime modules:

- Writer (append-only + fsync):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py`
- Replay validator (streaming, fail-closed):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/replay.py`

Constitution binding (hash allowlist; fail-closed):

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/versioning/constitution_registry.py`

Schema authority (pre-existing; not modified by C008):

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py` (S2)
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_registry.py` (C002)

## Canonical Storage Location (Deterministic)

Default (when no explicit path is provided):

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/_state_vault/state_vault.jsonl`

## S1 / S2 / S3 Status

- S1 Triple-Diff: PASS (triggered)
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_DIFF_RATIONALE_C008.md`
- S2 State Vault Schema Primacy: GREEN (no schema changes in C008)
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/STATE_VAULT_SCHEMA_SPEC.md`
- S3 Constitutional Guard: PASS (C008-specific report; avoids mutating earlier sealed reports)
  - Command: `python KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py --report KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C008.md`
  - Report: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C008.md`

## Tests (Pass/Fail-Closed Proof)

Commands executed:

- `python KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py` (PASS)
- `python KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_schema_contracts.py` (PASS)
- `python KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_state_vault.py` (PASS)

Fail-closed coverage includes:

- truncation -> FAIL
- mid-file corruption -> FAIL
- reorder -> FAIL
- schema drift -> FAIL
- payload/hash mismatch -> FAIL
- partial write (missing newline tail) -> FAIL
