# C008 STATE VAULT SUBSTRATE SEAL (V2)

Sealed at (UTC): 2025-12-27T13:32:02Z

## Declaration (Non-Negotiable)

C008 (State Vault Append-Only Discipline) is hereby sealed as a non-negotiable substrate of the KT V2 runtime.

From this point forward:

- All persistence must be append-only JSONL via the State Vault writer.
- All persisted records must be schema-validated via C002 (`schemas.schema_registry`) and S2 (`schemas.state_vault_schema`).
- Hash-chain continuity must be enforced and replay must be tamper-evident and fail-closed.
- No mutation, compaction, pruning, rewriting, or “best effort” recovery is permitted.

Any change to C008 (writer, replay, storage layout, or sealed artifacts listed below) requires:

1) explicit new constitutional authorization  
2) a new `V2_RELEASE_MANIFEST.jsonl` entry for the changed file(s)  
3) a new concept-scoped verification report proving all invariants remain PASS  

No hotfixes. No silent edits. Fail-closed.

## Canonical Storage Layout

Default State Vault path (deterministic):

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/_state_vault/state_vault.jsonl`

Rules:

- append-only writes only (O_APPEND)
- writer must fsync after each append
- file must end with newline; missing newline is treated as partial write corruption and halts

## Sealed Artifacts (Canonical File List + SHA-256)

Release manifest (append-only):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

| path | sha256 |
|---|---|
| `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C008_VERIFICATION.md` | `8317c0a1442b85b0fb569a8731b461bbc73df67b850703274365dbd9ebff6dde` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C008.md` | `69de12380834dddaa5534eee6b6c0cff4fa3ebd9c2f79ff36b1778ffd3e2f64f` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C008_VERIFICATION.md` | `3db589ab500e8fbd065a31d26be346f907f250608f068dd04a8590defa222e0c` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_DIFF_RATIONALE_C008.md` | `942a760299575a56f5c9f5ddda89bbc20430959e9b6dbdedad58ddd617275eea` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/__init__.py` | `3a1aa9c781a9ab56eb13b420e5610ff5f6c51be3ac1f95d8239254a6857d0ff2` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/replay.py` | `51236125ffbd893069db294f1240099c29125941629a3151fbf4314ff0465a6e` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py` | `38e16e7ad1f4ff6fcd40f23476026aa95679e5015878844c9bfa52fb6a1ba2dc` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/versioning/__init__.py` | `d4bef9d30908c45517725de5f20c3ece8575baf00c9b3ca9d46426fe11c04a8d` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/versioning/constitution_registry.py` | `6d4e045900d845b1e1369dd0e8799b0ee6f13a35289421f6840b690d49e38201` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_state_vault.py` | `0ce14dd8304387e2edd2efb0a2cc2601f1f7f2a45f368b85366652024001b425` |

