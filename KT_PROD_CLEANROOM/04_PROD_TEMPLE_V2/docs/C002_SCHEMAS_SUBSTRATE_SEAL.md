# C002 SCHEMAS SUBSTRATE SEAL (V2)

Sealed at (UTC): 2025-12-27T12:32:42Z

## Declaration (Non-Negotiable)

C002 (Schemas as Bounded Contracts Layer) is hereby sealed as a non-negotiable substrate of the KT V2 runtime.

From this point forward:

- No data enters runtime without schema validation.
- Unknown fields are rejected (fail-closed).
- Oversized payloads are rejected (fail-closed).
- Schema version drift is fail-closed (no fallback, no "latest").

Any change to C002 (including schema definitions, schema hashing, registry contents, or enforcement wiring listed below) requires:

1) explicit new constitutional authorization  
2) a new `V2_RELEASE_MANIFEST.jsonl` entry for the changed file(s)  
3) a new concept-scoped verification report proving all invariants remain PASS  

No hotfixes. No silent edits. Fail-closed.

## Scope of Authority (C002)

Authority boundary:

- `schemas/` is the sole authority for contract definitions and validation.
- `schema_registry.py` is the sole authority for which `(schema_id, schema_version_hash)` pairs are runtime-valid.
- `schema_hash.py` is the sole authority for canonical hashing helpers.
- `runtime_context_schema.py` is the canonical Entry→Spine runtime context perimeter schema.

Forbidden outside `schemas/`:

- ad-hoc schema validation
- silent key renames, defaults, coercion, or silent drops
- accepting unknown keys or unbounded text/arrays

## Upgrade Rules (Versioned, Append-Only, No Fallback)

- Schemas are immutable once sealed.
- Any schema change must produce a new `schema_version_hash` (derived deterministically from an explicit spec).
- `schema_registry.py` is append-only: new versions are added explicitly.
- Historical receipts/state-vault entries are never reinterpreted under new schema versions.
- If an unknown `schema_id` or mismatched `schema_version_hash` is encountered: halt (fail-closed).

## Sealed Artifacts (Canonical File List + SHA-256)

Release manifest (append-only):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

The following files are the C002 sealed substrate set (hashes are the authoritative fingerprint for this seal):

| path | sha256 |
|---|---|
| `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C002_VERIFICATION.md` | `6484e053ff10887a41cb8cdd11af70f6fde918e437cc89156bd0a6ea07cf7c0d` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT.md` | `ec9eda295c44eb828d29024c016e62b4a336952915ab596d2b4dbea8dfb4d9b2` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/SCHEMA_REGISTRY.md` | `e06ed3cc304d1d386e389d24545c9afd3412f37eec55d4748a105a52133f5eca` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/SCHEMA_VERSION_LOCK.md` | `fce6e8b6f52b850a1f01c291e8def7e519bb0d5019d188b83a8f28a778454678` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/STATE_VAULT_SCHEMA_SPEC.md` | `80415a7b1bfc07b2d93cdc9bd170a7139ba0579f592284f1171d96e81be0ac02` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C002_VERIFICATION.md` | `46431e65fea8e595ba47ed2bd786a4351b00e5e42ce564222c41947eb9621aa4` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py` | `a22cdf31829705c3a460f4589f45a6e91afa40485947d8df6efc98a47632060b` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/__init__.py` | `9894c8b46ab8374ab4875619d7568822f88862df35884490303dca6194b0373a` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/base_schema.py` | `b06560a978f654b3554045c857dca489bd27f207d72f13086eb172301410dbc6` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/runtime_context_schema.py` | `f86ba3554a7af2ca768cbec82bd764ecc4f52693f906d3987f18f15f33a8aa00` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_hash.py` | `891b36322a5d3794d2f6b57176945508ceb647104f1a6d0e4f7f9b41936e0fb0` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_registry.py` | `74d85b993ab8d6d5854ed9f81f5d4f5744d0702707c150ca00e0a6e55ee2a81f` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py` | `679a6d714c99964e0c58a4b7db52062667a18ddc76e5540ccf8539b14908f6cc` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py` | `557b2c5b1264f3c9e61ef9dc56a154a7c95b7001c288ab5a0b076bf2835cc8e8` |
| `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_schema_contracts.py` | `49e8a6b4a05b13a375caf0320f40a1ddb4305f3419ca987721db25931b9cf83c` |

