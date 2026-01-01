# STATE VAULT SCHEMA SPEC (S2)

Authority: This schema is the single, authoritative record shape for all V2 state/ledger/receipt/replay work.

Fail-closed: any record not conforming to this spec is rejected. No silent upgrades. No extra keys.

## Canonical Module
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py`

## Record Format
Storage format is JSON Lines (JSONL): one JSON object per line.

Records are append-only. Any correction is a new record ("correction receipt"), never an in-place rewrite.

## Required Fields (Immutable)
- `receipt_id` (64 lowercase hex): unique id for this record
- `created_at` (UTC ISO-8601 with `Z` suffix): creation timestamp
- `event_type` (string <= 64): event classifier (enum defined by governance/tests; unknown allowed only if schema-validated)
- `organ_id` (string <= 64): emitting organ identifier
- `event_hash` (64 lowercase hex): hash binding of the record's meaning
- `parent_hash` (64 lowercase hex): previous record hash (genesis uses 64 zeros)
- `payload_hash` (64 lowercase hex): hash of the bounded payload surface
- `schema_id` (fixed): `kt.state_vault.v1`
- `schema_version_hash` (64 lowercase hex): hash binding to this schema version
- `constitution_version_hash` (64 lowercase hex): binds record to the active constitution version

Genesis parent hash:
- `parent_hash = "0000000000000000000000000000000000000000000000000000000000000000"`

## Optional Fields (Explicit Allowlist; Bounded)
Only these optional fields may be present (all others are forbidden):
- `inputs_hash` (64 lowercase hex)
- `outputs_hash` (64 lowercase hex)
- `energy_cost` (number, 0 <= value <= 1e9)
- `energy_source` (enum): `EFFICIENCY` | `INEFFICIENCY`
- `crisis_mode` (enum): `NOMINAL` | `S1_SOFT_DAMP` | `S2_HARD_FREEZE` | `S3_DIAGNOSTIC` | `S4_REFLEX`

No raw payloads are permitted. No prompt/content/messages fields. Hashes and small enums only.

## Size Limits (Context Poisoning Defense)
Defined in code (schema-version-hash bound):
- Max record bytes: 4096 (UTF-8)
- Max string length: 256 (unless a field specifies a smaller max)

## Hash Binding Rules
`payload_hash` is computed from a canonical JSON encoding of only the allowed optional fields.

`event_hash` is computed from a canonical JSON encoding of:
- `payload_hash`
- `event_type`
- `organ_id`
- `parent_hash`
- `schema_version_hash`
- `constitution_version_hash`

## Chain Continuity Rules
Replay must validate:
- `parent_hash` continuity (each record references the prior record's `event_hash`, or genesis hash)
- recomputation of `payload_hash` and `event_hash`
- schema/constitution hashes exist in registries (fail-closed if unknown)

## Migration Policy (No Retroactive Reinterpretation)
- No record may be reinterpreted under a new schema or constitution version.
- If new fields are required in the future, a new schema_id/schema_version_hash is introduced explicitly.
- Historical replays either select matching logic by hashes or halt.

## Enforcement
Any historical module that requires fields outside this allowlist:
- is rejected, or
- must be wrapped at an organ boundary (adapter/governance/spine), never inside utilities.
