# C011 Schema Boundary Proof (Paradox)

This document is an audit note for C011 showing that Paradox Injection is **schema-bounded** and does not create an ungoverned payload surface.

## Authoritative Schemas (C011)

All Paradox schemas live in one file:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_schemas.py`

Defined (immutable IDs + version hashes):

- `ParadoxTriggerSchema` (`paradox.trigger`)
- `ParadoxTaskSchema` (`paradox.task`)
- `ParadoxResultSchema` (`paradox.result`)

## Boundedness Rules (Fail-Closed)

- Unknown fields are rejected (`reject_unknown_keys`).
- Max field counts are enforced (`enforce_max_fields`).
- Max canonical JSON byte size is enforced (`enforce_max_canonical_json_bytes`).
- Depth/string/list bounds are enforced (`validate_bounded_json_value`).

## Determinism

- Trigger/task/result hashes are derived from canonical JSON (sorted keys; stable separators).
- `ParadoxResultSchema` verifies `result_hash` against a recomputation (fail-closed on mismatch).

## Persistence / Leakage Constraints

- ParadoxEngine does not persist raw task/trigger content.
- On injection, Spine logs a **hash-only** governance event (event envelopes are hashed; only hashes are stored in the state vault).

