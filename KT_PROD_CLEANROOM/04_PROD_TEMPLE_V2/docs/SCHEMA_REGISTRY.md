# SCHEMA REGISTRY (C002)

Authority: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_registry.py`

Fail-closed: unknown `schema_id` or mismatched `schema_version_hash` halts (no fallback, no "latest").

## Registered Schemas (Append-Only)

| schema_id | schema_version_hash | Validator |
|---|---|---|
| `kt.runtime_context.v1` | `5dfa3cea99f397692e3bfa7f9995009f06e80831e86b4a40f4a87de96900f2e1` | `schemas.runtime_context_schema.validate_runtime_context` |
| `kt.state_vault.v1` | `a674f3335e7a4a03345660be013e3fb1c7b8ceda6aa2e6560ec236c8fa91413c` | `schemas.state_vault_schema.validate_state_vault_record` |

## How Runtime Must Use Schemas

- Payloads must carry `schema_id` + `schema_version_hash`.
- Runtime code must validate via `schemas.schema_registry` before any interpretation.
- Unknown keys are forbidden by schema validators (bounded contracts).

