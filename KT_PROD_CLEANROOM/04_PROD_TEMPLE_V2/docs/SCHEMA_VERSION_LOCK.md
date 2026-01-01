# SCHEMA VERSION LOCK (C002)

Schemas are immutable once sealed.

## Non-Negotiable Rules

- No silent upgrades: a schema change must change `schema_version_hash`.
- No "latest": runtime must validate exact `(schema_id, schema_version_hash)` via the registry.
- No defaults, no coercion, no silent drops: unknown fields are rejected (fail-closed).
- No retroactive reinterpretation: historical receipts/state-vault entries must not be revalidated under new schema versions.

## How to Introduce a New Schema Version (Forward-Only)

1) Update or add the schema specification under `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/`.
2) Ensure the new `schema_version_hash` is computed deterministically from the explicit schema spec.
3) Append the new `(schema_id -> schema_version_hash)` binding to:
   - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_registry.py`
4) Add tests proving:
   - unknown fields reject
   - oversize rejects
   - old hash fails closed unless explicitly registered
5) Seal: update release manifest + decision log + phase gates under explicit authorization.

