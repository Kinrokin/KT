# W4.5 S1 TRIPLE-DIFF RATIONALE — C008 (State Vault Append-Only Discipline)

Concept ID: C008  
Purpose: prevent re-implanting legacy persistence assumptions that violate C001/C002/S2 constraints.

## Inputs (Evidence Pointers)

Candidate (Mass Reality):

- `KT_MASS_REALITY/01_INBOX_DROPZONE/01_REPOS_RAW/KingsTheorem_v53/kings-theorem-v53/core/state_vault.py`
  - sha256: `8b94ab602e81c1da57387300a519072610facf4efd55cd2be481780f0ab43037`

Temple V1 baseline (authority reference only):

- `KT_TEMPLE_ROOT/src/memory/ledger.py`
  - sha256: `af30320e9609d4da1fb34cf72e4c499461e93b39d607a7a7708387b08bf72b83`
- `KT_TEMPLE_ROOT/src/memory/replay.py`
  - sha256: `64a776eed69abeb9b87f2e0e245b0dec9f47ee132035c2bbc4b510974af4e067`
- `KT_TEMPLE_ROOT/src/schemas/receipt_schema.py` (receipt record allowlist + hash binding)

Current V2 working tree (Cleanroom):

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py` (S2 authoritative record shape)
  - sha256: `679a6d714c99964e0c58a4b7db52062667a18ddc76e5540ccf8539b14908f6cc`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_registry.py` (C002 registry; fail-closed on drift)
  - sha256: `74d85b993ab8d6d5854ed9f81f5d4f5744d0702707c150ca00e0a6e55ee2a81f`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py` (C001 enforcement point consuming C002)
  - sha256: `a22cdf31829705c3a460f4589f45a6e91afa40485947d8df6efc98a47632060b`

## Diff A — Candidate vs V1 (What Changed Historically)

### Candidate: SQLite + mutable operational state + rollback

Evidence in candidate:

- external dependency + structured models: `from pydantic import BaseModel, Field`
- persistence backend: `import sqlite3` and `StateVault._init_db()` creates SQLite tables
- mutable state (flux): `StateVault.write_flux()` uses `INSERT OR REPLACE` (mutation)
- rollback behavior: `StateVault.rollback_to_anchor()` rewrites operational state from snapshots
- audit notes store unbounded `old_value/new_value/reason` fields (`SignedChangeNote`)
- storage path is a database file: default `db_path="logs/state_vault.db"`

Constitutional implication:

- This design is not append-only JSONL. It explicitly supports mutation and rollback.

### V1: append-only JSONL receipts + hash chain root

Evidence in V1:

- `MerkleLedger.append(...)` writes JSONL in append mode: `path.open("a", ...)`
- schema allowlist enforced by `schemas/receipt_schema.py` (unknown keys reject; bounded sizes)
- chain head advances by `event_hash` (parent hash chain)
- replay exists as a separate module: `KT_TEMPLE_ROOT/src/memory/replay.py`

Constitutional implication:

- V1 already embodies the “append-only + schema validated + hash chained” posture that C008 requires.

## Diff B — V1 vs current V2 (What Has Already Evolved)

V2 currently differs from V1 in two key, intentional ways:

1) Schema authority is centralized and registry-bound (C002):
   - V2 uses `schemas/schema_registry.py` to fail-closed on unknown `(schema_id, schema_version_hash)`.

2) V2 separates “runtime context contract” from “persistence record contract”:
   - Runtime Entry→Spine context is its own schema: `schemas/runtime_context_schema.py`
   - Persistence record shape is S2: `schemas/state_vault_schema.py`

What is NOT present yet in V2:

- no `memory/` writer or replay implementation exists yet (C008 will add it)

## Diff C — Candidate vs current V2 (What Re-Implant Delta Would Actually Be)

Candidate assumptions that violate current V2 substrate:

- Storage backend mismatch:
  - candidate persists via SQLite DB (`sqlite3`) rather than append-only JSONL.
- Mutation/rollback mismatch:
  - candidate’s “flux” and rollback semantics violate C008’s “no mutation / no rewrite / no recovery” rule.
- Contract mismatch vs S2:
  - candidate stores `snapshot_data` and `old_value/new_value/reason` (unbounded), which are forbidden by the S2 allowlist in `state_vault_schema.py`.

Therefore:

- Candidate cannot be transplanted into V2 without either (a) weakening C002 bounded-contract rules or (b) inventing a new schema that permits raw payload persistence.
- Both are constitutionally disallowed under current authorization.

## “Why” Answers (Fail-Closed)

### Why did this diverge historically?

Candidate `state_vault.py` explicitly targets a different system shape:

- “Immutable anchors + mutable flux” plus “Rollback” (see module docstring and the `flux` + `rollback_to_anchor` methods)

This is a fork in persistence philosophy: the candidate optimizes for operational mutable state and rollback recovery.

### Was the divergence fixing a bug, closing a loophole, or enforcing governance?

Evidence supports “operational recovery / audit trail expansion”, not governance hardening:

- rollback + mutable flux increase capability but expand the persistence surface area and introduce mutation.
- the schema perimeter is not equivalent to C002/S2 bounded contracts (candidate uses Pydantic models but stores arbitrary JSON strings in DB).

### Does reintroducing candidate logic violate any current schema/receipt constraints?

Yes, directly:

- S2 allowlist forbids `snapshot_data`, `old_value`, `new_value`, `reason`, and any raw/unbounded payload fields.
- C008’s append-only discipline forbids mutable state (`INSERT OR REPLACE`) and rollback rewriting.

## Conclusion (S1 Outcome)

- C008 proceeds as a V2-native implementation modeled on V1’s append-only ledger posture, but upgraded to C002 registry-bound schema enforcement and S2 state-vault schema primacy.
- Candidate `state_vault.py` may contribute *conceptual* ideas (e.g., chain verification routines), but its persistence topology (SQLite + mutable flux + rollback) is disqualified from direct reuse under current constitutional constraints.

