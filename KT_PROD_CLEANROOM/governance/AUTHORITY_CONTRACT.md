# KT Authority Contract (Topology A Bridge)

This contract freezes the transitional authority topology ("Topology A") for the external-admissibility program.

## Authority Resolution

- Active authority truth source: `kt_truth_ledger:ledger/current/current_pointer.json`
- Active truth must be resolved by the authority resolver (later workstream WS2):
  - `RESOLUTION_PATH = authority_resolver`
- Main-bound mirrors must never be used as active truth sources when the ledger source is active.

## Main-Bound Documentary Mirrors

These paths may exist on `main` for compatibility and documentary legibility, but are non-authoritative when the ledger source is active:

- `KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json`
- `KT_PROD_CLEANROOM/reports/current_state_receipt.json`
- `KT_PROD_CLEANROOM/reports/runtime_closure_audit.json`
- `KT_PROD_CLEANROOM/governance/execution_board.json`

Each main-bound documentary mirror must include these top-level documentary markers:

- `DOCUMENTARY_ONLY = true`
- `ACTIVE_AUTHORITY = false`
- `SUPERSEDED_BY = kt_truth_ledger:ledger/current/current_pointer.json`
- `RESOLUTION_PATH = authority_resolver`
- `MIRROR_CLASS = documentary_compatibility_surface`
- `LIVE_TRUTH_ALLOWED = false`

Legacy/compatibility markers MAY remain (for existing validators) but must not contradict the markers above:

- `documentary_only = true`
- `live_authority = false`
- `authority_role = DOCUMENTARY_ONLY`
- `published_head_authority_claimed = false`

## Proof-Class Discipline

WS1 freezes semantics only. It does not:

- change the resolver implementation
- prove published-head admissible convergence
- open H1 or enable router/multi-adapter work

