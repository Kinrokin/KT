# Domain 1 Publication Architecture Progress Report

## Scope

This report covers the Domain 1 implementation pass completed on 2026-03-10.

The goal of this pass was not to declare KT complete. The goal was to convert Truth Publication Architecture from doctrine into enforceable machinery and move the live repo onto the generated current-pointer model without illegally opening later constitutional domains.

## What Was Implemented

### New Domain 1 law surfaces

- `KT_PROD_CLEANROOM/governance/truth_publication_contract.json`
- `KT_PROD_CLEANROOM/governance/settled_authority_migration_contract.json`
- `KT_PROD_CLEANROOM/governance/truth_snapshot_retention_rules.json`
- `KT_PROD_CLEANROOM/governance/truth_publication_cleanliness_rules.json`
- `KT_PROD_CLEANROOM/governance/tracked_vs_generated_truth_boundary.json`
- `KT_PROD_CLEANROOM/governance/truth_bundle_contract.json`
- `KT_PROD_CLEANROOM/governance/truth_pointer_rules.json`
- `KT_PROD_CLEANROOM/governance/current_pointer_transition_rules.json`

### New Domain 1 tools

- `KT_PROD_CLEANROOM/tools/operator/truth_publication.py`
- `KT_PROD_CLEANROOM/tools/operator/truth_publication_validate.py`

### New tracked Domain 1 artifacts

- `KT_PROD_CLEANROOM/reports/truth_bundle.schema.json`
- `KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json`
- `KT_PROD_CLEANROOM/reports/truth_pointer_index.json`
- `KT_PROD_CLEANROOM/reports/truth_publication_receipt.json`
- `KT_PROD_CLEANROOM/reports/truth_snapshot_manifest.json`
- `KT_PROD_CLEANROOM/reports/truth_clean_state_receipt.json`
- `KT_PROD_CLEANROOM/reports/truth_publication_supersession_receipt.json`
- `KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json`

### New generated truth lane

- authoritative current pointer:
  `KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json`
- current bundle manifest:
  `KT_PROD_CLEANROOM/exports/_truth/current/current_bundle_manifest.json`
- immutable truth bundles:
  `KT_PROD_CLEANROOM/exports/_truth/bundles/<truth_subject_commit>/<truth_bundle_hash>/truth_bundle.json`

### Governance and zone updates

- `KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json` now points current-head truth root at the generated current pointer
- `KT_PROD_CLEANROOM/governance/trust_zone_registry.json` now includes `KT_PROD_CLEANROOM/exports/_truth/**` in `GENERATED_RUNTIME_TRUTH`
- `KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json` now recognizes the generated pointer lane and the Domain 1 tracked indexes
- `KT_PROD_CLEANROOM/governance/governance_surface_expiration_rules.json` now covers the new Domain 1 law surfaces

### Sync-path integration

`KT_PROD_CLEANROOM/tools/operator/truth_surface_sync.py` now:

- publishes immutable truth bundles
- emits the current pointer
- emits the tracked publication receipts and indexes
- drives `readiness_scope_manifest.json` and `execution_board.json` to the generated current pointer
- keeps Domain 1 locked until `truth_publication_stabilization_receipt.json` is `PASS`

## Verification

### Tests

- `python -m pytest -q KT_PROD_CLEANROOM/tests/operator`
- result: `40 passed`

### Live validators

- `python -m tools.operator.truth_publication_validate`
- result: `PASS`

- `python -m tools.operator.trust_zone_validate`
- result: `PASS`

- `python -m tools.operator.program_catalog_verify --strict`
- result: `PASS`

- `python -m tools.operator.source_integrity verify`
- result: `PASS`

### Live repeat-stability check

`python -m tools.operator.truth_surface_sync --sync-secondary-surfaces` was run repeatedly on the live repo after the Domain 1 patch.

Observed result:

- `KT_PROD_CLEANROOM/reports/truth_publication_receipt.json` stable across repeated sync
- `KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json` stable across repeated sync
- `KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json` stable across repeated sync

An intermediate drift bug was discovered during this pass:

- truth bundle hashes were mutating because the bundle descriptor carried a self-referential supersession chain

That bug was repaired by removing pointer-history from the hashed bundle descriptor and by suppressing self-supersession in the current pointer payload.

## Current Constitutional State After This Pass

- authority mode: `SETTLED_AUTHORITATIVE`
- active constitutional domain: `DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE`
- authoritative current truth source: `KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json`
- Domain 1 validator: present and passing
- no-parallel-truth rule: enforced in publication receipts and validator
- H1 activation: still locked

## What Is Not Finished

This pass does not lawfully close Domain 1.

The remaining blocker recorded in `truth_publication_stabilization_receipt.json` is:

- posture state is `CANONICAL_READY_FOR_REEARNED_GREEN`, not `TRUTHFUL_GREEN`

That means:

- `TRUTH_PUBLICATION_STABILIZED=false`
- `H1_ACTIVATION_ALLOWED=false`
- later constitutional domains remain locked

## Truthful Verdict

Domain 1 is no longer conceptual. It is now implemented, validated, wired into the live sync path, and carried by the execution board through the generated current-pointer model.

But Domain 1 is not yet complete, because the repo has not yet re-earned `TRUTHFUL_GREEN` from the final publication model on the active pinned head.
