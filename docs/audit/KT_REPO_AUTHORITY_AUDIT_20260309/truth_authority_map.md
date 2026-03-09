# Truth Authority Map

## Authoritative Sources

| Authority Class | Surfaces | Notes |
| --- | --- | --- |
| tier 0 immutable | `KT_PROD_CLEANROOM/governance/authority_os/KT_TITANIUM_ENFORCEMENT_BUNDLE_V3.json`, `KT_PROD_CLEANROOM/governance/authority_os/KT_CONTEXT_PACKET_HANDOFF_V3.json`, `KT_PROD_CLEANROOM/tools/verification/worm_write.py`, `KT_PROD_CLEANROOM/tools/delivery/redaction_rules.v1.json` | hard authority anchors |
| tier 1 constitutional | `KT_PROD_CLEANROOM/governance/program_catalog.json`, `ci/gates/p0_gate_definitions.json` | law for operator programs and release gates |
| tier 2 statutory | `KT_PROD_CLEANROOM/governance/sku_registry.json`, `KT_PROD_CLEANROOM/tools/operator/delta_proof.py`, `KT_PROD_CLEANROOM/tools/operator/serious_layer/continuous_gov_serious_v1.py` | operational statute |
| tier 3 administrative | `KT_PROD_CLEANROOM/docs/operator/KT_READINESS_GRADE_RUBRIC.md`, `KT_PROD_CLEANROOM/docs/operator/domains/DOMAIN_SUITE_STANDARD.md`, `KT_PROD_CLEANROOM/docs/operator/notebooks/README.md` | policy, not core truth |
| canonical primary | runtime source, schemas, governance contracts, operator tooling, verification, delivery, security, repo release controls | direct authority for runtime and enforcement |

## Derived Truth

- `KT_PROD_CLEANROOM/reports/live_validation_index.json`
- `KT_PROD_CLEANROOM/reports/current_state_receipt.json`
- `KT_PROD_CLEANROOM/reports/runtime_closure_audit.json`
- `KT_PROD_CLEANROOM/reports/posture_consistency_receipt.json`
- `KT_PROD_CLEANROOM/reports/posture_consistency_enforcement_receipt.json`
- `KT_PROD_CLEANROOM/reports/posture_conflict_receipt.json`

These are real truth surfaces only when they match the pinned head and are derived from current live validation evidence.

## Documentary Only

- `KT-Codex/**`
- `docs/**`
- `KT_PROD_CLEANROOM/docs/commercial/**`
- `README.md`
- `LICENSE`

These explain KT. They do not define runtime posture, operator readiness, or canonical scope.

## Historical Only

- `KT_TEMPLE_ROOT/**`
- `KT_LANE_LORA_PHASE_B/**`
- `KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/**`
- root operation artifacts such as `EPOCH_*`, `OPERATION_A_*`, `RUN_REPORT.md`, `runbook.txt`, `run_*.py`, `run_*.sh`, and `work_order.json`

These are lineage material. They can inform history but must not drive present posture.

## Stale Or Dangerous

- stale tracked truth receipts:
  - `KT_PROD_CLEANROOM/reports/current_state_receipt.json`
  - `KT_PROD_CLEANROOM/reports/runtime_closure_audit.json`
  - `KT_PROD_CLEANROOM/reports/posture_consistency_receipt.json`
  - `KT_PROD_CLEANROOM/reports/live_validation_index.json`
- incomplete tracked authority split:
  - `KT_PROD_CLEANROOM/governance/trust_zone_registry.json`
  - `KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json`
- misleading or quarantined surfaces:
  - `KT_PROD_CLEANROOM/05_QUARANTINE/**`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**`
  - `KT_PROD_CLEANROOM/AUDIT_LIVE_HASHED_V1.md`

## Where Posture Comes From

1. live validation evidence
2. posture contract
3. truth engine contract
4. current tracked receipts, but only after they are re-ratified against the current head

Fresh evidence on 2026-03-09 shows `CANONICAL_READY_FOR_REEARNED_GREEN` for `46173df31a9242c2e8f4bd7a1494b3466d1a89b9`.

## Where Posture Must Not Come From Again

- archive lineage
- commercial narrative docs
- quarantined runtime-adjacent tools
- stale tracked receipts that point at older heads
- local ignored export trees or secret-like residue
