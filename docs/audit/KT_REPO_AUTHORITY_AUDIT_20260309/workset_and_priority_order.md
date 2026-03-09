# Workset And Priority Order

## Freeze Now

- canonical runtime source and schemas under `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/**`
- tier 0 through tier 2 authority surfaces under `KT_PROD_CLEANROOM/governance/**`, `KT_PROD_CLEANROOM/tools/verification/worm_write.py`, and `KT_PROD_CLEANROOM/tools/delivery/redaction_rules.v1.json`
- operator, verification, delivery, and security code that already passed current-head validation

## Good But Needs Re-Ratification

- `KT_PROD_CLEANROOM/reports/current_state_receipt.json`
- `KT_PROD_CLEANROOM/reports/runtime_closure_audit.json`
- `KT_PROD_CLEANROOM/reports/posture_consistency_receipt.json`
- `KT_PROD_CLEANROOM/reports/live_validation_index.json`
- `KT_PROD_CLEANROOM/governance/execution_board.json`
- `KT_PROD_CLEANROOM/governance/trust_zone_registry.json`
- `KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json`

## Experimental And Lab Only

- `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**`
- `KT_PROD_CLEANROOM/tools/audit_intelligence/**`
- `KT_PROD_CLEANROOM/tools/canonicalize/**`
- `KT_PROD_CLEANROOM/tools/eval/**`
- `KT_PROD_CLEANROOM/tools/feedback/**`
- `KT_PROD_CLEANROOM/tools/governance/**`
- `KT_PROD_CLEANROOM/tools/growth/**`
- `KT_PROD_CLEANROOM/tools/live/**`
- `KT_PROD_CLEANROOM/tools/merge/**`
- `KT_PROD_CLEANROOM/tools/notebooks/**`
- `KT_PROD_CLEANROOM/tools/probes/**`
- `KT_PROD_CLEANROOM/tools/router/**`
- `KT_PROD_CLEANROOM/tools/suites/**`
- `KT_PROD_CLEANROOM/tools/tournament/**`
- `KT_PROD_CLEANROOM/tools/training/**`
- `KT_PROD_CLEANROOM/policy_c/**`

## Archive Only

- `KT_TEMPLE_ROOT/**`
- `KT_LANE_LORA_PHASE_B/**`
- `KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/**`
- root historical operation artifacts such as `EPOCH_*`, `KAGGLE_*`, `OPERATION_A_*`, `RUN_REPORT.md`, `runbook.txt`, `run_*.py`, and `run_*.sh`
- historical reference docs under `docs/audit/**`

## Dangerous Or Misleading And Must Be Quarantined

- `KT_PROD_CLEANROOM/05_QUARANTINE/**`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**`
- `KT_PROD_CLEANROOM/AUDIT_LIVE_HASHED_V1.md`
- local ignored export trees until they are either moved outside the repo target or explicitly treated as disposable runtime residue

## Ordered Work Plan

1. Pin the actual target as `main` at `46173df31a9242c2e8f4bd7a1494b3466d1a89b9` and stop treating `origin/main` at `4cf1b9d100f8699fa192d6a5409c69bc6e94761d` as the active truth reference.
2. Produce a real clean clone of `46173df31a9242c2e8f4bd7a1494b3466d1a89b9` with no ignored residue and rerun the truth matrix with clean-clone smoke enabled.
3. Fix `KT_PROD_CLEANROOM/tools/operator/truth_engine.py` so external live validation indexes are accepted without forcing `relative_to(root)`.
4. Promote the six-zone split into tracked governance: canonical, lab, archive, commercial, generated/runtime truth, quarantined.
5. Update readiness scoping so generated/runtime truth and quarantined surfaces are explicitly excluded from readiness claims.
6. Resync tracked truth surfaces from fresh live evidence for the pinned head: live validation index, current state receipt, runtime closure audit, posture consistency receipt, enforcement receipt, conflict receipt, and execution board.
7. Eliminate local residue from the target checkout or move runtime export roots outside the audited repo target; remove `.env.secret` from the working tree target.
8. Move misleading historical root artifacts into an explicit archive surface so the repo root stops mixing lineage with active control surfaces.
9. Re-run delivery, replay, and release-discipline evidence on the clean clone so delivery/security claims are current for the same pinned head.
10. Only after steps 1 through 9, decide whether KT can re-earn `TRUTHFUL_GREEN` or should remain at `CANONICAL_READY_FOR_REEARNED_GREEN`.
