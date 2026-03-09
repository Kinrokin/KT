# Operator Posture Note

Read active posture only from the current-head truth source, live validation evidence, posture contracts, and re-ratified tracked truth receipts.

Do not read these as active posture:

- documentary only: `KT-Codex/**`, `docs/**`, `KT_PROD_CLEANROOM/docs/commercial/**`, `README.md`, `LICENSE`
- historical only: `KT_TEMPLE_ROOT/**`, `KT_LANE_LORA_PHASE_B/**`, `KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/**`, root operation artifacts
- lab only: `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**`, `KT_PROD_CLEANROOM/tools/{growth,training,router,merge,tournament,eval,feedback,governance,live,probes,suites,canonicalize}/**`, `KT_PROD_CLEANROOM/policy_c/**`
- quarantined: `KT_PROD_CLEANROOM/05_QUARANTINE/**`, `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**`, `KT_PROD_CLEANROOM/AUDIT_LIVE_HASHED_V1.md`
- stale tracked truth: `KT_PROD_CLEANROOM/reports/current_state_receipt.json`, `KT_PROD_CLEANROOM/reports/live_validation_index.json`, `KT_PROD_CLEANROOM/reports/posture_consistency_receipt.json`, `KT_PROD_CLEANROOM/reports/runtime_closure_audit.json`

Until the clean-clone rerun and truth-surface resync are complete, use `current_head_truth_source.json` as the packet's posture anchor for `46173df31a9242c2e8f4bd7a1494b3466d1a89b9`.
