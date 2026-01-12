# W5.1 C018 Verification — Epoch Orchestrator (Tooling-Only)

Concept: `C018` — Epoch Orchestrator

Scope proven here (tooling-only):
- Deterministic epoch plan parsing + epoch hash computation.
- Sequential execution of crucibles via C019 runner subprocess (no kernel imports in tool process).
- Append-only evidence (manifest, summary, checkpoint, per-crucible run records).
- Resume behavior proven via unit tests.

## Implementation Files
- `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py`
- `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_schemas.py`
- `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_manifest.py`
- `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_budget.py`
- `KT_PROD_CLEANROOM/tools/growth/orchestrator/checkpoint_store.py`

## Tests (Low-RAM)
Command executed:
- `python -m unittest -q KT_PROD_CLEANROOM/tools/growth/orchestrator/tests/test_epoch_orchestrator.py`

Result:
- PASS

Coverage (minimum requirements):
- Determinism: `compute_epoch_hash` stable for same plan/spec hashes.
- Resume correctness: checkpoint-driven resume skips completed crucibles.
- Append-only discipline: run records written once.

## One Successful Epoch (>= 3 crucibles)
Epoch plan:
- `KT_PROD_CLEANROOM/tools/growth/epochs/EPOCH-0001-GOV-HONESTY.json`

Command executed:
- `python -m KT_PROD_CLEANROOM.tools.growth.orchestrator.epoch_orchestrator --epoch KT_PROD_CLEANROOM/tools/growth/epochs/EPOCH-0001-GOV-HONESTY.json --mode normal`

Artifacts written:
- `KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/EPOCH-0001-GOV-HONESTY/epoch_manifest.json`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/EPOCH-0001-GOV-HONESTY/epoch_summary.json`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/EPOCH-0001-GOV-HONESTY/checkpoint.json`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/EPOCH-0001-GOV-HONESTY/CRU-GOV-HONESTY-0*/run_record.json`

Determinism proof:
- `epoch_hash` computed from plan + spec hashes equals:
  - `48d226cd50a754ac5bba5f5d5ffd1683ba284d96f296dcb2b064fd758250cacb`
  - matches `epoch_manifest.json` and `epoch_summary.json`.

Notes:
- This orchestrator is measurement-only. It does not interpret kernel outputs.
- Kernel is invoked only via subprocess harness.
