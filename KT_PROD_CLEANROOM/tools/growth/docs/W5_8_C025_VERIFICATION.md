# W5.8 — C025 Distillation Pipeline — Verification

## Scope

Offline-only deterministic distillation producing reproducible artifact hashes.

This concept produces a metadata + hash bundle (no training execution).

## Files

- `KT_PROD_CLEANROOM/tools/growth/distillation/distill_schemas.py`
- `KT_PROD_CLEANROOM/tools/growth/distillation/distill_runner.py`
- `KT_PROD_CLEANROOM/tools/growth/distillation/tests/test_distillation.py`
- `KT_PROD_CLEANROOM/tools/growth/check_c025_constitution.py`

## Tests (executed)

- `python -m unittest -q KT_PROD_CLEANROOM/tools/growth/distillation/tests/test_distillation.py`

## Guard (executed)

- `python KT_PROD_CLEANROOM/tools/growth/check_c025_constitution.py KT_PROD_CLEANROOM/tools/growth/distillation`

Report:

- `KT_PROD_CLEANROOM/tools/growth/docs/CONSTITUTIONAL_GUARD_REPORT_C025.md`

## Distillation run (executed)

Input:

- `KT_PROD_CLEANROOM/tools/growth/artifacts/training_warehouse/warehouse_manifest.jsonl`

Output artifact dir (≥1):

- `KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/a8cdbaa243445452c47e0ba9f99c08b3fd2355bd13eb2424b868725f29166b45/`

Idempotence proof (executed; no overwrite):

- `python KT_PROD_CLEANROOM/tools/growth/distillation/distill_runner.py --warehouse-manifest KT_PROD_CLEANROOM/tools/growth/artifacts/training_warehouse/warehouse_manifest.jsonl --out-dir KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/a8cdbaa243445452c47e0ba9f99c08b3fd2355bd13eb2424b868725f29166b45 --allow-existing`

Artifact hashes (sha256):

- `KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/a8cdbaa243445452c47e0ba9f99c08b3fd2355bd13eb2424b868725f29166b45/distill_config.json` = `deb97940f20a790920c4fe9552cbf99f413f406a33ef4ab23c874268a4fb2a9f`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/a8cdbaa243445452c47e0ba9f99c08b3fd2355bd13eb2424b868725f29166b45/run_manifest.json` = `d5778f5676c35d76826f57eb5500d6b698f0e1034f577c8e40292e953a2bfc70`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/a8cdbaa243445452c47e0ba9f99c08b3fd2355bd13eb2424b868725f29166b45/model_artifact.json` = `d358938ed0af72fe47279189c3a110da5d928f42f99db956d81c8bac1705825c`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/distillation_ledger_chained.jsonl` = `9381a5ed95ef7a80083f667af19b49d25311f5a2c8712f48a34e36ba5d9d0b1e`
