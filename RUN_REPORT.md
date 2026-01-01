# KT E2E Run Report (Clean Clone)

## Primary References

- **Epoch hash:** `48d226cd50a754ac5bba5f5d5ffd1683ba284d96f296dcb2b064fd758250cacb` (`EPOCH-0001-GOV-HONESTY`)
- **Artifacts archive (zip):** `d:\KingsTheorem_Archive\_kt_e2e_archives\KT_E2E_20251231_212651_69c4122.zip`

## Run Context

- **Clean clone path:** `d:\KingsTheorem_Archive\_kt_clean_clone_20251231_212537`
- **Repo commit (clean clone):** `69c4122326b0d3787d8e737b73395450145e2669`
- **Command executed (Git Bash):** `./run_kt_e2e.sh` (stdout+stderr captured to `e2e_run.log`)
- **Kernel target:** `V2_SOVEREIGN`
- **Deterministic seed:** `0` (as configured in `run_kt_e2e.sh`)

## Phase Results (PASS/FAIL)

- **C019 (single crucible):** `PASS`
  - Crucible: `CRU-GOV-HONESTY-01`
  - Run ID: `44509da7d1f2133fc57c1d7fa59dce57bd72250c761913a5340bd3242c78f01e`
  - Output keys (stdout.json): `status, head_hash, record_count, thermodynamics, paradox, temporal, multiverse, council, cognition, curriculum`
  - Output status: `OK`
  - Replay: `PASS` (`head_hash=37b3e90c24b781617dc6951632d26588d3f182196bf32ca882a44a5853cee3e9`, `record_count=4`)
  - Governance: `VERIFIED` (`types=["GOV_POLICY_APPLY"]`, `count=2`)
- **C018 (epoch orchestration):** `PASS`
  - Epoch ID: `EPOCH-0001-GOV-HONESTY`
  - Epoch hash: `48d226cd50a754ac5bba5f5d5ffd1683ba284d96f296dcb2b064fd758250cacb`
  - Included run IDs:
    - `CRU-GOV-HONESTY-01`: `44509da7d1f2133fc57c1d7fa59dce57bd72250c761913a5340bd3242c78f01e`
    - `CRU-GOV-HONESTY-02`: `5756210b3f2b6948cd8a553bfc8a10c0213911917e1b8ebaaf82409ea06023f8`
    - `CRU-GOV-HONESTY-03`: `fce642be095b0847c0e463e7655a56964cafbda0d5c0782f060b71ec49674610`
- **C023+ (eval + drift/paradox metrics):** `PASS` (no output printed by runner; artifacts written under `KT_PROD_CLEANROOM/tools/growth/artifacts/`)
- **C021 (teacher factory):** `PASS`
  - Curriculum package: `KT_PROD_CLEANROOM/tools/growth/artifacts/curriculum/df6d16b822efbe826ef848cc766cbaedac6f0bd7087860ba9314bb77b3875279.json`
- **C020 (dream loop):** `PASS`
  - Dream ID: `DREAM-GOV-HONESTY-01`
  - Dream spec hash: `ae2146996d2c7488b33959420994eff44e26108998fffa053fe36968b64ad48d`
- **C024 (training warehouse):** `PASS`
  - Manifest: `KT_PROD_CLEANROOM/tools/growth/artifacts/training_warehouse/warehouse_manifest.jsonl`
- **C025 (distillation):** `PASS`

## What’s In The Zip

The archive includes (from the clean clone):

- `e2e_run.log`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/`
- `KT_PROD_CLEANROOM/tools/growth/ledgers/`
