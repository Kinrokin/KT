# W5.6 — C023+ Evaluation Expansion — Verification

## Scope

Tooling-only numeric metrics derived from:

- outcome distributions
- replay status (PASS/FAIL)
- governance event type counts

No raw stdout/stderr/prompt ingestion.

## Files

- `KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/eval_plus_schemas.py`
- `KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/eval_plus_runner.py`
- `KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/tests/test_eval_harness_plus.py`
- `KT_PROD_CLEANROOM/tools/growth/check_c023_plus_constitution.py`

## Tests (executed)

- `python -m unittest -q KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/tests/test_eval_harness_plus.py`

## Guard (executed)

- `python KT_PROD_CLEANROOM/tools/growth/check_c023_plus_constitution.py KT_PROD_CLEANROOM/tools/growth/eval_harness_plus`

Report:

- `KT_PROD_CLEANROOM/tools/growth/docs/CONSTITUTIONAL_GUARD_REPORT_C023_PLUS.md`

## Sample run (tooling-only; executed)

- `python KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/eval_plus_runner.py --epoch-dir KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/EPOCH-0001-GOV-HONESTY --epoch-id EPOCH-0001-GOV-HONESTY --out KT_PROD_CLEANROOM/tools/growth/artifacts/eval_harness_plus/EVALPLUS-0001-GOV-HONESTY/extended_result.json`

Idempotence proof (executed; no overwrite):

- `python KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/eval_plus_runner.py --epoch-dir KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/EPOCH-0001-GOV-HONESTY --epoch-id EPOCH-0001-GOV-HONESTY --out KT_PROD_CLEANROOM/tools/growth/artifacts/eval_harness_plus/EVALPLUS-0001-GOV-HONESTY/extended_result.json --allow-existing`

Output:

- `KT_PROD_CLEANROOM/tools/growth/artifacts/eval_harness_plus/EVALPLUS-0001-GOV-HONESTY/extended_result.json`

Artifact hashes (sha256):

- `KT_PROD_CLEANROOM/tools/growth/artifacts/eval_harness_plus/EVALPLUS-0001-GOV-HONESTY/extended_result.json` = `55a15b6ffa4890736d014ab25a98ec982a2e4ccf7609758bb8c4dacc5e4aaecc`
