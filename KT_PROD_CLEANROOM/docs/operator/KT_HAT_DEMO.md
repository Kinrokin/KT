# KT Hat Demo (Runtime Plane) - Operator Notes

The hat demo is a **runtime-plane** demonstration only. It must never mutate the certified factory lane.

## Hard Boundaries
- Writes are allowed only under `KT_PROD_CLEANROOM/exports/_runs/...` (WORM).
- No receipt minting. No law surface edits. No training/evaluation promotions.
- Fail-closed on missing policy/suite inputs.

## Run (Preferred)
- `python -m tools.operator.kt_cli --profile v1 hat-demo`

Windows wrapper (no installs):
- `powershell -ExecutionPolicy Bypass -File KT_PROD_CLEANROOM/tools/operator/kt.ps1 --profile v1 hat-demo`

## Outputs (Per Run)
- `verdict.txt` (one line)
- `hat_demo/router_run_report.json`
- `hat_demo/routing_receipt_<case_id>.json` (one per suite case)
- `transcripts/hat_demo.log`

## Verify
Use the operator report renderer:
- `python -m tools.operator.kt_cli --profile v1 report --run <hat_demo_run_dir>`

