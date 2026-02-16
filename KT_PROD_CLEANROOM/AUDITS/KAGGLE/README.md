# KT V1 Kaggle Cells (Canonical, Copy/Paste)

These scripts are **not** required for CI and must never run with signing keys in CI.

They are intended for:

- Kaggle / offline hosts
- reproducible demonstrations
- operator runbooks

## Files

- `KT_MRT1_CERTIFY_V1.sh` — runs the constitutional batteries and (optionally) the FL4 determinism canary twice.
- `KT_ROUTER_HAT_DEMO_V1.sh` — runs the EPIC_19 deterministic router hat demo and emits routing receipts.
- `KT_EVAL_AUDIT_REPORT_DEMO_V1.sh` — runs EPIC_17 suite evaluation + EPIC_18 consolidated audit report generation on canned outputs.

## Assumptions

- Run from the repo root (the directory that contains `KT_PROD_CLEANROOM/`).
- Python environment already installed.
- No secrets are echoed or printed by these scripts.

## Canonical environment wiring

All scripts set:

`PYTHONPATH="$PWD/KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src:$PWD/KT_PROD_CLEANROOM"`

## Canonical-lane note

Do **not** export `KT_CANONICAL_LANE=1` while running `pytest`; set it only for canonical-lane verification commands.

