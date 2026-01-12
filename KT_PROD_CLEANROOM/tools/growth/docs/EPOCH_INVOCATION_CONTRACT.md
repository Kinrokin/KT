# Epoch Invocation Contract

This document defines the canonical, deterministic entrypoint for epoch execution.

## Canonical API

Use the importable function below for all tooling and automation:

```python
from pathlib import Path
from KT_PROD_CLEANROOM.tools.growth.orchestrator.epoch_orchestrator import run_epoch_from_plan

summary = run_epoch_from_plan(
    plan_path=Path("KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_NEXT_AUTO.json"),
    resume=False,
    mode="salvage",
)
```

## Supported Modes

- `normal`: run epoch without salvage.
- `salvage`: run epoch and emit salvage artifacts after completion.
- `shadow`: reserved for non-authoritative tooling runs (currently treated as `normal`).

## CLI Parity

The CLI is a thin wrapper that calls the same function. Supported flags:

```
--epoch <path> --mode normal|salvage|shadow [--resume] [--summary-only] [--salvage-out-root <path>] [--no-auto-bump]
```

Passing any undeclared flag is a fail-closed error.

## Prohibited Patterns

- Subprocess invocation of `epoch_orchestrator.py` from tooling code.
- Ad-hoc CLI argument construction outside of the orchestrator module.

All tooling must import and call `run_epoch_from_plan`.
