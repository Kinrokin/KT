from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from tools.growth.e2e_gate import main as _e2e_gate_main

DEFAULT_MILESTONE_PLAN = "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_REANCHOR_CONSTRAINT.json"
DEFAULT_PRESSURE_PLAN = "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_NEXT_AUTO.json"


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Canonical Growth Lane E2E gate runner (wrapper around tools.growth.e2e_gate).",
    )
    p.add_argument(
        "--milestone-plan",
        default=DEFAULT_MILESTONE_PLAN,
        help=f"Path to milestone epoch plan (default: {DEFAULT_MILESTONE_PLAN}).",
    )
    p.add_argument(
        "--pressure-plan",
        default=DEFAULT_PRESSURE_PLAN,
        help=f"Path to pressure epoch plan (default: {DEFAULT_PRESSURE_PLAN}).",
    )
    p.add_argument(
        "--pressure-runs",
        type=int,
        default=1,
        help="Number of pressure epochs to run (default: 1).",
    )
    p.add_argument(
        "--out",
        default="",
        help="Write JSON report to path (optional).",
    )
    p.add_argument(
        "--timeout-s",
        type=int,
        default=1200,
        help="Per subprocess timeout in seconds (default: 1200).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Stream subprocess stdout/stderr (not recommended; can be noisy).",
    )
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    # Fail fast on obviously wrong paths. We keep this local (no registry reads) and deterministic.
    for label, p in (("milestone-plan", args.milestone_plan), ("pressure-plan", args.pressure_plan)):
        if not Path(p).exists():
            raise SystemExit(f"FAIL: missing {label}: {p}")

    gate_argv = [
        "--milestone-plan",
        args.milestone_plan,
        "--pressure-plan",
        args.pressure_plan,
        "--pressure-runs",
        str(args.pressure_runs),
        "--timeout-s",
        str(args.timeout_s),
    ]
    if args.out:
        gate_argv += ["--out", args.out]
    if args.verbose:
        gate_argv += ["--verbose"]

    return int(_e2e_gate_main(gate_argv))


if __name__ == "__main__":
    raise SystemExit(main())
