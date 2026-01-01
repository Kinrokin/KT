from __future__ import annotations

import argparse
import json
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="C019 Crucible Runner (tooling-only; subprocess kernel invocation)")
    p.add_argument("--crucible", required=True, help="Path to a crucible YAML/JSON spec")
    p.add_argument("--kernel", default="", help="Optional: run only this kernel target (e.g., V2_SOVEREIGN)")
    p.add_argument("--seed", type=int, default=0, help="Deterministic seed (default: 0)")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    crucible_path = Path(args.crucible).resolve()
    if not crucible_path.exists():
        raise SystemExit(f"Crucible file not found: {crucible_path.as_posix()}")

    crucibles_root = Path(__file__).resolve().parent / "crucibles"
    # Local tooling import only; does not import any kernel modules.
    import sys

    sys.path.insert(0, str(crucibles_root))
    from crucible_runner import run_crucible_file  # noqa: E402

    records = run_crucible_file(crucible_path, seed=args.seed)
    if args.kernel:
        records = [r for r in records if r.kernel_target == args.kernel]

    # Print a minimal, hash-only summary. Do not print kernel stdout/stderr here.
    out = [
        {
            "run_id": r.run_id,
            "crucible_id": r.crucible_id,
            "kernel_target": r.kernel_target,
            "outcome": r.outcome,
            "output_contract_pass": r.output_contract_pass,
            "replay_status": r.replay_status,
            "replay_pass": r.replay_pass,
            "governance_status": r.governance_status,
            "governance_pass": r.governance_pass,
            "artifacts_dir": r.artifacts_dir,
            "notes": r.notes,
        }
        for r in records
    ]
    print(json.dumps(out, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

