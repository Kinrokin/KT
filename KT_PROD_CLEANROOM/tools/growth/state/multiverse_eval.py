from __future__ import annotations

import argparse
import json
from pathlib import Path


class MultiverseEvalError(RuntimeError):
    pass


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Multiverse evaluation stub (Policy B wiring; fail-closed).")
    p.add_argument("--fork-root", required=True, help="Path to a paradox fork root directory.")
    p.add_argument("--out", required=True, help="Output JSON path for multiverse evaluation record.")
    return p.parse_args()


def _write_once(path: Path, payload: str) -> None:
    if path.exists():
        raise MultiverseEvalError(f"Refusing to overwrite existing file: {path.as_posix()} (fail-closed)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8", newline="\n")


def main() -> int:
    args = _parse_args()
    fork_root = Path(args.fork_root).resolve()
    if not fork_root.exists() or not fork_root.is_dir():
        raise MultiverseEvalError(f"fork_root missing or not a directory: {fork_root.as_posix()} (fail-closed)")

    branches = [p for p in fork_root.iterdir() if p.is_dir()]
    if not branches:
        raise MultiverseEvalError(f"fork_root contains no branches: {fork_root.as_posix()} (fail-closed)")

    payload = {
        "schema": "MULTIVERSE_EVAL_V1",
        "schema_version": 1,
        "fork_root": fork_root.as_posix(),
        "branches": [b.name for b in sorted(branches)],
        "status": "NOT_EVALUATED",
        "notes": "Policy B wiring stub; evaluation disabled.",
    }
    _write_once(Path(args.out).resolve(), json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
