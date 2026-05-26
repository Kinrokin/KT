from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from g32_common import GENERATED_COMPUTE_PACKET_PREFIXES, IGNORED_POLICY_PREFIXES, TRAINING_PATH_PREFIXES, read_json


def changed_files(base: str | None) -> list[str]:
    cmd = ["git", "diff", "--name-only", base, "HEAD"] if base else ["git", "diff", "--name-only", "--cached"]
    return [line.strip().replace("\\", "/") for line in subprocess.check_output(cmd, text=True).splitlines() if line.strip()]


def is_ignored_policy_path(path: str) -> bool:
    return path.startswith(IGNORED_POLICY_PREFIXES)


def is_training_like_path(path: str) -> bool:
    if is_ignored_policy_path(path):
        return False
    if path.startswith(TRAINING_PATH_PREFIXES):
        return True
    if path.startswith(GENERATED_COMPUTE_PACKET_PREFIXES) and path.endswith((".py", ".zip")):
        return True
    return False


def receipt_authorizes(path: Path) -> bool:
    if not path.exists():
        return False
    receipt = read_json(path)
    return any(row.get("training_decision") in {"TRAIN_ADAPTER", "TRAIN_ROUTER"} for row in receipt.get("decisions", []))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--receipt", default="reports/g32_training_decision_receipt.json")
    args = parser.parse_args()
    training_like = [path for path in changed_files(args.base) if is_training_like_path(path)]
    passed = not training_like or receipt_authorizes(Path(args.receipt))
    print(
        json.dumps(
            {
                "schema_id": "kt.do_not_train_enforcement.v1",
                "training_like_changes": training_like,
                "receipt": args.receipt,
                "pass": passed,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
