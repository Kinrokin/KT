from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from ktstop300_common import REPORTS, write_json


def gh_json(*args: str) -> dict:
    return json.loads(subprocess.check_output(["gh", *args], text=True))


def check_review_completion(pr_number: str | None = None) -> dict:
    if not pr_number:
        return {
            "schema_id": "kt.stop300.v4.review_completion_receipt.v1",
            "status": "PENDING_PR_REVIEW_COMPLETION",
            "unresolved_review_thread_count": None,
            "required_merge_gate": "zero unresolved review threads",
            "claim_ceiling_status": "PRESERVED",
        }
    pr = gh_json("pr", "view", pr_number, "--json", "state,reviewDecision,statusCheckRollup")
    pending_checks = [
        check.get("name")
        for check in pr.get("statusCheckRollup", [])
        if check.get("status") != "COMPLETED" or check.get("conclusion") not in {"SUCCESS", "SKIPPED", "NEUTRAL"}
    ]
    # GraphQL review-thread state is the only authoritative unresolved-thread source.
    query = """
    query($owner:String!, $repo:String!, $number:Int!) {
      repository(owner:$owner, name:$repo) {
        pullRequest(number:$number) {
          reviewThreads(first:100) {
            nodes { isResolved }
          }
        }
      }
    }
    """
    repo = gh_json("repo", "view", "--json", "nameWithOwner")["nameWithOwner"]
    owner, name = repo.split("/", 1)
    raw = subprocess.check_output(
        ["gh", "api", "graphql", "-f", f"query={query}", "-F", f"owner={owner}", "-F", f"repo={name}", "-F", f"number={int(pr_number)}"],
        text=True,
    )
    payload = json.loads(raw)
    threads = payload["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
    unresolved = sum(1 for thread in threads if not thread.get("isResolved"))
    status = "PASS_ZERO_UNRESOLVED_THREADS_BEFORE_MERGE" if unresolved == 0 and not pending_checks else "BLOCK_REVIEW_COMPLETION_PENDING"
    return {
        "schema_id": "kt.stop300.v4.review_completion_receipt.v1",
        "status": status,
        "pr_number": int(pr_number),
        "unresolved_review_thread_count": unresolved,
        "pending_checks": pending_checks,
        "required_merge_gate": "zero unresolved review threads",
        "claim_ceiling_status": "PRESERVED",
    }


def main(argv: list[str]) -> int:
    pr_number = argv[1] if len(argv) > 1 else os.environ.get("KT_PR_NUMBER")
    receipt = check_review_completion(pr_number)
    write_json(REPORTS / "stop300_v4_review_completion_receipt.json", receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    if receipt["status"].startswith("BLOCK"):
        raise SystemExit(receipt["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
