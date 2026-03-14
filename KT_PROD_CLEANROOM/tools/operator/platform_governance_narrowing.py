from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json"

PLATFORM_GOVERNANCE_VERDICT_PROVEN = "PLATFORM_ENFORCEMENT_PROVEN"
PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY = "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"
PLATFORM_GOVERNANCE_VERDICT_UNPROVEN = "PLATFORM_GOVERNANCE_NOT_PROVEN"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(repo_root()), text=True).strip()


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def build_platform_governance_claims(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    branch = _load_required(root, str((Path(report_root_rel) / "main_branch_protection_receipt.json").as_posix()))
    ci = _load_required(root, str((Path(report_root_rel) / "ci_gate_promotion_receipt.json").as_posix()))
    branch_status = str(branch.get("status", "")).strip() or "MISSING"
    ci_status = str(ci.get("status", "")).strip() or "MISSING"
    branch_claim_admissible = bool(branch.get("claim_admissible"))

    if branch_status == "PASS" and branch_claim_admissible:
        verdict = PLATFORM_GOVERNANCE_VERDICT_PROVEN
        claim_admissible = True
        boundary = "Current main has fresh GitHub branch-protection / ruleset enforcement proof; platform-enforced governance claims are admissible."
        allowed_claims = [
            "platform-enforced governance proven on main",
            "workflow governance live on current head",
        ]
        forbidden_claims: list[str] = []
        ceiling = "PLATFORM_ENFORCED_CURRENT_HEAD"
    elif ci_status in {"PASS_WITH_PLATFORM_BLOCK", "PASS", "PASS_WITH_WARNINGS"} and branch_status != "PASS":
        verdict = PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY
        claim_admissible = False
        boundary = (
            "Current-head workflow governance is fresh, but GitHub branch-protection / ruleset enforcement is not proven on main. "
            "Do not claim platform-enforced governance while main_branch_protection_receipt is not PASS."
        )
        allowed_claims = [
            "fail-closed workflow governance is live on the current head",
            "the desired GitHub ruleset is committed in-repo",
            "platform block or missing branch-protection proof is explicit",
        ]
        forbidden_claims = [
            "platform-enforced governance proven on main",
            "fresh active branch-protection / ruleset enforcement on main",
            "higher enterprise legitimacy from platform enforcement",
        ]
        ceiling = "WORKFLOW_GOVERNANCE_ONLY"
    else:
        verdict = PLATFORM_GOVERNANCE_VERDICT_UNPROVEN
        claim_admissible = False
        boundary = "Workflow governance and platform branch-protection proof are not both fresh enough to support governance claims on main."
        allowed_claims = ["desired GitHub ruleset is committed in-repo"]
        forbidden_claims = [
            "platform-enforced governance proven on main",
            "workflow governance proven on the current head",
        ]
        ceiling = "NO_GOVERNANCE_UPGRADE"

    return {
        "platform_governance_verdict": verdict,
        "platform_governance_claim_admissible": claim_admissible,
        "workflow_governance_status": ci_status,
        "branch_protection_status": branch_status,
        "platform_governance_claim_boundary": boundary,
        "allowed_current_claims": allowed_claims,
        "forbidden_current_claims": forbidden_claims,
        "enterprise_legitimacy_ceiling": ceiling,
        "platform_governance_receipt_refs": [
            str((Path(report_root_rel) / "ci_gate_promotion_receipt.json").as_posix()),
            str((Path(report_root_rel) / "main_branch_protection_receipt.json").as_posix()),
        ],
        "platform_block": branch.get("platform_block"),
    }


def build_platform_governance_narrowing_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    claims = build_platform_governance_claims(root=root, report_root_rel=report_root_rel)
    return {
        "schema_id": "kt.operator.platform_governance_narrowing_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "branch_ref": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "validated_head_sha": _git("rev-parse", "HEAD"),
        **claims,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit the formal platform-governance narrowing receipt.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    parser.add_argument("--out", default=DEFAULT_RECEIPT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt = build_platform_governance_narrowing_receipt(root=root, report_root_rel=str(args.report_root))
    out_path = Path(str(args.out)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    write_json_stable(out_path, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
