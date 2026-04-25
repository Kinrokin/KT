from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_truth_engine_post_pr_canonical_handoff_note.json"
OUTPUT_RECEIPT = "cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRUTH_ENGINE_POST_PR_CANONICAL_HANDOFF_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-truth-engine"
CANONICAL_REPLAY_BRANCH = "main"
EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_POST_PR_CANONICAL_HANDOFF_PREPARED"
OUTCOME = "POST_F_TRUTH_ENGINE_POST_PR_CANONICAL_HANDOFF_DEFINED__READY_AFTER_PR15"
NEXT_MOVE = "RERUN_POST_F_TRUTH_ENGINE_RECOMPUTE_ON_MAIN_AFTER_PR15_MERGE"
CANONICAL_HANDOFF_EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_POST_PR_CANONICAL_HANDOFF_FROZEN"
CANONICAL_HANDOFF_OUTCOME = "POST_F_TRUTH_ENGINE_POST_PR_CANONICAL_HANDOFF_FROZEN__MAIN_REPLAY_COMPLETE"
CANONICAL_HANDOFF_NEXT_MOVE = "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip() or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def build_outputs(*, recompute_receipt: Dict[str, Any], posture_index: Dict[str, Any], branch_ref: str) -> Dict[str, Dict[str, Any] | str]:
    root = repo_root()
    canonical_mode = branch_ref == CANONICAL_REPLAY_BRANCH
    execution_status = CANONICAL_HANDOFF_EXECUTION_STATUS if canonical_mode else EXECUTION_STATUS
    outcome = CANONICAL_HANDOFF_OUTCOME if canonical_mode else OUTCOME
    next_lawful_move = CANONICAL_HANDOFF_NEXT_MOVE if canonical_mode else NEXT_MOVE
    claim_boundary = (
        "This note freezes the canonical truth-engine handoff after PR #15 landed and the main replay completed. "
        "It does not widen package or prep authority."
        if canonical_mode
        else "This note prepares the exact canonical handoff after PR #15 lands. It does not itself recompute main or settle remote canonical truth early."
    )
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_post_pr_canonical_handoff_note.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": execution_status,
        "outcome": outcome,
        "claim_boundary": claim_boundary,
        "first_canonical_truth_engine_freeze_on_main": {
            "outputs_to_freeze": [
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_authority_graph.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_posture_index.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_ledger.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_stale_source_quarantine_list.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json",
            ],
            "success_condition": "same derivation as branch replay with zero blocking contradictions and zero advisory contradictions",
        },
        "supersession_after_pr15": {
            "branch_local_advisory_to_supersede": "merge_truth::remote_main_pending_pr15",
            "supersession_reason": "remote main converged to the same canonical merge state",
            "branch_local_recompute_receipt_ref": common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json").as_posix(),
        },
        "unchanged_boundaries_after_pr15": {
            "package_truth_posture": list(posture_index.get("package_truth_posture", [])),
            "product_truth_posture": list(posture_index.get("product_truth_posture", [])),
            "theorem_truth_posture": list(posture_index.get("theorem_truth_posture", [])),
            "package_boundary_statement": "Deferred package promotion remains unchanged until a separate package-promotion court.",
        },
        "handoff_operator_note": {
            "run_on_branch": CANONICAL_REPLAY_BRANCH,
            "prerequisite": "PR #15 merged to origin/main and local main refreshed from origin/main",
            "replay_command": "python -m tools.operator.cohort0_post_f_truth_engine_validator_and_recompute_tranche",
        },
        "actual_recompute_branch_ref": str(recompute_receipt.get("branch_ref", "")).strip(),
        "blocking_contradiction_count": int(recompute_receipt.get("blocking_contradiction_count", 0)),
        "advisory_condition_count": int(recompute_receipt.get("advisory_condition_count", 0)),
        "next_lawful_move": next_lawful_move,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": execution_status,
        "outcome": outcome,
        "freeze_output_count": len(packet["first_canonical_truth_engine_freeze_on_main"]["outputs_to_freeze"]),
        "blocking_contradiction_count": int(recompute_receipt.get("blocking_contradiction_count", 0)),
        "advisory_condition_count": int(recompute_receipt.get("advisory_condition_count", 0)),
        "next_lawful_move": next_lawful_move,
    }
    report = common.report_lines(
        "Cohort0 Post-F Truth Engine Post-PR Canonical Handoff Report",
        [
            f"- Execution status: `{execution_status}`",
            f"- Outcome: `{outcome}`",
            "- Canonical rerun target: `main` after PR `#15` merge",
            "- Advisory contradiction to supersede: `merge_truth::remote_main_pending_pr15`",
            f"- Actual recompute branch: `{str(recompute_receipt.get('branch_ref', branch_ref)).strip()}`",
            f"- Blocking contradictions: `{int(recompute_receipt.get('blocking_contradiction_count', 0))}`",
            f"- Advisory conditions: `{int(recompute_receipt.get('advisory_condition_count', 0))}`",
            f"- Next lawful move: `{next_lawful_move}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(*, reports_root: Path, recompute_receipt_path: Path, posture_index_path: Path) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name not in {REQUIRED_BRANCH, CANONICAL_REPLAY_BRANCH}:
        raise RuntimeError(f"FAIL_CLOSED: post-PR canonical handoff note must run on {REQUIRED_BRANCH} or {CANONICAL_REPLAY_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: post-PR canonical handoff note requires a clean worktree")
    recompute_receipt = common.load_json_required(root, recompute_receipt_path, label="truth-engine recompute receipt")
    posture_index = common.load_json_required(root, posture_index_path, label="truth-engine posture index")
    common.ensure_pass(recompute_receipt, label="truth-engine recompute receipt")
    if branch_name == CANONICAL_REPLAY_BRANCH:
        if str(recompute_receipt.get("branch_ref", "")).strip() != CANONICAL_REPLAY_BRANCH:
            raise RuntimeError("FAIL_CLOSED: canonical handoff requires a main-bound recompute receipt")
        if int(recompute_receipt.get("blocking_contradiction_count", 0)) != 0 or int(recompute_receipt.get("advisory_condition_count", 0)) != 0:
            raise RuntimeError("FAIL_CLOSED: canonical handoff requires zero blocking contradictions and zero advisory conditions")
    outputs = build_outputs(recompute_receipt=recompute_receipt, posture_index=posture_index, branch_ref=branch_name)
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {"outcome": outputs["receipt"]["outcome"]}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Prepare the post-PR canonical truth-engine handoff note.")
    parser.add_argument(
        "--recompute-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json",
    )
    parser.add_argument(
        "--posture-index",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_posture_index.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        recompute_receipt_path=common.resolve_path(root, args.recompute_receipt),
        posture_index_path=common.resolve_path(root, args.posture_index),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
