from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_truth_engine_post_merge_replay_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_truth_engine_post_merge_replay_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRUTH_ENGINE_POST_MERGE_REPLAY_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-truth-engine"
EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_POST_MERGE_REPLAY_PACKET_BOUND"
OUTCOME = "POST_F_TRUTH_ENGINE_POST_MERGE_REPLAY_PREPARED__REMOTE_MAIN_CONVERGENCE_PENDING"
NEXT_MOVE = "RERUN_POST_F_TRUTH_ENGINE_RECOMPUTE_ON_MAIN_AFTER_PR15_MERGE"


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


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def build_outputs(*, branch_head: str, main_head: str, recompute_receipt: Dict[str, Any], posture_index: Dict[str, Any]) -> Dict[str, Dict[str, Any] | str]:
    root = repo_root()
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_post_merge_replay_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "claim_boundary": (
            "This packet prepares the exact truth-engine replay on main after PR #15 lands. "
            "It does not execute that replay early and does not widen package or prep authority."
        ),
        "authority_header": {
            "authoritative_lane_branch": REQUIRED_BRANCH,
            "authoritative_lane_branch_head": branch_head,
            "canonical_parent_main_head": main_head,
            "remote_canonical_convergence_pending": True,
        },
        "exact_sources_to_reread_on_main": [
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_contract_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_successor_gate_d_post_clear_branch_law_packet.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_gate_f_post_close_live_product_truth_packet.json").as_posix(),
        ],
        "expected_advisory_disappearance": {
            "current_advisory_contradiction_id": "merge_truth::remote_main_pending_pr15",
            "expected_after_pr15": "advisory contradiction removed because origin/main and main converge",
        },
        "outputs_to_supersede_or_overwrite_on_main": [
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_authority_graph.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_posture_index.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_ledger.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_stale_source_quarantine_list.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json",
        ],
        "success_condition": {
            "same_derivation_as_branch": True,
            "blocking_contradictions": 0,
            "advisory_contradictions": 0,
            "package_truth_posture_must_remain": list(posture_index.get("package_truth_posture", [])),
            "theorem_truth_posture_must_remain": list(posture_index.get("theorem_truth_posture", [])),
            "product_truth_posture_must_remain": list(posture_index.get("product_truth_posture", [])),
        },
        "first_main_replay_command": "python -m tools.operator.cohort0_post_f_truth_engine_validator_and_recompute_tranche",
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_post_merge_replay_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "replay_source_count": len(packet["exact_sources_to_reread_on_main"]),
        "success_condition_output_count": len(packet["outputs_to_supersede_or_overwrite_on_main"]),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Truth Engine Post-Merge Replay Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            "- Replay target: `main` after PR `#15` merge",
            "- Expected advisory disappearance: `merge_truth::remote_main_pending_pr15`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(*, reports_root: Path, recompute_receipt_path: Path, posture_index_path: Path) -> Dict[str, Any]:
    root = repo_root()
    if _current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: replay packet must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: replay packet requires a clean worktree")

    recompute_receipt = common.load_json_required(root, recompute_receipt_path, label="truth-engine recompute receipt")
    posture_index = common.load_json_required(root, posture_index_path, label="truth-engine posture index")
    common.ensure_pass(recompute_receipt, label="truth-engine recompute receipt")
    if str(recompute_receipt.get("next_lawful_move", "")).strip() != NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: recompute receipt does not authorize main replay")

    outputs = build_outputs(
        branch_head=_git_rev_parse(root, "HEAD"),
        main_head=_git_rev_parse(root, "main"),
        recompute_receipt=recompute_receipt,
        posture_index=posture_index,
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Prepare the exact post-merge truth-engine replay on main.")
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
