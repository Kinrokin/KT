from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_parallel_prep_lane_matrix_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_parallel_prep_lane_matrix_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PARALLEL_PREP_LANE_MATRIX_REPORT.md"

REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
EXECUTION_STATUS = "PASS__POST_F_PARALLEL_PREP_LANE_MATRIX_BOUND"
MATRIX_OUTCOME = "POST_F_PARALLEL_PREP_LANES_OPENED__NON_AUTHORITATIVE_ONLY"
AUTHORITATIVE_NEXT_MOVE = "CONVENE_POST_F_TRACK_03_HUMAN_REVIEW_COURT"


def _current_branch_name(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception:
        return "UNKNOWN_BRANCH"
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


def _current_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


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


def _lane_matrix() -> List[Dict[str, Any]]:
    mutable_roots = [
        "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_*",
        "KT_PROD_CLEANROOM/tools/operator/cohort0_post_f_parallel_*",
        "KT_PROD_CLEANROOM/tests/operator/test_cohort0_post_f_parallel_*",
    ]
    forbidden_mutations = [
        "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_01_*",
        "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_*",
        "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_*",
        "KT_PROD_CLEANROOM/reports/cohort0_successor_*",
        "KT_PROD_CLEANROOM/reports/cohort0_gate_*",
        "KT_PROD_CLEANROOM/runs/post_f_track_03/**",
    ]
    return [
        {
            "lane_id": "trust_zone_boundary_purification_scaffold",
            "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
            "scope": "Prepare trust-zone and boundary-purification packets without rewriting live authority or canonical promotion state.",
            "allowed_mutable_surfaces": mutable_roots,
            "disqualifiers": [
                "any edit to live Track 01/02/03 receipts or summaries",
                "any change to canonical-branch posture",
                "any attempt to promote or merge as part of prep work",
            ],
            "expected_outputs": [
                "trust-zone scope packet",
                "boundary-purification blocker ledger",
                "prep-only validation scaffold",
            ],
        },
        {
            "lane_id": "truth_engine_contradiction_validator_scaffold",
            "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
            "scope": "Prepare contradiction-validation and live-truth derivation scaffolds without mutating the frozen truth spine.",
            "allowed_mutable_surfaces": mutable_roots,
            "disqualifiers": [
                "any rewrite of live header truth",
                "any new claim about canonical promotion outcome",
                "any counted-path rerun outside a separately authorized court",
            ],
            "expected_outputs": [
                "truth-engine scope packet",
                "contradiction-validator scaffold",
                "prep-only test harness",
            ],
        },
        {
            "lane_id": "residual_proof_law_hardening_scaffold",
            "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
            "scope": "Package residual proof-law hardening items exposed by Track 03 without back-editing the counted run or its receipts.",
            "allowed_mutable_surfaces": mutable_roots,
            "disqualifiers": [
                "any overwrite of Track 03 counted artifacts",
                "any reinterpretation of promotion block as failure",
                "any auto-promotion of human-review-required files",
            ],
            "expected_outputs": [
                "residual hardening packet",
                "bounded hardening queue",
                "prep-only acceptance checklist",
            ],
        },
        {
            "lane_id": "upper_stack_ratification_scaffold",
            "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
            "scope": "Prepare upper-stack ratification sequencing packets as non-claim scaffolds only.",
            "allowed_mutable_surfaces": mutable_roots,
            "disqualifiers": [
                "any claim that ratification already occurred",
                "any uplift from prep scaffolding into live posture",
                "any commercial or broad-platform interpretation",
            ],
            "expected_outputs": [
                "ordered ratification scope packet",
                "dependency map",
                "non-claim staging notes",
            ],
        },
    ]


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    human_review_packet: Dict[str, Any],
    human_review_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(human_review_packet.get("authority_header", {}))
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_parallel_prep_lane_matrix_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "matrix_outcome": MATRIX_OUTCOME,
        "claim_boundary": (
            "This packet authorizes non-authoritative preparation lanes only. It does not modify live posture, "
            "does not reopen Track 03 counted execution, and does not supersede the authoritative human-review lane."
        ),
        "authoritative_lane_lock": {
            "exclusive_live_truth_owner": "track03_human_review_and_promotion_decision_lane",
            "working_branch": branch_name,
            "working_branch_head_at_matrix_time": branch_head,
            "canonical_authority_branch": "main",
            "authoritative_next_move": AUTHORITATIVE_NEXT_MOVE,
            "parallel_prep_lanes_may_mutate_live_truth": False,
        },
        "authority_header": {
            "canonical_authority_branch": "main",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
            "gate_d_cleared_on_successor_line": bool(authority_header.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(authority_header.get("gate_e_open_on_successor_line", False)),
            "gate_f_narrow_wedge_confirmed": bool(authority_header.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_open": bool(authority_header.get("gate_f_open", False)),
            "post_f_reaudit_passed": bool(authority_header.get("post_f_reaudit_passed", False)),
        },
        "parallel_lanes": _lane_matrix(),
        "global_disqualifiers": [
            "any silent overwrite of authoritative Track 01/02/03 truth surfaces",
            "any branch-law or orchestrator mutation from a prep lane",
            "any claim widening beyond bounded Track 01, Track 02, or Track 03 receipts",
            "any promotion or merge action from a non-authoritative prep lane",
        ],
        "prep_output_boundary": {
            "allowed_output_roots": [
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_*",
                "KT_PROD_CLEANROOM/tools/operator/cohort0_post_f_parallel_*",
                "KT_PROD_CLEANROOM/tests/operator/test_cohort0_post_f_parallel_*",
            ],
            "forbidden_output_roots": [
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_01_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_*",
                "KT_PROD_CLEANROOM/runs/post_f_track_03/**",
            ],
        },
        "subject_head": str(human_review_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": AUTHORITATIVE_NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_parallel_prep_lane_matrix_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "matrix_outcome": MATRIX_OUTCOME,
        "parallel_lane_count": len(packet["parallel_lanes"]),
        "working_branch": branch_name,
        "working_branch_head_at_matrix_time": branch_head,
        "working_branch_non_authoritative_until_protected_merge": True,
        "authoritative_next_move": AUTHORITATIVE_NEXT_MOVE,
        "subject_head": packet["subject_head"],
        "next_lawful_move": AUTHORITATIVE_NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Parallel Prep Lane Matrix Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Matrix outcome: `{MATRIX_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Parallel lane count: `{len(packet['parallel_lanes'])}`",
            f"- Authoritative next move: `{AUTHORITATIVE_NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    human_review_packet_path: Path,
    human_review_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: parallel prep lane matrix must run on {REQUIRED_WORKING_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: parallel prep lane matrix requires a clean worktree before execution")

    human_review_packet = common.load_json_required(root, human_review_packet_path, label="Track 03 human review packet")
    human_review_receipt = common.load_json_required(root, human_review_receipt_path, label="Track 03 human review receipt")

    common.ensure_pass(human_review_packet, label="Track 03 human review packet")
    common.ensure_pass(human_review_receipt, label="Track 03 human review receipt")
    if str(human_review_receipt.get("next_lawful_move", "")).strip() != AUTHORITATIVE_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: Track 03 human review receipt must preserve the authoritative next move")
    if not bool(human_review_receipt.get("working_branch_non_authoritative_until_protected_merge", False)):
        raise RuntimeError("FAIL_CLOSED: prep lanes require the branch to remain non-authoritative until merge")

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_current_head(root),
        human_review_packet=human_review_packet,
        human_review_receipt=human_review_receipt,
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "matrix_outcome": MATRIX_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": AUTHORITATIVE_NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Author the post-F parallel prep lane matrix packet.")
    parser.add_argument(
        "--human-review-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_packet.json",
    )
    parser.add_argument(
        "--human-review-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        human_review_packet_path=common.resolve_path(root, args.human_review_packet),
        human_review_receipt_path=common.resolve_path(root, args.human_review_receipt),
    )
    print(result["matrix_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
