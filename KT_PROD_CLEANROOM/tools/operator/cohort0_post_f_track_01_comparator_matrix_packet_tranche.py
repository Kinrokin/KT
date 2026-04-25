from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_01_comparative_scope_packet_tranche as scope_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_01_comparator_matrix_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_01_comparator_matrix_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_01_COMPARATOR_MATRIX_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_TRACK_01_COMPARATOR_MATRIX_BOUND"
MATRIX_OUTCOME = "POST_F_TRACK_01_COMPARATOR_MATRIX_DEFINED__TINY_SET_ONLY"
TRACK_ID = scope_tranche.TRACK_ID
NEXT_MOVE = "AUTHOR_POST_F_TRACK_01_METRIC_SCORECARD_CONTRACT"


def _require_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


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


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    branch_name: str,
    scope_packet: Dict[str, Any],
    live_product_truth_packet: Dict[str, Any],
    post_merge_closeout_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(scope_packet.get("authority_header", {}))
    confirmed_surface = dict(scope_packet.get("confirmed_canonical_surface", {}))
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_comparator_matrix_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet freezes the tiny Track 01 comparator matrix for the confirmed canonical wedge only. "
            "It does not execute the benchmark, does not award superiority, and does not widen the product or theorem claim surface."
        ),
        "execution_status": EXECUTION_STATUS,
        "matrix_outcome": MATRIX_OUTCOME,
        "track_identity": {
            "track_id": TRACK_ID,
            "matrix_type": "tiny_comparator_set",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
        },
        "authority_header": {
            "canonical_authority_branch": "main",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
            "gate_d_cleared_on_successor_line": bool(authority_header.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(authority_header.get("gate_e_open_on_successor_line", False)),
            "gate_f_narrow_wedge_confirmed": bool(authority_header.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_open": bool(authority_header.get("gate_f_open", False)),
            "cleanup_closeout_merged_locally": str(post_merge_closeout_receipt.get("status", "")).strip()
            == "PASS__CANONICAL_CLEAN_CLOSEOUT_MERGED_TO_MAIN",
        },
        "matrix_purpose": {
            "comparison_category": "GOVERNED_RECEIPT_BACKED_FAIL_CLOSED_EXECUTION_UNDER_LAW",
            "confirmed_surface_wedge_id": str(confirmed_surface.get("wedge_id", "")).strip(),
            "surface_lock": "local_verifier_mode_only",
            "target_use": "post_f_track_01_first_bounded_comparative_execution",
        },
        "active_comparator_rows": [
            {
                "row_id": "KT_CANONICAL_WEDGE",
                "row_type": "CANONICAL_CONFIRMED_SURFACE",
                "selection_rule": "Frozen by the confirmed Gate F local_verifier_mode wedge packet.",
                "comparator_subject": str(confirmed_surface.get("wedge_id", "")).strip(),
                "active_profile_id": str(confirmed_surface.get("active_profile_id", "")).strip(),
                "named_target_required_now": True,
                "category_fair": True,
            },
            {
                "row_id": "STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE",
                "row_type": "INTERNAL_STATIC_BASELINE",
                "selection_rule": (
                    "Exactly one strongest approved static internal baseline may be selected. "
                    "It must already be lawfully validated and must run on the same bounded wedge contract."
                ),
                "named_target_required_now": False,
                "selection_receipt_required_before_execution": True,
                "category_fair": True,
            },
            {
                "row_id": "ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW",
                "row_type": "EXTERNAL_MONOLITH_WORKFLOW",
                "selection_rule": (
                    "Exactly one named external monolith workflow may be selected for execution. "
                    "The workflow must be category-fair for the confirmed wedge and may not imply a broad vendor bakeoff."
                ),
                "named_target_required_now": False,
                "selection_receipt_required_before_execution": True,
                "category_fair": True,
                "single_slot_only": True,
            },
        ],
        "conditional_internal_comparator_policy": {
            "additional_internal_comparators_allowed": False,
            "exception_rule": (
                "An additional internal comparator may appear only if it is already lawfully validated and a separate "
                "selection receipt proves category fairness without widening Track 01."
            ),
        },
        "metric_schema": {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparator_metric_schema.v1",
            "counting_metrics": [
                {
                    "metric_id": "receipt_completeness",
                    "summary": "Does the run return the full bounded receipt set required by the wedge contract?",
                    "counting_mode": "bounded_scorecard",
                },
                {
                    "metric_id": "replayability",
                    "summary": "Can the result be replayed or audited from the returned proof surfaces without repo archaeology?",
                    "counting_mode": "bounded_scorecard",
                },
                {
                    "metric_id": "fail_closed_behavior",
                    "summary": "Does the system fail closed under bounded errors instead of drifting into silent success?",
                    "counting_mode": "bounded_scorecard",
                },
                {
                    "metric_id": "operator_clarity_and_bounded_execution_integrity",
                    "summary": "Does the operator path stay clear, bounded, and faithful to the declared wedge contract?",
                    "counting_mode": "bounded_scorecard",
                },
                {
                    "metric_id": "useful_output_success_under_wedge_contract",
                    "summary": "Does the system complete the useful bounded task without stepping outside the confirmed wedge surface?",
                    "counting_mode": "bounded_scorecard",
                },
            ],
        },
        "verdict_schema": {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparator_verdict_schema.v1",
            "allowed_verdicts": [
                "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR",
                "KT_CANONICAL_WEDGE_PARITY__CATEGORY_FAIR",
                "KT_CANONICAL_WEDGE_DEFICIT__CATEGORY_FAIR",
                "DEFERRED__COMPARATOR_SELECTION_OR_METRIC_DEFECT",
            ],
            "interpretation_guard": "Verdicts are Track 01 bounded comparative outcomes only, not broad product or model claims.",
        },
        "forbidden_score_interpretations": [
            "No best AI framing.",
            "No broad reasoning or model superiority claim.",
            "No full-system superiority claim.",
            "No Kaggle or math carryover.",
            "No broad vendor bakeoff framing from a single external monolith row.",
        ],
        "source_refs": common.output_ref_dict(
            scope_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}"),
            live_product_truth_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json"),
            post_merge_closeout_receipt=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_post_merge_closeout_receipt.json"),
        ),
        "subject_head": subject_head,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_comparator_matrix_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "matrix_outcome": MATRIX_OUTCOME,
        "track_id": TRACK_ID,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "active_row_count": len(packet["active_comparator_rows"]),
        "metric_count": len(packet["metric_schema"]["counting_metrics"]),
        "next_lawful_move": NEXT_MOVE,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 01 Comparator Matrix Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Matrix outcome: `{MATRIX_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Active comparator rows: `{len(packet['active_comparator_rows'])}`",
            f"- Counting metrics: `{len(packet['metric_schema']['counting_metrics'])}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    scope_packet_path: Path,
    live_product_truth_packet_path: Path,
    post_merge_closeout_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    scope_packet = common.load_json_required(root, scope_packet_path, label="Track 01 comparative scope packet")
    live_product_truth_packet = common.load_json_required(root, live_product_truth_packet_path, label="post-F live product truth packet")
    post_merge_closeout_receipt = common.load_json_required(root, post_merge_closeout_receipt_path, label="post-merge closeout receipt")

    _require_pass(scope_packet, label="Track 01 comparative scope packet")
    _require_pass(live_product_truth_packet, label="post-F live product truth packet")
    if str(post_merge_closeout_receipt.get("status", "")).strip() != "PASS__CANONICAL_CLEAN_CLOSEOUT_MERGED_TO_MAIN":
        raise RuntimeError("FAIL_CLOSED: Track 01 comparator matrix requires the merged closeout receipt")
    if str(scope_packet.get("scope_outcome", "")).strip() != scope_tranche.SCOPE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 01 comparator matrix requires the bound comparative scope packet")
    if str(scope_packet.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRACK_01_COMPARATOR_MATRIX_PACKET":
        raise RuntimeError("FAIL_CLOSED: Track 01 comparator matrix requires the scope packet to point here next")

    authority_header = dict(scope_packet.get("authority_header", {}))
    if not bool(authority_header.get("working_branch_non_authoritative_until_protected_merge", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 comparator matrix requires explicit non-authoritative branch posture")

    canonical_live_status = dict(live_product_truth_packet.get("canonical_live_product_status", {}))
    if str(canonical_live_status.get("current_product_posture", "")).strip() != common.GATE_F_CONFIRMED_POSTURE:
        raise RuntimeError("FAIL_CLOSED: Track 01 comparator matrix requires the confirmed Gate F wedge posture")
    if bool(canonical_live_status.get("gate_f_open", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 comparator matrix assumes Gate F remains a narrow wedge")

    subject_head = str(scope_packet.get("subject_head", "")).strip() or str(live_product_truth_packet.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 01 comparator matrix requires a subject head")

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        branch_name=_current_branch_name(root),
        scope_packet=scope_packet,
        live_product_truth_packet=live_product_truth_packet,
        post_merge_closeout_receipt=post_merge_closeout_receipt,
    )

    packet_path = (reports_root / OUTPUT_PACKET).resolve()
    receipt_path = (reports_root / OUTPUT_RECEIPT).resolve()
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    common.write_outputs(
        packet_path=packet_path,
        receipt_path=receipt_path,
        report_path=report_path,
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "packet_path": packet_path.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "report_path": report_path.as_posix(),
        "matrix_outcome": MATRIX_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the post-F Track 01 comparator matrix packet.")
    parser.add_argument(
        "--scope-packet",
        default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--live-product-truth-packet",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json",
    )
    parser.add_argument(
        "--post-merge-closeout-receipt",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_merge_closeout_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        scope_packet_path=common.resolve_path(root, args.scope_packet),
        live_product_truth_packet_path=common.resolve_path(root, args.live_product_truth_packet),
        post_merge_closeout_receipt_path=common.resolve_path(root, args.post_merge_closeout_receipt),
    )
    print(result["matrix_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
