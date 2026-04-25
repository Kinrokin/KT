from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_01_comparator_matrix_packet_tranche as matrix_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_01_metric_scorecard_contract.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_01_metric_scorecard_contract_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_01_METRIC_SCORECARD_CONTRACT_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_TRACK_01_METRIC_SCORECARD_CONTRACT_BOUND"
CONTRACT_OUTCOME = "POST_F_TRACK_01_METRIC_SCORECARD_CONTRACT_DEFINED__TINY_WEDGE_ONLY"
TRACK_ID = matrix_tranche.TRACK_ID
NEXT_MOVE = "EXECUTE_POST_F_TRACK_01_FIRST_BOUNDED_COMPARATIVE_EXECUTION"


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
    matrix_packet: Dict[str, Any],
    live_product_truth_packet: Dict[str, Any],
    post_merge_closeout_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(matrix_packet.get("authority_header", {}))
    matrix_purpose = dict(matrix_packet.get("matrix_purpose", {}))
    canonical_surface = dict(live_product_truth_packet.get("selected_wedge_summary", {}))

    metric_rules = [
        {
            "metric_id": "receipt_completeness",
            "weight": 3,
            "hard_stop": True,
            "evidence_sources": [
                "row_execution_receipt",
                "pass_fail_receipt",
                "audit_packet_manifest",
                "required_receipt_index",
            ],
            "scoring_rule": {
                "PASS": "All required wedge receipts are emitted, referenced, and internally consistent.",
                "PARTIAL": "All core required receipts exist, but one bounded supporting cross-reference is incomplete.",
                "FAIL": "A required wedge receipt is missing or inconsistent while the row still claims completion.",
                "DEFERRED": "The receipt bundle is missing entirely or comparator selection/category-fairness is not yet bound.",
            },
        },
        {
            "metric_id": "replayability",
            "weight": 3,
            "hard_stop": True,
            "evidence_sources": [
                "audit_packet_manifest",
                "replay_reference_bundle",
                "receipt_cross_refs",
            ],
            "scoring_rule": {
                "PASS": "The run can be replayed or audited from returned refs alone without repo archaeology.",
                "PARTIAL": "Replay is possible with one bounded documented manual step and no hidden local state.",
                "FAIL": "Replay requires repo archaeology, hidden state, or non-returned artifacts.",
                "DEFERRED": "Replay artifacts or cross-references are missing.",
            },
        },
        {
            "metric_id": "fail_closed_behavior",
            "weight": 3,
            "hard_stop": True,
            "evidence_sources": [
                "pass_fail_receipt",
                "fail_closed_event_register",
                "error_boundary_log",
            ],
            "scoring_rule": {
                "PASS": "Bounded defects terminate fail-closed and are surfaced explicitly in the returned evidence.",
                "PARTIAL": "The defect terminates fail-closed, but one event annotation or boundary note is incomplete.",
                "FAIL": "The row drifts into silent success, ambiguous state, or open-ended continuation on bounded defect.",
                "DEFERRED": "Fail-closed path evidence is absent or the event register is missing.",
            },
        },
        {
            "metric_id": "operator_clarity_and_bounded_execution_integrity",
            "weight": 2,
            "hard_stop": False,
            "evidence_sources": [
                "bounded_operator_run_script",
                "operator_run_transcript",
                "execution_contract_echo",
            ],
            "scoring_rule": {
                "PASS": "The operator path is clear, bounded, and matches the declared wedge contract with no hidden steps.",
                "PARTIAL": "The path stays bounded, but one manual clarification is needed.",
                "FAIL": "The path drifts from the declared contract or relies on hidden operator steps.",
                "DEFERRED": "Run instructions, transcript, or contract echo are missing.",
            },
        },
        {
            "metric_id": "useful_output_success_under_wedge_contract",
            "weight": 2,
            "hard_stop": False,
            "evidence_sources": [
                "execution_receipt",
                "useful_output_manifest",
                "result_summary",
            ],
            "scoring_rule": {
                "PASS": "The bounded task completes usefully without leaving the confirmed wedge surface.",
                "PARTIAL": "The result is materially useful, but one bounded defect remains.",
                "FAIL": "The task does not complete usefully or requires stepping outside the wedge contract.",
                "DEFERRED": "Useful-output evidence is missing.",
            },
        },
    ]

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_metric_scorecard_contract.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This contract binds only the Track 01 metric scorecard for the confirmed canonical wedge. "
            "It defines how bounded comparative rows are scored and interpreted without executing the benchmark or widening any product claim."
        ),
        "execution_status": EXECUTION_STATUS,
        "contract_outcome": CONTRACT_OUTCOME,
        "track_identity": {
            "track_id": TRACK_ID,
            "contract_type": "metric_scorecard",
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
        "confirmed_surface_lock": {
            "wedge_id": str(canonical_surface.get("wedge_id", "")).strip(),
            "active_profile_id": str(canonical_surface.get("active_profile_id", "")).strip(),
            "comparison_category": str(matrix_purpose.get("comparison_category", "")).strip(),
            "surface_lock": str(matrix_purpose.get("surface_lock", "")).strip(),
        },
        "score_states": {
            "PASS": {"points": 2, "interpretation": "Metric satisfied cleanly within the wedge contract."},
            "PARTIAL": {"points": 1, "interpretation": "Metric mostly satisfied, but one bounded defect remains."},
            "FAIL": {"points": 0, "interpretation": "Metric not satisfied inside the wedge contract."},
            "DEFERRED": {"points": None, "interpretation": "Metric cannot be counted because required evidence or fairness binding is missing."},
        },
        "metric_rules": metric_rules,
        "aggregation_rule": {
            "weighting_rule": "weighted_score = sum(metric_points * weight) across non-deferred metrics",
            "max_weighted_score": 26,
            "normalized_score_rule": "normalized_score = weighted_score / 26 when no metric is deferred; otherwise null",
            "hard_stop_metrics": [
                "receipt_completeness",
                "replayability",
                "fail_closed_behavior",
            ],
            "row_deferred_condition": (
                "Any metric is DEFERRED, any comparator-selection receipt is missing, or category-fairness is broken."
            ),
            "row_fail_condition": (
                "Not deferred, and either any hard-stop metric is FAIL or weighted_score <= 13."
            ),
            "row_partial_condition": (
                "Not deferred, no hard-stop metric is FAIL, and weighted_score is between 14 and 20 inclusive."
            ),
            "row_pass_condition": (
                "Not deferred, no hard-stop metric is FAIL, and weighted_score >= 21."
            ),
        },
        "comparative_verdict_rulebook": {
            "allowed_verdicts": [
                {
                    "verdict": "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR",
                    "rule": (
                        "All compared rows are category-fair and non-deferred, the KT canonical row is PASS, "
                        "and every comparator row is PARTIAL or FAIL with a lower weighted score."
                    ),
                },
                {
                    "verdict": "KT_CANONICAL_WEDGE_PARITY__CATEGORY_FAIR",
                    "rule": (
                        "All compared rows are category-fair and non-deferred, at least one comparator row shares the KT row class, "
                        "and the weighted-score delta is <= 2 with no comparator outranking KT."
                    ),
                },
                {
                    "verdict": "KT_CANONICAL_WEDGE_DEFICIT__CATEGORY_FAIR",
                    "rule": (
                        "A category-fair comparator row outranks KT by row class, or by >= 3 weighted points at the same row class."
                    ),
                },
                {
                    "verdict": "DEFERRED__COMPARATOR_SELECTION_OR_METRIC_DEFECT",
                    "rule": (
                        "Any compared row is deferred, any selection receipt is missing, or category-fairness is broken."
                    ),
                },
            ]
        },
        "anti_drift_guardrails": [
            "No broad model-quality interpretation.",
            "No full-system inference.",
            "No Kaggle or math leakage.",
            "No translation of Track 01 outcomes into broader router, lobe, or civilization claims.",
            "No broad commercialization or vendor-bakeoff framing from Track 01 scorecards.",
        ],
        "source_refs": common.output_ref_dict(
            matrix_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{matrix_tranche.OUTPUT_PACKET}"),
            live_product_truth_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json"),
            post_merge_closeout_receipt=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_post_merge_closeout_receipt.json"),
        ),
        "subject_head": subject_head,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_metric_scorecard_contract_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "contract_outcome": CONTRACT_OUTCOME,
        "track_id": TRACK_ID,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "metric_count": len(packet["metric_rules"]),
        "max_weighted_score": packet["aggregation_rule"]["max_weighted_score"],
        "next_lawful_move": NEXT_MOVE,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 01 Metric Scorecard Contract Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Contract outcome: `{CONTRACT_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Metrics bound: `{len(packet['metric_rules'])}`",
            f"- Max weighted score: `{packet['aggregation_rule']['max_weighted_score']}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    matrix_packet_path: Path,
    live_product_truth_packet_path: Path,
    post_merge_closeout_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    matrix_packet = common.load_json_required(root, matrix_packet_path, label="Track 01 comparator matrix packet")
    live_product_truth_packet = common.load_json_required(root, live_product_truth_packet_path, label="post-F live product truth packet")
    post_merge_closeout_receipt = common.load_json_required(root, post_merge_closeout_receipt_path, label="post-merge closeout receipt")

    _require_pass(matrix_packet, label="Track 01 comparator matrix packet")
    _require_pass(live_product_truth_packet, label="post-F live product truth packet")
    if str(post_merge_closeout_receipt.get("status", "")).strip() != "PASS__CANONICAL_CLEAN_CLOSEOUT_MERGED_TO_MAIN":
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract requires the merged closeout receipt")
    if str(matrix_packet.get("matrix_outcome", "")).strip() != matrix_tranche.MATRIX_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract requires the bound comparator matrix")
    if str(matrix_packet.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRACK_01_METRIC_SCORECARD_CONTRACT":
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract requires the matrix packet to point here next")

    authority_header = dict(matrix_packet.get("authority_header", {}))
    if not bool(authority_header.get("working_branch_non_authoritative_until_protected_merge", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract requires explicit non-authoritative branch posture")

    canonical_live_status = dict(live_product_truth_packet.get("canonical_live_product_status", {}))
    if str(canonical_live_status.get("current_product_posture", "")).strip() != common.GATE_F_CONFIRMED_POSTURE:
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract requires the confirmed Gate F wedge posture")
    if bool(canonical_live_status.get("gate_f_open", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract assumes Gate F remains a narrow wedge")

    subject_head = str(matrix_packet.get("subject_head", "")).strip() or str(live_product_truth_packet.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract requires a subject head")

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        branch_name=_current_branch_name(root),
        matrix_packet=matrix_packet,
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
        "contract_outcome": CONTRACT_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the post-F Track 01 metric scorecard contract.")
    parser.add_argument(
        "--matrix-packet",
        default=f"{common.REPORTS_ROOT_REL}/{matrix_tranche.OUTPUT_PACKET}",
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
        matrix_packet_path=common.resolve_path(root, args.matrix_packet),
        live_product_truth_packet_path=common.resolve_path(root, args.live_product_truth_packet),
        post_merge_closeout_receipt_path=common.resolve_path(root, args.post_merge_closeout_receipt),
    )
    print(result["contract_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
