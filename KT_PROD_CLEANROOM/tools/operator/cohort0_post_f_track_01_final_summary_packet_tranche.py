from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_01_comparative_scope_packet_tranche as scope_tranche
from tools.operator import cohort0_post_f_track_01_comparator_matrix_packet_tranche as matrix_tranche
from tools.operator import cohort0_post_f_track_01_metric_scorecard_contract_tranche as contract_tranche
from tools.operator import cohort0_post_f_track_01_first_bounded_comparative_execution_tranche as first_wave
from tools.operator import cohort0_post_f_track_01_second_bounded_comparative_execution_tranche as second_wave
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_01_final_summary_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_01_final_summary_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_01_FINAL_SUMMARY_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_TRACK_01_FINAL_SUMMARY_PACKET_BOUND"
SUMMARY_OUTCOME = "POST_F_TRACK_01_REPEATED_BOUNDED_ADVANTAGE_FROZEN__CANONICAL_WEDGE_ONLY"
TRACK_ID = contract_tranche.TRACK_ID
NEXT_MOVE = "AUTHOR_POST_F_TRACK_02_SCOPE_PACKET"


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


def _validated_row_summary(
    *,
    row_receipt: Dict[str, Any],
    expected_row_id: str,
) -> Dict[str, Any]:
    if str(row_receipt.get("row_id", "")).strip() != expected_row_id:
        raise RuntimeError(f"FAIL_CLOSED: expected row {expected_row_id}")
    if not bool(row_receipt.get("category_fair", False)):
        raise RuntimeError(f"FAIL_CLOSED: {expected_row_id} must remain category fair")
    return {
        "row_id": expected_row_id,
        "row_class": str(row_receipt.get("row_class", "")).strip(),
        "weighted_score": int(row_receipt.get("weighted_score", 0)),
        "normalized_score": row_receipt.get("normalized_score", None),
    }


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    branch_name: str,
    scope_packet: Dict[str, Any],
    matrix_packet: Dict[str, Any],
    contract_packet: Dict[str, Any],
    first_execution_packet: Dict[str, Any],
    first_execution_receipt: Dict[str, Any],
    first_scorecard: Dict[str, Any],
    first_verdict: Dict[str, Any],
    first_kt_row: Dict[str, Any],
    first_internal_row: Dict[str, Any],
    first_external_row: Dict[str, Any],
    second_variation_receipt: Dict[str, Any],
    second_execution_packet: Dict[str, Any],
    second_execution_receipt: Dict[str, Any],
    second_scorecard: Dict[str, Any],
    second_verdict: Dict[str, Any],
    second_kt_row: Dict[str, Any],
    second_internal_row: Dict[str, Any],
    second_external_row: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(scope_packet.get("authority_header", {}))

    first_wave_summary = {
        "execution_receipt_ref": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_RECEIPT}",
        "execution_packet_ref": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_PACKET}",
        "scorecard_ref": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_SCORECARD}",
        "verdict_ref": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_VERDICT}",
        "row_receipt_refs": {
            "kt": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_KT_ROW}",
            "internal": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_INTERNAL_ROW}",
            "external": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_EXTERNAL_ROW}",
        },
        "verdict": str(first_verdict.get("verdict", "")).strip(),
        "row_summaries": [
            _validated_row_summary(row_receipt=first_kt_row, expected_row_id="KT_CANONICAL_WEDGE"),
            _validated_row_summary(row_receipt=first_internal_row, expected_row_id="STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE"),
            _validated_row_summary(row_receipt=first_external_row, expected_row_id="ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW"),
        ],
    }
    second_wave_summary = {
        "variation_receipt_ref": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_VARIATION}",
        "execution_receipt_ref": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_RECEIPT}",
        "execution_packet_ref": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_PACKET}",
        "scorecard_ref": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_SCORECARD}",
        "verdict_ref": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_VERDICT}",
        "row_receipt_refs": {
            "kt": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_KT_ROW}",
            "internal": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_INTERNAL_ROW}",
            "external": f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_EXTERNAL_ROW}",
        },
        "variation_id": str(second_variation_receipt.get("variation_id", "")).strip(),
        "variation_type": str(second_variation_receipt.get("variation_type", "")).strip(),
        "verdict": str(second_verdict.get("verdict", "")).strip(),
        "row_summaries": [
            _validated_row_summary(row_receipt=second_kt_row, expected_row_id="KT_CANONICAL_WEDGE"),
            _validated_row_summary(row_receipt=second_internal_row, expected_row_id="STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE"),
            _validated_row_summary(row_receipt=second_external_row, expected_row_id="ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW"),
        ],
    }

    repeated_verdict = {
        "verdict_id": "KT_CANONICAL_WEDGE_REPEATED_BOUNDED_ADVANTAGE__TRACK_01_CLOSED",
        "statement": (
            "KT canonical wedge has repeated bounded category-fair advantage on the confirmed local_verifier_mode surface, "
            "including replay-and-operator-handoff stress."
        ),
        "confirmed_surface_wedge_id": str(scope_packet.get("confirmed_canonical_surface", {}).get("wedge_id", "")).strip(),
        "confirmed_surface_profile_id": str(scope_packet.get("confirmed_canonical_surface", {}).get("active_profile_id", "")).strip(),
        "comparison_category": str(scope_packet.get("comparison_category", {}).get("category_id", "")).strip(),
        "comparator_row_count": 3,
        "metric_count": len(contract_packet.get("metric_rules", [])),
        "waves_executed": 2,
        "same_tiny_matrix_across_waves": True,
        "same_five_metric_contract_across_waves": True,
        "category_fair": True,
        "first_wave_verdict": str(first_verdict.get("verdict", "")).strip(),
        "second_wave_verdict": str(second_verdict.get("verdict", "")).strip(),
        "holds_under_replay_and_operator_handoff_stress": True,
    }

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_final_summary_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "summary_outcome": SUMMARY_OUTCOME,
        "claim_boundary": (
            "This packet freezes Track 01 as a bounded comparative proof packet for the confirmed local_verifier_mode wedge only. "
            "It does not widen into best-AI, broad model, full-system, router, lobe, Kaggle, or broad commercial claims."
        ),
        "track_identity": {
            "track_id": TRACK_ID,
            "track_name": "Canonical Comparative Proof",
            "track_status": "CLOSED__BOUNDED_PROOF_PACKET_ONLY",
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
            "post_f_reaudit_passed": bool(authority_header.get("post_f_reaudit_passed", False)),
        },
        "bound_track_stack": {
            "scope_packet_ref": f"KT_PROD_CLEANROOM/reports/{scope_tranche.OUTPUT_PACKET}",
            "comparator_matrix_packet_ref": f"KT_PROD_CLEANROOM/reports/{matrix_tranche.OUTPUT_PACKET}",
            "metric_scorecard_contract_ref": f"KT_PROD_CLEANROOM/reports/{contract_tranche.OUTPUT_PACKET}",
            "first_wave": first_wave_summary,
            "second_wave": second_wave_summary,
        },
        "final_track_verdict": repeated_verdict,
        "forbidden_interpretations": [
            "Not a best AI claim.",
            "Not broad model superiority.",
            "Not full-system superiority.",
            "Not router or lobe superiority.",
            "Not Kaggle or math carryover.",
            "Not broad commercial expansion.",
        ],
        "source_refs": common.output_ref_dict(
            scope_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}"),
            comparator_matrix_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{matrix_tranche.OUTPUT_PACKET}"),
            metric_scorecard_contract=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{contract_tranche.OUTPUT_PACKET}"),
            first_execution_receipt=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_RECEIPT}"),
            first_scorecard=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_SCORECARD}"),
            first_verdict=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_VERDICT}"),
            second_variation_receipt=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_VARIATION}"),
            second_execution_receipt=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_RECEIPT}"),
            second_scorecard=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_SCORECARD}"),
            second_verdict=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_VERDICT}"),
        ),
        "subject_head": subject_head,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_final_summary_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "summary_outcome": SUMMARY_OUTCOME,
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "waves_executed": repeated_verdict["waves_executed"],
        "metric_count": repeated_verdict["metric_count"],
        "repeated_advantage_confirmed": True,
        "holds_under_replay_and_operator_handoff_stress": True,
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 01 Final Summary Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Summary outcome: `{SUMMARY_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Waves executed: `{repeated_verdict['waves_executed']}`",
            f"- Final bounded verdict: `{repeated_verdict['verdict_id']}`",
            f"- Statement: `{repeated_verdict['statement']}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    scope_packet_path: Path,
    matrix_packet_path: Path,
    contract_packet_path: Path,
    first_execution_packet_path: Path,
    first_execution_receipt_path: Path,
    first_scorecard_path: Path,
    first_verdict_path: Path,
    first_kt_row_path: Path,
    first_internal_row_path: Path,
    first_external_row_path: Path,
    second_variation_receipt_path: Path,
    second_execution_packet_path: Path,
    second_execution_receipt_path: Path,
    second_scorecard_path: Path,
    second_verdict_path: Path,
    second_kt_row_path: Path,
    second_internal_row_path: Path,
    second_external_row_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    scope_packet = common.load_json_required(root, scope_packet_path, label="Track 01 scope packet")
    matrix_packet = common.load_json_required(root, matrix_packet_path, label="Track 01 comparator matrix packet")
    contract_packet = common.load_json_required(root, contract_packet_path, label="Track 01 metric scorecard contract")
    first_execution_packet = common.load_json_required(root, first_execution_packet_path, label="Track 01 first execution packet")
    first_execution_receipt = common.load_json_required(root, first_execution_receipt_path, label="Track 01 first execution receipt")
    first_scorecard = common.load_json_required(root, first_scorecard_path, label="Track 01 first scorecard")
    first_verdict = common.load_json_required(root, first_verdict_path, label="Track 01 first verdict receipt")
    first_kt_row = common.load_json_required(root, first_kt_row_path, label="Track 01 first KT row receipt")
    first_internal_row = common.load_json_required(root, first_internal_row_path, label="Track 01 first internal row receipt")
    first_external_row = common.load_json_required(root, first_external_row_path, label="Track 01 first external row receipt")
    second_variation_receipt = common.load_json_required(root, second_variation_receipt_path, label="Track 01 second-wave variation receipt")
    second_execution_packet = common.load_json_required(root, second_execution_packet_path, label="Track 01 second execution packet")
    second_execution_receipt = common.load_json_required(root, second_execution_receipt_path, label="Track 01 second execution receipt")
    second_scorecard = common.load_json_required(root, second_scorecard_path, label="Track 01 second scorecard")
    second_verdict = common.load_json_required(root, second_verdict_path, label="Track 01 second verdict receipt")
    second_kt_row = common.load_json_required(root, second_kt_row_path, label="Track 01 second KT row receipt")
    second_internal_row = common.load_json_required(root, second_internal_row_path, label="Track 01 second internal row receipt")
    second_external_row = common.load_json_required(root, second_external_row_path, label="Track 01 second external row receipt")

    for payload, label in [
        (scope_packet, "Track 01 scope packet"),
        (matrix_packet, "Track 01 comparator matrix packet"),
        (contract_packet, "Track 01 metric scorecard contract"),
        (first_execution_packet, "Track 01 first execution packet"),
        (first_execution_receipt, "Track 01 first execution receipt"),
        (first_scorecard, "Track 01 first scorecard"),
        (first_verdict, "Track 01 first verdict receipt"),
        (first_kt_row, "Track 01 first KT row receipt"),
        (first_internal_row, "Track 01 first internal row receipt"),
        (first_external_row, "Track 01 first external row receipt"),
        (second_variation_receipt, "Track 01 second-wave variation receipt"),
        (second_execution_packet, "Track 01 second execution packet"),
        (second_execution_receipt, "Track 01 second execution receipt"),
        (second_scorecard, "Track 01 second scorecard"),
        (second_verdict, "Track 01 second verdict receipt"),
        (second_kt_row, "Track 01 second KT row receipt"),
        (second_internal_row, "Track 01 second internal row receipt"),
        (second_external_row, "Track 01 second external row receipt"),
    ]:
        _require_pass(payload, label=label)

    if str(scope_packet.get("scope_outcome", "")).strip() != scope_tranche.SCOPE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the bound scope packet")
    if str(matrix_packet.get("matrix_outcome", "")).strip() != matrix_tranche.MATRIX_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the bound comparator matrix packet")
    if str(contract_packet.get("contract_outcome", "")).strip() != contract_tranche.CONTRACT_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the bound scorecard contract")
    if str(first_execution_receipt.get("verdict", "")).strip() != "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR":
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires a first-wave bounded advantage")
    if str(second_execution_receipt.get("verdict", "")).strip() != "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR":
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires a second-wave bounded advantage")
    if str(second_execution_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRACK_01_FINAL_SUMMARY_PACKET":
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the second wave to point here next")
    if not bool(second_variation_receipt.get("same_three_row_matrix", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the second wave to preserve the three-row matrix")
    if not bool(second_variation_receipt.get("same_five_metric_contract", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the second wave to preserve the five-metric contract")

    if str(first_kt_row.get("row_class", "")).strip() != "PASS" or int(first_kt_row.get("weighted_score", 0)) != 26:
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the first-wave canonical wedge to stay PASS at 26")
    if str(second_kt_row.get("row_class", "")).strip() != "PASS" or int(second_kt_row.get("weighted_score", 0)) != 26:
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires the second-wave canonical wedge to stay PASS at 26")

    subject_head = str(second_execution_receipt.get("subject_head", "")).strip() or str(first_execution_receipt.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 01 final summary requires a subject head")

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        branch_name=_current_branch_name(root),
        scope_packet=scope_packet,
        matrix_packet=matrix_packet,
        contract_packet=contract_packet,
        first_execution_packet=first_execution_packet,
        first_execution_receipt=first_execution_receipt,
        first_scorecard=first_scorecard,
        first_verdict=first_verdict,
        first_kt_row=first_kt_row,
        first_internal_row=first_internal_row,
        first_external_row=first_external_row,
        second_variation_receipt=second_variation_receipt,
        second_execution_packet=second_execution_packet,
        second_execution_receipt=second_execution_receipt,
        second_scorecard=second_scorecard,
        second_verdict=second_verdict,
        second_kt_row=second_kt_row,
        second_internal_row=second_internal_row,
        second_external_row=second_external_row,
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
        "summary_outcome": SUMMARY_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the final Track 01 summary proof packet.")
    parser.add_argument("--scope-packet", default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}")
    parser.add_argument("--matrix-packet", default=f"{common.REPORTS_ROOT_REL}/{matrix_tranche.OUTPUT_PACKET}")
    parser.add_argument("--contract-packet", default=f"{common.REPORTS_ROOT_REL}/{contract_tranche.OUTPUT_PACKET}")
    parser.add_argument("--first-execution-packet", default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_PACKET}")
    parser.add_argument("--first-execution-receipt", default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_RECEIPT}")
    parser.add_argument("--first-scorecard", default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_SCORECARD}")
    parser.add_argument("--first-verdict", default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_VERDICT}")
    parser.add_argument("--first-kt-row", default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_KT_ROW}")
    parser.add_argument("--first-internal-row", default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_INTERNAL_ROW}")
    parser.add_argument("--first-external-row", default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_EXTERNAL_ROW}")
    parser.add_argument("--second-variation-receipt", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_VARIATION}")
    parser.add_argument("--second-execution-packet", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_PACKET}")
    parser.add_argument("--second-execution-receipt", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_RECEIPT}")
    parser.add_argument("--second-scorecard", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_SCORECARD}")
    parser.add_argument("--second-verdict", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_VERDICT}")
    parser.add_argument("--second-kt-row", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_KT_ROW}")
    parser.add_argument("--second-internal-row", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_INTERNAL_ROW}")
    parser.add_argument("--second-external-row", default=f"{common.REPORTS_ROOT_REL}/{second_wave.OUTPUT_EXTERNAL_ROW}")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        scope_packet_path=common.resolve_path(root, args.scope_packet),
        matrix_packet_path=common.resolve_path(root, args.matrix_packet),
        contract_packet_path=common.resolve_path(root, args.contract_packet),
        first_execution_packet_path=common.resolve_path(root, args.first_execution_packet),
        first_execution_receipt_path=common.resolve_path(root, args.first_execution_receipt),
        first_scorecard_path=common.resolve_path(root, args.first_scorecard),
        first_verdict_path=common.resolve_path(root, args.first_verdict),
        first_kt_row_path=common.resolve_path(root, args.first_kt_row),
        first_internal_row_path=common.resolve_path(root, args.first_internal_row),
        first_external_row_path=common.resolve_path(root, args.first_external_row),
        second_variation_receipt_path=common.resolve_path(root, args.second_variation_receipt),
        second_execution_packet_path=common.resolve_path(root, args.second_execution_packet),
        second_execution_receipt_path=common.resolve_path(root, args.second_execution_receipt),
        second_scorecard_path=common.resolve_path(root, args.second_scorecard),
        second_verdict_path=common.resolve_path(root, args.second_verdict),
        second_kt_row_path=common.resolve_path(root, args.second_kt_row),
        second_internal_row_path=common.resolve_path(root, args.second_internal_row),
        second_external_row_path=common.resolve_path(root, args.second_external_row),
    )
    print(result["summary_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
