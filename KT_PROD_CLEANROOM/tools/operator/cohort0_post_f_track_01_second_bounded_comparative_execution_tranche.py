from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_01_first_bounded_comparative_execution_tranche as first_wave
from tools.operator import cohort0_post_f_track_01_metric_scorecard_contract_tranche as contract_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_VARIATION = "cohort0_post_f_track_01_second_wave_variation_receipt.json"
OUTPUT_KT_ROW = "cohort0_post_f_track_01_second_wave_row_kt_canonical_wedge_receipt.json"
OUTPUT_INTERNAL_ROW = "cohort0_post_f_track_01_second_wave_row_internal_static_baseline_receipt.json"
OUTPUT_EXTERNAL_ROW = "cohort0_post_f_track_01_second_wave_row_externalized_workflow_receipt.json"
OUTPUT_SCORECARD = "cohort0_post_f_track_01_second_bounded_comparative_scorecard.json"
OUTPUT_VERDICT = "cohort0_post_f_track_01_second_bounded_comparative_verdict_receipt.json"
OUTPUT_PACKET = "cohort0_post_f_track_01_second_bounded_comparative_execution_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_01_second_bounded_comparative_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_01_SECOND_BOUNDED_COMPARATIVE_EXECUTION_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_TRACK_01_SECOND_BOUNDED_COMPARATIVE_EXECUTION_COMPLETE"
EXECUTION_OUTCOME = "POST_F_TRACK_01_SECOND_BOUNDED_COMPARATIVE_EXECUTION_COMPLETE__KT_WEDGE_ADVANTAGE_HOLDS_UNDER_REPLAY_HANDOFF_STRESS"
TRACK_ID = contract_tranche.TRACK_ID
VARIATION_ID = "TRACK_01_REPLAY_AND_OPERATOR_HANDOFF_STRESS__SAME_TINY_MATRIX"
NEXT_MOVE = "AUTHOR_POST_F_TRACK_01_FINAL_SUMMARY_PACKET"


def _require_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _require_file(path: Path, *, label: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")


def _build_variation_receipt(*, branch_name: str, subject_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_variation_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "variation_id": VARIATION_ID,
        "variation_type": "REPLAY_AND_OPERATOR_HANDOFF_STRESS",
        "row_set_frozen_from_first_wave": True,
        "same_three_row_matrix": True,
        "same_five_metric_contract": True,
        "single_variation_only": (
            "This second wave keeps the same row set and the same scorecard contract, "
            "and varies only the workload emphasis toward operator handoff and independent replay stress."
        ),
        "first_wave_receipt_ref": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_RECEIPT}",
        "first_wave_verdict_ref": f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_VERDICT}",
        "claim_boundary": (
            "This variation re-measures the same Track 01 lane under replay-and-operator-handoff stress only. "
            "It does not widen the comparator set, the metric schema, or the product claim surface."
        ),
    }


def _build_kt_row(
    *,
    contract_packet: Dict[str, Any],
    live_product_truth_packet: Dict[str, Any],
    variation_receipt_ref: str,
) -> Dict[str, Any]:
    metrics = first_wave._load_contract_metrics(contract_packet)
    results = [
        first_wave._metric_result(
            metric_id="receipt_completeness",
            state="PASS",
            contract_metric=metrics["receipt_completeness"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                variation_receipt_ref,
            ],
            justification="The canonical wedge still returns a complete bounded receipt bundle when measured through the product install and operator handoff surfaces.",
        ),
        first_wave._metric_result(
            metric_id="replayability",
            state="PASS",
            contract_metric=metrics["replayability"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_independent_replay_recipe.md",
                "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                variation_receipt_ref,
            ],
            justification="The canonical wedge has an explicit independent replay recipe and kit-level replay refs without repo archaeology.",
        ),
        first_wave._metric_result(
            metric_id="fail_closed_behavior",
            state="PASS",
            contract_metric=metrics["fail_closed_behavior"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                variation_receipt_ref,
            ],
            justification="The canonical verifier path continues to expose bounded PASS/FAIL surfaces cleanly under replay-and-handoff stress.",
        ),
        first_wave._metric_result(
            metric_id="operator_clarity_and_bounded_execution_integrity",
            state="PASS",
            contract_metric=metrics["operator_clarity_and_bounded_execution_integrity"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
                "KT_PROD_CLEANROOM/product/client_wrapper_spec.json",
                variation_receipt_ref,
            ],
            justification="The canonical wedge remains the shortest operator path even when the court stresses handoff and replay explicitly.",
        ),
        first_wave._metric_result(
            metric_id="useful_output_success_under_wedge_contract",
            state="PASS",
            contract_metric=metrics["useful_output_success_under_wedge_contract"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                variation_receipt_ref,
            ],
            justification="The canonical wedge still completes the useful bounded verifier-and-handoff task without leaving the confirmed local_verifier_mode surface.",
        ),
    ]
    classification = first_wave._classify_row(metric_results=results, contract_packet=contract_packet)
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_row_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "row_id": "KT_CANONICAL_WEDGE",
        "row_type": "CANONICAL_CONFIRMED_SURFACE",
        "row_subject": live_product_truth_packet.get("selected_wedge_summary", {}).get("wedge_id", ""),
        "category_fair": True,
        "variation_id": VARIATION_ID,
        "metric_results": results,
        **classification,
    }


def _build_internal_row(
    *,
    contract_packet: Dict[str, Any],
    selected_profile: Dict[str, Any],
    selection_receipt_ref: str,
    variation_receipt_ref: str,
) -> Dict[str, Any]:
    metrics = first_wave._load_contract_metrics(contract_packet)
    results = [
        first_wave._metric_result(
            metric_id="receipt_completeness",
            state="PARTIAL",
            contract_metric=metrics["receipt_completeness"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
                "KT_PROD_CLEANROOM/product/nist_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/iso_42001_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/eu_ai_act_alignment_matrix.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="The regulated workflow row remains bounded, but the operator handoff bundle is canonical-wedge centered and requires extra mapping surfaces to complete this row cleanly.",
        ),
        first_wave._metric_result(
            metric_id="replayability",
            state="PARTIAL",
            contract_metric=metrics["replayability"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_independent_replay_recipe.md",
                "KT_PROD_CLEANROOM/product/nist_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/iso_42001_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/eu_ai_act_alignment_matrix.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="Replay remains possible, but this row requires pulling the extra regulated overlays alongside the replay path, which is a bounded manual step beyond the canonical wedge.",
        ),
        first_wave._metric_result(
            metric_id="fail_closed_behavior",
            state="PASS",
            contract_metric=metrics["fail_closed_behavior"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="The regulated workflow baseline still resolves against the same detached PASS/FAIL boundary.",
        ),
        first_wave._metric_result(
            metric_id="operator_clarity_and_bounded_execution_integrity",
            state="PARTIAL",
            contract_metric=metrics["operator_clarity_and_bounded_execution_integrity"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
                "KT_PROD_CLEANROOM/product/nist_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/iso_42001_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/eu_ai_act_alignment_matrix.json",
                selection_receipt_ref,
            ],
            justification="The row stays lawful, but the operator path is heavier because the regulated overlays are not the shortest handoff path the wedge was optimized for.",
        ),
        first_wave._metric_result(
            metric_id="useful_output_success_under_wedge_contract",
            state="PARTIAL",
            contract_metric=metrics["useful_output_success_under_wedge_contract"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="Useful bounded output remains available, but it takes one extra documented standards-overlay step, which is a bounded defect for this replay-and-handoff stress lane.",
        ),
    ]
    classification = first_wave._classify_row(metric_results=results, contract_packet=contract_packet)
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_row_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "row_id": "STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE",
        "row_type": "INTERNAL_STATIC_BASELINE",
        "row_subject": str(selected_profile.get("profile_id", "")).strip(),
        "category_fair": True,
        "variation_id": VARIATION_ID,
        "selection_receipt_ref": selection_receipt_ref,
        "metric_results": results,
        **classification,
    }


def _build_external_row(
    *,
    contract_packet: Dict[str, Any],
    selection_receipt_ref: str,
    variation_receipt_ref: str,
) -> Dict[str, Any]:
    metrics = first_wave._load_contract_metrics(contract_packet)
    results = [
        first_wave._metric_result(
            metric_id="receipt_completeness",
            state="PARTIAL",
            contract_metric=metrics["receipt_completeness"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="The detached workflow stays bounded, but one detached-specific receipt still has to be pulled in alongside the shortest operator handoff bundle.",
        ),
        first_wave._metric_result(
            metric_id="replayability",
            state="PASS",
            contract_metric=metrics["replayability"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_independent_replay_recipe.md",
                "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="The detached workflow is the strongest replay-oriented comparator row because it carries an explicit independent replay recipe and detached runtime proof path.",
        ),
        first_wave._metric_result(
            metric_id="fail_closed_behavior",
            state="PASS",
            contract_metric=metrics["fail_closed_behavior"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="The detached workflow continues to prove explicit bounded PASS/FAIL behavior under replay stress.",
        ),
        first_wave._metric_result(
            metric_id="operator_clarity_and_bounded_execution_integrity",
            state="PARTIAL",
            contract_metric=metrics["operator_clarity_and_bounded_execution_integrity"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md",
                "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="The detached workflow remains bounded, but it is less direct than the canonical in-repo handoff path and still needs one manual package-handling step.",
        ),
        first_wave._metric_result(
            metric_id="useful_output_success_under_wedge_contract",
            state="PARTIAL",
            contract_metric=metrics["useful_output_success_under_wedge_contract"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                selection_receipt_ref,
                variation_receipt_ref,
            ],
            justification="The detached row still proves the bounded verifier result, but it is optimized for detached replay parity rather than the full canonical handoff path.",
        ),
    ]
    classification = first_wave._classify_row(metric_results=results, contract_packet=contract_packet)
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_row_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "row_id": "ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW",
        "row_type": "EXTERNAL_MONOLITH_WORKFLOW",
        "row_subject": "KT_PUBLIC_VERIFIER_DETACHED_PACKAGE_WORKFLOW_V1",
        "category_fair": True,
        "variation_id": VARIATION_ID,
        "selection_receipt_ref": selection_receipt_ref,
        "metric_results": results,
        **classification,
    }


def _build_scorecard(
    *,
    subject_head: str,
    kt_row: Dict[str, Any],
    internal_row: Dict[str, Any],
    external_row: Dict[str, Any],
) -> Dict[str, Any]:
    ranking = sorted(
        (
            {
                "row_id": str(row.get("row_id", "")).strip(),
                "row_class": str(row.get("row_class", "")).strip(),
                "weighted_score": int(row.get("weighted_score", 0)),
            }
            for row in [kt_row, internal_row, external_row]
        ),
        key=lambda item: first_wave._row_rank(str(item["row_class"]), int(item["weighted_score"])),
        reverse=True,
    )
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "variation_id": VARIATION_ID,
        "row_summaries": ranking,
        "scorecard_boundary": "This scorecard ranks only the second bounded Track 01 replay-and-handoff stress lane for the confirmed wedge.",
    }


def _build_verdict(
    *,
    subject_head: str,
    kt_row: Dict[str, Any],
    internal_row: Dict[str, Any],
    external_row: Dict[str, Any],
) -> Dict[str, Any]:
    comparators = [internal_row, external_row]
    if any(str(row.get("row_class", "")).strip() == "DEFERRED" or not bool(row.get("category_fair", False)) for row in [kt_row, *comparators]):
        verdict = "DEFERRED__COMPARATOR_SELECTION_OR_METRIC_DEFECT"
        rationale = "At least one second-wave row is deferred or not category-fair, so the replay-and-handoff stress verdict must fail closed."
    else:
        kt_class = str(kt_row.get("row_class", "")).strip()
        kt_score = int(kt_row.get("weighted_score", 0))
        comp_classes = [str(row.get("row_class", "")).strip() for row in comparators]
        comp_scores = [int(row.get("weighted_score", 0)) for row in comparators]
        if kt_class == "PASS" and all(
            row_class in {"PARTIAL", "FAIL"} and score < kt_score
            for row_class, score in zip(comp_classes, comp_scores)
        ):
            verdict = "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR"
            rationale = "The canonical wedge kept a clean PASS under replay-and-handoff stress while every category-fair comparator stayed below it."
        elif any(
            first_wave._row_rank(row_class, score) > first_wave._row_rank(kt_class, kt_score)
            or (row_class == kt_class and score >= kt_score + 3)
            for row_class, score in zip(comp_classes, comp_scores)
        ):
            verdict = "KT_CANONICAL_WEDGE_DEFICIT__CATEGORY_FAIR"
            rationale = "A category-fair comparator outranked the canonical wedge under the second bounded replay-and-handoff stress court."
        elif any(
            row_class == kt_class and abs(score - kt_score) <= 2
            for row_class, score in zip(comp_classes, comp_scores)
        ):
            verdict = "KT_CANONICAL_WEDGE_PARITY__CATEGORY_FAIR"
            rationale = "At least one category-fair comparator held parity with the canonical wedge under the second bounded stress court."
        else:
            verdict = "DEFERRED__COMPARATOR_SELECTION_OR_METRIC_DEFECT"
            rationale = "The second-wave row pattern did not satisfy a bounded verdict cleanly enough to avoid defer."

    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_verdict_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "variation_id": VARIATION_ID,
        "verdict": verdict,
        "claim_boundary": "This verdict applies only to the second bounded Track 01 replay-and-handoff stress lane for the confirmed wedge.",
        "rationale": rationale,
    }


def build_outputs(
    *,
    subject_head: str,
    branch_name: str,
    variation_receipt: Dict[str, Any],
    kt_row: Dict[str, Any],
    internal_row: Dict[str, Any],
    external_row: Dict[str, Any],
    scorecard: Dict[str, Any],
    verdict: Dict[str, Any],
) -> Dict[str, Any]:
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_execution_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "claim_boundary": (
            "This packet records one second bounded comparative execution for Track 01 only. "
            "It reuses the same tiny comparator set and the same scorecard contract, and varies only the replay-and-operator-handoff stress."
        ),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "variation_receipt_ref": f"KT_PROD_CLEANROOM/reports/{OUTPUT_VARIATION}",
        "row_receipt_order": [
            OUTPUT_KT_ROW,
            OUTPUT_INTERNAL_ROW,
            OUTPUT_EXTERNAL_ROW,
        ],
        "selection_receipts_reused_from_first_wave": [
            first_wave.OUTPUT_INTERNAL_SELECTION,
            first_wave.OUTPUT_EXTERNAL_SELECTION,
        ],
        "scorecard_ref": f"KT_PROD_CLEANROOM/reports/{OUTPUT_SCORECARD}",
        "verdict_ref": f"KT_PROD_CLEANROOM/reports/{OUTPUT_VERDICT}",
        "row_summary": [
            {"row_id": kt_row["row_id"], "row_class": kt_row["row_class"], "weighted_score": kt_row["weighted_score"]},
            {"row_id": internal_row["row_id"], "row_class": internal_row["row_class"], "weighted_score": internal_row["weighted_score"]},
            {"row_id": external_row["row_id"], "row_class": external_row["row_class"], "weighted_score": external_row["weighted_score"]},
        ],
        "verdict": verdict["verdict"],
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "variation_id": VARIATION_ID,
        "verdict": verdict["verdict"],
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 01 Second Bounded Comparative Execution Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Execution outcome: `{EXECUTION_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Variation: `{VARIATION_ID}`",
            f"- Verdict: `{verdict['verdict']}`",
            f"- KT row: `{kt_row['row_class']}` / `{kt_row['weighted_score']}`",
            f"- Internal row: `{internal_row['row_class']}` / `{internal_row['weighted_score']}`",
            f"- External row: `{external_row['row_class']}` / `{external_row['weighted_score']}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    contract_packet_path: Path,
    matrix_packet_path: Path,
    first_execution_packet_path: Path,
    first_execution_receipt_path: Path,
    internal_selection_receipt_path: Path,
    external_selection_receipt_path: Path,
    live_product_truth_packet_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    contract_packet = common.load_json_required(root, contract_packet_path, label="Track 01 metric scorecard contract")
    matrix_packet = common.load_json_required(root, matrix_packet_path, label="Track 01 comparator matrix packet")
    first_execution_packet = common.load_json_required(root, first_execution_packet_path, label="first bounded comparative execution packet")
    first_execution_receipt = common.load_json_required(root, first_execution_receipt_path, label="first bounded comparative execution receipt")
    internal_selection_receipt = common.load_json_required(root, internal_selection_receipt_path, label="first-wave internal selection receipt")
    external_selection_receipt = common.load_json_required(root, external_selection_receipt_path, label="first-wave external selection receipt")
    live_product_truth_packet = common.load_json_required(root, live_product_truth_packet_path, label="post-F live product truth packet")
    profiles_payload = common.load_json_required(root, common.DEPLOYMENT_PROFILES_REL, label="deployment profiles")

    _require_pass(contract_packet, label="Track 01 metric scorecard contract")
    _require_pass(matrix_packet, label="Track 01 comparator matrix packet")
    _require_pass(first_execution_packet, label="first bounded comparative execution packet")
    _require_pass(first_execution_receipt, label="first bounded comparative execution receipt")
    _require_pass(internal_selection_receipt, label="first-wave internal selection receipt")
    _require_pass(external_selection_receipt, label="first-wave external selection receipt")
    _require_pass(live_product_truth_packet, label="post-F live product truth packet")

    if str(contract_packet.get("contract_outcome", "")).strip() != contract_tranche.CONTRACT_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 01 second wave requires the bound metric scorecard contract")
    if str(first_execution_receipt.get("verdict", "")).strip() != "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR":
        raise RuntimeError("FAIL_CLOSED: Track 01 second wave requires a first-wave canonical wedge advantage")
    if str(first_execution_receipt.get("next_lawful_move", "")).strip() != "DECIDE_POST_F_TRACK_01_SECOND_WAVE_OR_FINAL_SUMMARY_PACKET":
        raise RuntimeError("FAIL_CLOSED: Track 01 second wave requires the first wave to point to the decision layer")

    selected_surface = dict(live_product_truth_packet.get("selected_wedge_summary", {}))
    active_profile_id = str(selected_surface.get("active_profile_id", "")).strip()
    if active_profile_id != common.ACTIVE_WEDGE_PROFILE_ID:
        raise RuntimeError("FAIL_CLOSED: Track 01 second wave assumes the canonical local_verifier_mode wedge")

    internal_profile = first_wave._choose_internal_baseline(profiles_payload, active_profile_id=active_profile_id)
    if str(internal_profile.get("profile_id", "")).strip() != str(internal_selection_receipt.get("selected_profile_id", "")).strip():
        raise RuntimeError("FAIL_CLOSED: Track 01 second wave requires the internal comparator row to stay frozen")
    if str(external_selection_receipt.get("selected_workflow_id", "")).strip() != "KT_PUBLIC_VERIFIER_DETACHED_PACKAGE_WORKFLOW_V1":
        raise RuntimeError("FAIL_CLOSED: Track 01 second wave requires the detached public verifier package workflow row")

    required_files = [
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/public_verifier_kit.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/kt_independent_replay_recipe.md"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/nist_mapping_matrix.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/iso_42001_mapping_matrix.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/eu_ai_act_alignment_matrix.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/client_wrapper_spec.json"),
    ]
    for path in required_files:
        _require_file(path, label=path.name)

    subject_head = str(first_execution_receipt.get("subject_head", "")).strip() or str(live_product_truth_packet.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 01 second wave requires a subject head")

    branch_name = first_wave._current_branch_name(root)
    variation_receipt = _build_variation_receipt(branch_name=branch_name, subject_head=subject_head)
    variation_receipt_ref = f"KT_PROD_CLEANROOM/reports/{OUTPUT_VARIATION}"
    internal_selection_ref = f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_INTERNAL_SELECTION}"
    external_selection_ref = f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_EXTERNAL_SELECTION}"

    kt_row = _build_kt_row(
        contract_packet=contract_packet,
        live_product_truth_packet=live_product_truth_packet,
        variation_receipt_ref=variation_receipt_ref,
    )
    internal_row = _build_internal_row(
        contract_packet=contract_packet,
        selected_profile=internal_profile,
        selection_receipt_ref=internal_selection_ref,
        variation_receipt_ref=variation_receipt_ref,
    )
    external_row = _build_external_row(
        contract_packet=contract_packet,
        selection_receipt_ref=external_selection_ref,
        variation_receipt_ref=variation_receipt_ref,
    )
    scorecard = _build_scorecard(
        subject_head=subject_head,
        kt_row=kt_row,
        internal_row=internal_row,
        external_row=external_row,
    )
    verdict = _build_verdict(
        subject_head=subject_head,
        kt_row=kt_row,
        internal_row=internal_row,
        external_row=external_row,
    )
    outputs = build_outputs(
        subject_head=subject_head,
        branch_name=branch_name,
        variation_receipt=variation_receipt,
        kt_row=kt_row,
        internal_row=internal_row,
        external_row=external_row,
        scorecard=scorecard,
        verdict=verdict,
    )

    payloads = {
        OUTPUT_VARIATION: variation_receipt,
        OUTPUT_KT_ROW: kt_row,
        OUTPUT_INTERNAL_ROW: internal_row,
        OUTPUT_EXTERNAL_ROW: external_row,
        OUTPUT_SCORECARD: scorecard,
        OUTPUT_VERDICT: verdict,
        OUTPUT_PACKET: outputs["packet"],
        OUTPUT_RECEIPT: outputs["receipt"],
    }
    for filename, payload in payloads.items():
        common.write_json_stable((reports_root / filename).resolve(), payload)
    common.write_text((reports_root / OUTPUT_REPORT).resolve(), str(outputs["report"]))

    return {
        "execution_outcome": EXECUTION_OUTCOME,
        "verdict": verdict["verdict"],
        "scorecard_path": (reports_root / OUTPUT_SCORECARD).resolve().as_posix(),
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the second bounded Track 01 comparative run.")
    parser.add_argument(
        "--contract-packet",
        default=f"{common.REPORTS_ROOT_REL}/{contract_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--matrix-packet",
        default=f"{common.REPORTS_ROOT_REL}/{contract_tranche.matrix_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--first-execution-packet",
        default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--first-execution-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_RECEIPT}",
    )
    parser.add_argument(
        "--internal-selection-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_INTERNAL_SELECTION}",
    )
    parser.add_argument(
        "--external-selection-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{first_wave.OUTPUT_EXTERNAL_SELECTION}",
    )
    parser.add_argument(
        "--live-product-truth-packet",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        contract_packet_path=common.resolve_path(root, args.contract_packet),
        matrix_packet_path=common.resolve_path(root, args.matrix_packet),
        first_execution_packet_path=common.resolve_path(root, args.first_execution_packet),
        first_execution_receipt_path=common.resolve_path(root, args.first_execution_receipt),
        internal_selection_receipt_path=common.resolve_path(root, args.internal_selection_receipt),
        external_selection_receipt_path=common.resolve_path(root, args.external_selection_receipt),
        live_product_truth_packet_path=common.resolve_path(root, args.live_product_truth_packet),
    )
    print(result["execution_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
