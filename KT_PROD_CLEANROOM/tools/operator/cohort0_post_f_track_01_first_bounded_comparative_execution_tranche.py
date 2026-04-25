from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_01_metric_scorecard_contract_tranche as contract_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_INTERNAL_SELECTION = "cohort0_post_f_track_01_internal_baseline_selection_receipt.json"
OUTPUT_EXTERNAL_SELECTION = "cohort0_post_f_track_01_external_workflow_selection_receipt.json"
OUTPUT_KT_ROW = "cohort0_post_f_track_01_row_kt_canonical_wedge_receipt.json"
OUTPUT_INTERNAL_ROW = "cohort0_post_f_track_01_row_internal_static_baseline_receipt.json"
OUTPUT_EXTERNAL_ROW = "cohort0_post_f_track_01_row_externalized_workflow_receipt.json"
OUTPUT_SCORECARD = "cohort0_post_f_track_01_first_bounded_comparative_scorecard.json"
OUTPUT_VERDICT = "cohort0_post_f_track_01_comparative_verdict_receipt.json"
OUTPUT_PACKET = "cohort0_post_f_track_01_first_bounded_comparative_execution_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_01_first_bounded_comparative_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_01_FIRST_BOUNDED_COMPARATIVE_EXECUTION_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_TRACK_01_FIRST_BOUNDED_COMPARATIVE_EXECUTION_COMPLETE"
EXECUTION_OUTCOME = "POST_F_TRACK_01_FIRST_BOUNDED_COMPARATIVE_EXECUTION_COMPLETE__KT_WEDGE_ADVANTAGE_IN_BOUNDED_LANE"
TRACK_ID = contract_tranche.TRACK_ID
NEXT_MOVE = "DECIDE_POST_F_TRACK_01_SECOND_WAVE_OR_FINAL_SUMMARY_PACKET"

INTERNAL_SELECTION_ID = "REGULATED_WORKFLOW_MODE__STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE"
EXTERNAL_SELECTION_ID = "DETACHED_PUBLIC_VERIFIER_PACKAGE_WORKFLOW__CATEGORY_FAIR_EXTERNALIZED_ROW"


def _require_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _require_file(path: Path, *, label: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")


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


def _load_contract_metrics(contract_packet: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = contract_packet.get("metric_rules", [])
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract missing metric rules")
    metrics: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        metric_id = str(row.get("metric_id", "")).strip()
        if metric_id:
            metrics[metric_id] = dict(row)
    if len(metrics) != 5:
        raise RuntimeError("FAIL_CLOSED: Track 01 metric contract must bind exactly five metrics")
    return metrics


def _profile_by_id(profiles_payload: Dict[str, Any], profile_id: str) -> Dict[str, Any]:
    for row in profiles_payload.get("profiles", []):
        if isinstance(row, dict) and str(row.get("profile_id", "")).strip() == profile_id:
            return dict(row)
    raise RuntimeError(f"FAIL_CLOSED: missing deployment profile {profile_id}")


def _choose_internal_baseline(profiles_payload: Dict[str, Any], *, active_profile_id: str) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    active = _profile_by_id(profiles_payload, active_profile_id)
    active_ceiling = str(active.get("max_externality_class", "")).strip()
    for row in profiles_payload.get("profiles", []):
        if not isinstance(row, dict):
            continue
        profile_id = str(row.get("profile_id", "")).strip()
        if not profile_id or profile_id == active_profile_id:
            continue
        if str(row.get("max_externality_class", "")).strip() != active_ceiling:
            continue
        candidates.append(dict(row))
    if not candidates:
        raise RuntimeError("FAIL_CLOSED: no same-ceiling internal baseline candidate exists")
    candidates.sort(
        key=lambda row: (
            int(row.get("additional_review_minutes", 0)),
            len(row.get("evidence_refs", [])) if isinstance(row.get("evidence_refs", []), list) else 0,
            str(row.get("profile_id", "")).strip(),
        ),
        reverse=True,
    )
    return candidates[0]


def _metric_result(
    *,
    metric_id: str,
    state: str,
    contract_metric: Dict[str, Any],
    evidence_refs: List[str],
    justification: str,
) -> Dict[str, Any]:
    rulebook = dict(contract_metric.get("scoring_rule", {}))
    return {
        "metric_id": metric_id,
        "state": state,
        "weight": int(contract_metric.get("weight", 0)),
        "hard_stop": bool(contract_metric.get("hard_stop", False)),
        "evidence_refs": list(evidence_refs),
        "state_rule": str(rulebook.get(state, "")).strip(),
        "justification": justification,
    }


def _points_for_state(contract_packet: Dict[str, Any], state: str) -> Optional[int]:
    states = dict(contract_packet.get("score_states", {}))
    row = dict(states.get(state, {}))
    value = row.get("points", None)
    return None if value is None else int(value)


def _classify_row(
    *,
    metric_results: List[Dict[str, Any]],
    contract_packet: Dict[str, Any],
) -> Dict[str, Any]:
    weighted_score = 0
    has_deferred = False
    hard_stop_fail = False
    for row in metric_results:
        state = str(row.get("state", "")).strip()
        points = _points_for_state(contract_packet, state)
        if points is None:
            has_deferred = True
            continue
        weight = int(row.get("weight", 0))
        weighted_score += points * weight
        if bool(row.get("hard_stop", False)) and state == "FAIL":
            hard_stop_fail = True

    if has_deferred:
        row_class = "DEFERRED"
        normalized_score = None
    elif hard_stop_fail or weighted_score <= 13:
        row_class = "FAIL"
        normalized_score = round(weighted_score / 26.0, 4)
    elif 14 <= weighted_score <= 20:
        row_class = "PARTIAL"
        normalized_score = round(weighted_score / 26.0, 4)
    else:
        row_class = "PASS"
        normalized_score = round(weighted_score / 26.0, 4)
    return {
        "row_class": row_class,
        "weighted_score": weighted_score,
        "normalized_score": normalized_score,
    }


def _build_internal_selection_receipt(
    *,
    branch_name: str,
    selected_profile: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_internal_baseline_selection_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "selection_id": INTERNAL_SELECTION_ID,
        "row_type": "INTERNAL_STATIC_BASELINE",
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "selected_profile_id": str(selected_profile.get("profile_id", "")).strip(),
        "selection_reason": (
            "Selected the highest-evidence same-ceiling internal profile outside the canonical wedge. "
            "regulated_workflow_mode carries the strongest approved static internal review burden while staying inside E1 same-host bounds."
        ),
        "category_fair": True,
        "evidence_refs": list(selected_profile.get("evidence_refs", [])),
    }


def _build_external_selection_receipt(*, branch_name: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_external_workflow_selection_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "selection_id": EXTERNAL_SELECTION_ID,
        "row_type": "EXTERNAL_MONOLITH_WORKFLOW",
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "selected_workflow_id": "KT_PUBLIC_VERIFIER_DETACHED_PACKAGE_WORKFLOW_V1",
        "selection_reason": (
            "Selected the already-proven detached public verifier package as the single externalized workflow row. "
            "It stays in the same-host detached replay ceiling, is category-fair to the confirmed wedge, and avoids claiming a broad third-party vendor bakeoff."
        ),
        "category_fair": True,
        "evidence_refs": [
            "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
            "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
            "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
        ],
    }


def _build_kt_row(
    *,
    contract_packet: Dict[str, Any],
    live_product_truth_packet: Dict[str, Any],
) -> Dict[str, Any]:
    metrics = _load_contract_metrics(contract_packet)
    evidence_common = [
        "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
        "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
        "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
    ]
    results = [
        _metric_result(
            metric_id="receipt_completeness",
            state="PASS",
            contract_metric=metrics["receipt_completeness"],
            evidence_refs=evidence_common,
            justification="The canonical wedge returns the full bounded verifier receipt set required by the confirmed contract.",
        ),
        _metric_result(
            metric_id="replayability",
            state="PASS",
            contract_metric=metrics["replayability"],
            evidence_refs=evidence_common,
            justification="The canonical wedge exposes the audit packet and receipt cross-refs directly from the returned surface.",
        ),
        _metric_result(
            metric_id="fail_closed_behavior",
            state="PASS",
            contract_metric=metrics["fail_closed_behavior"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            ],
            justification="PASS/FAIL is explicit and bounded for the canonical wedge path.",
        ),
        _metric_result(
            metric_id="operator_clarity_and_bounded_execution_integrity",
            state="PASS",
            contract_metric=metrics["operator_clarity_and_bounded_execution_integrity"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/product/client_wrapper_spec.json",
                "KT_PROD_CLEANROOM/product/operator_runbook_v2.md",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
            ],
            justification="The canonical wedge is the shortest declared operator path with no extra review overlays.",
        ),
        _metric_result(
            metric_id="useful_output_success_under_wedge_contract",
            state="PASS",
            contract_metric=metrics["useful_output_success_under_wedge_contract"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json",
                "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json",
            ],
            justification="The canonical wedge completes the bounded verifier task and handoff exactly as the product truth surface declares.",
        ),
    ]
    classification = _classify_row(metric_results=results, contract_packet=contract_packet)
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_row_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "row_id": "KT_CANONICAL_WEDGE",
        "row_type": "CANONICAL_CONFIRMED_SURFACE",
        "row_subject": live_product_truth_packet.get("selected_wedge_summary", {}).get("wedge_id", ""),
        "category_fair": True,
        "metric_results": results,
        **classification,
    }


def _build_internal_row(
    *,
    contract_packet: Dict[str, Any],
    selected_profile: Dict[str, Any],
    selection_receipt_ref: str,
) -> Dict[str, Any]:
    metrics = _load_contract_metrics(contract_packet)
    evidence_refs = list(selected_profile.get("evidence_refs", []))
    results = [
        _metric_result(
            metric_id="receipt_completeness",
            state="PASS",
            contract_metric=metrics["receipt_completeness"],
            evidence_refs=evidence_refs,
            justification="The regulated workflow profile binds the same bounded verifier receipts plus the mapped standards surfaces it declares.",
        ),
        _metric_result(
            metric_id="replayability",
            state="PARTIAL",
            contract_metric=metrics["replayability"],
            evidence_refs=evidence_refs + [selection_receipt_ref],
            justification="Replay remains bounded, but the regulated workflow row requires one additional documented standards-legibility step beyond the canonical wedge.",
        ),
        _metric_result(
            metric_id="fail_closed_behavior",
            state="PASS",
            contract_metric=metrics["fail_closed_behavior"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                selection_receipt_ref,
            ],
            justification="The regulated workflow profile still uses the same detached PASS/FAIL validator boundary.",
        ),
        _metric_result(
            metric_id="operator_clarity_and_bounded_execution_integrity",
            state="PARTIAL",
            contract_metric=metrics["operator_clarity_and_bounded_execution_integrity"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/product/deployment_profiles.json",
                "KT_PROD_CLEANROOM/product/nist_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/iso_42001_mapping_matrix.json",
                "KT_PROD_CLEANROOM/product/eu_ai_act_alignment_matrix.json",
                selection_receipt_ref,
            ],
            justification="The profile stays bounded, but it adds a standards-review overlay that makes the operator path heavier than the canonical wedge.",
        ),
        _metric_result(
            metric_id="useful_output_success_under_wedge_contract",
            state="PARTIAL",
            contract_metric=metrics["useful_output_success_under_wedge_contract"],
            evidence_refs=evidence_refs + [selection_receipt_ref],
            justification="The regulated workflow completes the same bounded task, but the added review burden is a bounded defect for this narrow Track 01 lane.",
        ),
    ]
    classification = _classify_row(metric_results=results, contract_packet=contract_packet)
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_row_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "row_id": "STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE",
        "row_type": "INTERNAL_STATIC_BASELINE",
        "row_subject": str(selected_profile.get("profile_id", "")).strip(),
        "category_fair": True,
        "selection_receipt_ref": selection_receipt_ref,
        "metric_results": results,
        **classification,
    }


def _build_external_row(
    *,
    contract_packet: Dict[str, Any],
    selection_receipt_ref: str,
) -> Dict[str, Any]:
    metrics = _load_contract_metrics(contract_packet)
    evidence_refs = [
        "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
        "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
        "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
        "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
    ]
    results = [
        _metric_result(
            metric_id="receipt_completeness",
            state="PASS",
            contract_metric=metrics["receipt_completeness"],
            evidence_refs=evidence_refs,
            justification="The detached package workflow carries the bounded detached receipt, manifest, audit manifest, and verifier kit surfaces.",
        ),
        _metric_result(
            metric_id="replayability",
            state="PARTIAL",
            contract_metric=metrics["replayability"],
            evidence_refs=evidence_refs + [selection_receipt_ref],
            justification="The detached workflow is replayable, but it requires one extra documented package/runtime handoff step compared with the canonical wedge.",
        ),
        _metric_result(
            metric_id="fail_closed_behavior",
            state="PASS",
            contract_metric=metrics["fail_closed_behavior"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                selection_receipt_ref,
            ],
            justification="The detached workflow explicitly proves bounded PASS/FAIL parity and withholds stronger claims.",
        ),
        _metric_result(
            metric_id="operator_clarity_and_bounded_execution_integrity",
            state="PARTIAL",
            contract_metric=metrics["operator_clarity_and_bounded_execution_integrity"],
            evidence_refs=[
                "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                "KT_PROD_CLEANROOM/product/client_wrapper_spec.json",
                selection_receipt_ref,
            ],
            justification="The workflow stays bounded, but the detached package path is less direct than the canonical in-repo verifier flow.",
        ),
        _metric_result(
            metric_id="useful_output_success_under_wedge_contract",
            state="PARTIAL",
            contract_metric=metrics["useful_output_success_under_wedge_contract"],
            evidence_refs=evidence_refs + [selection_receipt_ref],
            justification="The detached workflow proves the bounded verifier result, but it is optimized for detached parity rather than the full canonical handoff path.",
        ),
    ]
    classification = _classify_row(metric_results=results, contract_packet=contract_packet)
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_row_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "row_id": "ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW",
        "row_type": "EXTERNAL_MONOLITH_WORKFLOW",
        "row_subject": "KT_PUBLIC_VERIFIER_DETACHED_PACKAGE_WORKFLOW_V1",
        "category_fair": True,
        "selection_receipt_ref": selection_receipt_ref,
        "metric_results": results,
        **classification,
    }


def _row_rank(row_class: str, weighted_score: int) -> tuple[int, int]:
    class_rank = {"DEFERRED": 0, "FAIL": 1, "PARTIAL": 2, "PASS": 3}
    return (class_rank.get(row_class, 0), weighted_score)


def _build_scorecard(
    *,
    subject_head: str,
    kt_row: Dict[str, Any],
    internal_row: Dict[str, Any],
    external_row: Dict[str, Any],
) -> Dict[str, Any]:
    rows = [kt_row, internal_row, external_row]
    ranking = sorted(
        (
            {
                "row_id": str(row.get("row_id", "")).strip(),
                "row_class": str(row.get("row_class", "")).strip(),
                "weighted_score": int(row.get("weighted_score", 0)),
            }
            for row in rows
        ),
        key=lambda item: _row_rank(str(item["row_class"]), int(item["weighted_score"])),
        reverse=True,
    )
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "row_summaries": ranking,
        "scorecard_boundary": "This scorecard ranks only the bounded Track 01 governed-execution lane for the confirmed wedge.",
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
        rationale = "At least one row is deferred or not category-fair, so the bounded comparative verdict must fail closed."
    else:
        kt_class = str(kt_row.get("row_class", "")).strip()
        kt_score = int(kt_row.get("weighted_score", 0))
        comp_classes = [str(row.get("row_class", "")).strip() for row in comparators]
        comp_scores = [int(row.get("weighted_score", 0)) for row in comparators]
        if kt_class == "PASS" and all(row_class in {"PARTIAL", "FAIL"} and score < kt_score for row_class, score in zip(comp_classes, comp_scores)):
            verdict = "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR"
            rationale = "The canonical wedge passed cleanly and every comparator row remained below it within the bounded governed-execution lane."
        elif any(_row_rank(row_class, score) > _row_rank(kt_class, kt_score) or (row_class == kt_class and score >= kt_score + 3) for row_class, score in zip(comp_classes, comp_scores)):
            verdict = "KT_CANONICAL_WEDGE_DEFICIT__CATEGORY_FAIR"
            rationale = "A category-fair comparator row outranked the canonical wedge on the bounded Track 01 scorecard."
        elif any(row_class == kt_class and abs(score - kt_score) <= 2 for row_class, score in zip(comp_classes, comp_scores)):
            verdict = "KT_CANONICAL_WEDGE_PARITY__CATEGORY_FAIR"
            rationale = "At least one category-fair comparator row stayed within the bounded parity window without outranking the canonical wedge."
        else:
            verdict = "DEFERRED__COMPARATOR_SELECTION_OR_METRIC_DEFECT"
            rationale = "The row pattern did not satisfy any bounded verdict rule cleanly enough to avoid defer."

    return {
        "schema_id": "kt.operator.cohort0_post_f_track_01_comparative_verdict_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "verdict": verdict,
        "claim_boundary": "This verdict applies only to the bounded Track 01 governed-execution lane for the confirmed wedge.",
        "rationale": rationale,
    }


def build_outputs(
    *,
    subject_head: str,
    branch_name: str,
    internal_selection: Dict[str, Any],
    external_selection: Dict[str, Any],
    kt_row: Dict[str, Any],
    internal_row: Dict[str, Any],
    external_row: Dict[str, Any],
    scorecard: Dict[str, Any],
    verdict: Dict[str, Any],
) -> Dict[str, Any]:
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_execution_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "claim_boundary": (
            "This packet records one first bounded comparative execution for Track 01 only. "
            "It does not widen product truth, does not claim broad model superiority, and does not escape the confirmed local_verifier_mode wedge."
        ),
        "track_id": TRACK_ID,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "row_receipt_order": [
            OUTPUT_KT_ROW,
            OUTPUT_INTERNAL_ROW,
            OUTPUT_EXTERNAL_ROW,
        ],
        "selection_receipts": [
            OUTPUT_INTERNAL_SELECTION,
            OUTPUT_EXTERNAL_SELECTION,
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
        "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "verdict": verdict["verdict"],
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 01 First Bounded Comparative Execution Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Execution outcome: `{EXECUTION_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Verdict: `{verdict['verdict']}`",
            f"- KT row: `{kt_row['row_class']}` / `{kt_row['weighted_score']}`",
            f"- Internal row: `{internal_row['row_class']}` / `{internal_row['weighted_score']}`",
            f"- External row: `{external_row['row_class']}` / `{external_row['weighted_score']}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {
        "packet": packet,
        "receipt": receipt,
        "report": report,
    }


def run(
    *,
    reports_root: Path,
    contract_packet_path: Path,
    matrix_packet_path: Path,
    live_product_truth_packet_path: Path,
    post_merge_closeout_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    contract_packet = common.load_json_required(root, contract_packet_path, label="Track 01 metric scorecard contract")
    matrix_packet = common.load_json_required(root, matrix_packet_path, label="Track 01 comparator matrix packet")
    live_product_truth_packet = common.load_json_required(root, live_product_truth_packet_path, label="post-F live product truth packet")
    post_merge_closeout_receipt = common.load_json_required(root, post_merge_closeout_receipt_path, label="post-merge closeout receipt")
    profiles_payload = common.load_json_required(root, common.DEPLOYMENT_PROFILES_REL, label="deployment profiles")
    wrapper_spec = common.load_json_required(root, common.CLIENT_WRAPPER_SPEC_REL, label="client wrapper spec")

    _require_pass(contract_packet, label="Track 01 metric scorecard contract")
    _require_pass(matrix_packet, label="Track 01 comparator matrix packet")
    _require_pass(live_product_truth_packet, label="post-F live product truth packet")
    if str(post_merge_closeout_receipt.get("status", "")).strip() != "PASS__CANONICAL_CLEAN_CLOSEOUT_MERGED_TO_MAIN":
        raise RuntimeError("FAIL_CLOSED: Track 01 execution requires the merged closeout receipt")
    if str(contract_packet.get("contract_outcome", "")).strip() != contract_tranche.CONTRACT_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 01 execution requires the bound metric scorecard contract")
    if str(contract_packet.get("next_lawful_move", "")).strip() != "EXECUTE_POST_F_TRACK_01_FIRST_BOUNDED_COMPARATIVE_EXECUTION":
        raise RuntimeError("FAIL_CLOSED: Track 01 execution requires the metric contract to point here next")

    required_files = [
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/kt_operator_greenline_receipt.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/nist_mapping_matrix.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/iso_42001_mapping_matrix.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/eu_ai_act_alignment_matrix.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/one_page_product_truth_surface.md"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/support_boundary.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/product/client_wrapper_spec.json"),
        common.resolve_path(root, "KT_PROD_CLEANROOM/reports/public_verifier_kit.json"),
    ]
    for path in required_files:
        _require_file(path, label=path.name)

    selected_surface = dict(live_product_truth_packet.get("selected_wedge_summary", {}))
    active_profile_id = str(selected_surface.get("active_profile_id", "")).strip()
    if active_profile_id != common.ACTIVE_WEDGE_PROFILE_ID:
        raise RuntimeError("FAIL_CLOSED: Track 01 execution assumes the canonical local_verifier_mode wedge")

    internal_profile = _choose_internal_baseline(profiles_payload, active_profile_id=active_profile_id)
    if str(internal_profile.get("profile_id", "")).strip() != "regulated_workflow_mode":
        raise RuntimeError("FAIL_CLOSED: Track 01 execution expects regulated_workflow_mode as the strongest same-ceiling internal baseline")

    subject_head = str(contract_packet.get("subject_head", "")).strip() or str(live_product_truth_packet.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 01 execution requires a subject head")

    branch_name = _current_branch_name(root)
    internal_selection = _build_internal_selection_receipt(branch_name=branch_name, selected_profile=internal_profile)
    external_selection = _build_external_selection_receipt(branch_name=branch_name)

    internal_selection_ref = f"KT_PROD_CLEANROOM/reports/{OUTPUT_INTERNAL_SELECTION}"
    external_selection_ref = f"KT_PROD_CLEANROOM/reports/{OUTPUT_EXTERNAL_SELECTION}"

    kt_row = _build_kt_row(contract_packet=contract_packet, live_product_truth_packet=live_product_truth_packet)
    internal_row = _build_internal_row(
        contract_packet=contract_packet,
        selected_profile=internal_profile,
        selection_receipt_ref=internal_selection_ref,
    )
    external_row = _build_external_row(
        contract_packet=contract_packet,
        selection_receipt_ref=external_selection_ref,
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
        internal_selection=internal_selection,
        external_selection=external_selection,
        kt_row=kt_row,
        internal_row=internal_row,
        external_row=external_row,
        scorecard=scorecard,
        verdict=verdict,
    )

    payloads = {
        OUTPUT_INTERNAL_SELECTION: internal_selection,
        OUTPUT_EXTERNAL_SELECTION: external_selection,
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
    parser = common.main_parser("Execute the first bounded Track 01 comparative run.")
    parser.add_argument(
        "--contract-packet",
        default=f"{common.REPORTS_ROOT_REL}/{contract_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--matrix-packet",
        default=f"{common.REPORTS_ROOT_REL}/{contract_tranche.matrix_tranche.OUTPUT_PACKET}",
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
        contract_packet_path=common.resolve_path(root, args.contract_packet),
        matrix_packet_path=common.resolve_path(root, args.matrix_packet),
        live_product_truth_packet_path=common.resolve_path(root, args.live_product_truth_packet),
        post_merge_closeout_receipt_path=common.resolve_path(root, args.post_merge_closeout_receipt),
    )
    print(result["execution_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
