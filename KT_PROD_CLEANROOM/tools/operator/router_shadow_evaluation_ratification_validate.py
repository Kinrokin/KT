from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.wave2b_router_shadow_validate import build_wave2b_shadow_reports


DEFAULT_R4_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_evaluation_law_contract.json"
DEFAULT_R4_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_terminal_state.json"
DEFAULT_R1_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/crucible_pressure_law_ratification_receipt.json"
DEFAULT_R2_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/adapter_lifecycle_law_ratification_receipt.json"
DEFAULT_R3_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/tournament_promotion_merge_law_ratification_receipt.json"
DEFAULT_ROUTER_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
DEFAULT_ROUTER_PROMOTION_LAW_REL = "KT_PROD_CLEANROOM/governance/router_promotion_law.json"
DEFAULT_C005_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json"
DEFAULT_SELECTION_REPORT_REL = "KT_PROD_CLEANROOM/reports/kt_wave2b_router_selection_receipt.json"
DEFAULT_MATRIX_REPORT_REL = "KT_PROD_CLEANROOM/reports/kt_wave2b_router_shadow_eval_matrix.json"
DEFAULT_HEALTH_REPORT_REL = "KT_PROD_CLEANROOM/reports/kt_wave2b_route_distribution_health.json"
DEFAULT_TELEMETRY_REL = "KT_PROD_CLEANROOM/reports/.tmp_b04_r4_router_shadow_telemetry.jsonl"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_shadow_evaluation_ratification_receipt.json"

EXPECTED_CURRENT_STEP_ID = "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
EXPECTED_NEXT_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
EXPECTED_ALLOWED_FOLLOW_ON_STEPS = {
    "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF",
    "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
    "B04_R7_LOBE_ARCHITECTURE_RATIFICATION",
}
SETTLED_R5_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
SETTLED_R6_STEP_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
SETTLED_R6_HOLD_MOVE = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"
SETTLED_R6_HOLD_EXECUTION_MODE = "R6_NEXT_IN_ORDER_BLOCKED_PENDING_EARNED_SUPERIORITY__INITIAL_R5_PROOF_COMPLETE"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _write_receipt(
    *,
    root: Path,
    target: Path,
    payload: Dict[str, Any],
    allow_default_repo_write: bool,
) -> None:
    default_target = (root / DEFAULT_RECEIPT_REL).resolve()
    resolved_target = target.resolve()
    if resolved_target == default_target and not allow_default_repo_write:
        raise RuntimeError("FAIL_CLOSED: tracked router-shadow ratification receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def _order_locked_progress_after_r4(
    *,
    overlay: Dict[str, Any],
    next_contract: Dict[str, Any],
    resume: Dict[str, Any],
    reanchor: Dict[str, Any],
) -> bool:
    next_step = str(next_contract.get("exact_next_counted_workstream_id", "")).strip()
    in_sequence_progress = (
        next_step in EXPECTED_ALLOWED_FOLLOW_ON_STEPS
        and str(next_contract.get("execution_mode", "")).strip().startswith("CIVILIZATION_RATIFICATION_ORDER_LOCKED__")
        and bool(next_contract.get("repo_state_executable_now")) is True
        and str(overlay.get("next_counted_workstream_id", "")).strip() == next_step
        and str(resume.get("exact_next_counted_workstream_id", "")).strip() == next_step
        and str(reanchor.get("next_lawful_move", "")).strip() == next_step
    )
    settled_replay_progress = (
        next_step == SETTLED_R6_STEP_ID
        and str(next_contract.get("source_workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(next_contract.get("execution_mode", "")).strip() == SETTLED_R6_HOLD_EXECUTION_MODE
        and bool(next_contract.get("repo_state_executable_now")) is False
        and str(overlay.get("schema_id", "")).strip() == "kt.current_campaign_state_overlay.v1"
        and str(overlay.get("workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(overlay.get("next_counted_workstream_id", "")).strip() == SETTLED_R6_STEP_ID
        and str(overlay.get("current_lawful_gate_standing", {}).get("current_counted_batch", "")).strip() == SETTLED_R5_STEP_ID
        and bool(overlay.get("repo_state_executable_now")) is False
        and str(resume.get("workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(resume.get("exact_next_counted_workstream_id", "")).strip() == SETTLED_R6_STEP_ID
        and bool(resume.get("repo_state_executable_now")) is False
        and str(reanchor.get("workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(reanchor.get("next_lawful_move", "")).strip() == SETTLED_R6_HOLD_MOVE
    )
    return in_sequence_progress or settled_replay_progress


def build_router_shadow_evaluation_ratification_receipt(
    *,
    root: Path,
    selection_report: Dict[str, Any],
    matrix_report: Dict[str, Any],
    health_report: Dict[str, Any],
) -> Dict[str, Any]:
    current_head = _git_head(root)
    r4_contract = load_json(root / DEFAULT_R4_CONTRACT_REL)
    r4_terminal = load_json(root / DEFAULT_R4_TERMINAL_STATE_REL)
    r1_receipt = load_json(root / DEFAULT_R1_RECEIPT_REL)
    r2_receipt = load_json(root / DEFAULT_R2_RECEIPT_REL)
    r3_receipt = load_json(root / DEFAULT_R3_RECEIPT_REL)
    router_policy_registry = load_json(root / DEFAULT_ROUTER_POLICY_REGISTRY_REL)
    router_promotion_law = load_json(root / DEFAULT_ROUTER_PROMOTION_LAW_REL)
    c005_receipt = load_json(root / DEFAULT_C005_RECEIPT_REL)
    overlay = load_json(root / DEFAULT_CURRENT_OVERLAY_REL)
    next_contract = load_json(root / DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    resume = load_json(root / DEFAULT_RESUME_BLOCKERS_REL)
    reanchor = load_json(root / DEFAULT_REANCHOR_PACKET_REL)

    current_state_authority = [
        str(item).strip()
        for item in overlay.get("authority_stack", {}).get("current_state_authority", [])
        if str(item).strip()
    ]
    case_rows = [row for row in selection_report.get("case_rows", []) if isinstance(row, dict)]
    exact_path_match_count = sum(
        1
        for row in matrix_report.get("rows", [])
        if isinstance(row, dict) and bool(row.get("exact_path_match"))
    )
    fallback_case_ids = list(health_report.get("fallback_case_ids", []))
    allowed_signal_classes = list(router_promotion_law.get("candidate_input_ceiling", {}).get("allowed_signal_classes", []))
    forbidden_signal_classes = list(router_promotion_law.get("candidate_input_ceiling", {}).get("forbidden_signal_classes", []))

    checks = [
        {
            "check_id": "r4_contract_and_terminal_state_bind_only_router_shadow_evaluation",
            "pass": str(r4_contract.get("workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
            and str(r4_contract.get("ratification_mode", "")).strip() == "RATIFICATION_ONLY_NO_ROUTER_PROOF_CUTOVER_OR_LOBE_ADVANCE"
            and str(r4_terminal.get("current_state", "")).strip() == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFIED"
            and r4_terminal.get("router_shadow_ratified") is True
            and r4_terminal.get("router_vs_best_adapter_proof_ratified") is False,
        },
        {
            "check_id": "r4_consumes_r1_r2_r3_authority_chain",
            "pass": str(r1_receipt.get("status", "")).strip() == "PASS"
            and str(r2_receipt.get("status", "")).strip() == "PASS"
            and str(r3_receipt.get("status", "")).strip() == "PASS"
            and any("b04_r1_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and any("b04_r2_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and any("b04_r3_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and DEFAULT_R3_RECEIPT_REL in router_promotion_law.get("authority_refs", []),
        },
        {
            "check_id": "router_law_is_shadow_only_and_static_baseline_remains_canonical",
            "pass": str(c005_receipt.get("status", "")).strip() == "PASS"
            and str(c005_receipt.get("canonical_router_status", "")).strip() == "STATIC_CANONICAL_BASELINE_ONLY"
            and router_promotion_law.get("shadow_evaluation_status", {}).get("shadow_only_authorized") is True
            and router_promotion_law.get("shadow_evaluation_status", {}).get("canonical_static_router_retains_authority") is True
            and router_promotion_law.get("shadow_evaluation_status", {}).get("learned_router_cutover_allowed") is False,
        },
        {
            "check_id": "shadow_reports_pass_and_are_same_head",
            "pass": str(selection_report.get("status", "")).strip() == "PASS"
            and str(matrix_report.get("status", "")).strip() == "PASS"
            and str(health_report.get("status", "")).strip() == "PASS"
            and str(selection_report.get("current_git_head", "")).strip() == current_head
            and str(matrix_report.get("current_git_head", "")).strip() == current_head
            and str(health_report.get("current_git_head", "")).strip() == current_head
            and str(selection_report.get("subject_head", "")).strip() == current_head
            and str(matrix_report.get("subject_head", "")).strip() == current_head
            and str(health_report.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "shadow_selection_is_explainable_replayable_and_fallback_preserving",
            "pass": len(case_rows) >= 4
            and all(bool(row.get("explainability_complete")) for row in case_rows)
            and all(str(row.get("replayability_class", "")).strip() == "E0_INTERNAL_SELF_ISSUED_ONLY" for row in case_rows)
            and any(bool(row.get("shadow_selection", {}).get("fallback_engaged")) for row in case_rows)
            and "canonical_router_cut_over_to_learned_mode" in selection_report.get("stronger_claim_not_made", []),
        },
        {
            "check_id": "shadow_matrix_and_distribution_show_no_regression_or_collapse",
            "pass": matrix_report.get("promotion_decision", {}).get("canonical_router_unchanged") is True
            and matrix_report.get("promotion_decision", {}).get("learned_router_cutover_allowed") is False
            and matrix_report.get("promotion_decision", {}).get("shadow_promotable") is False
            and int(health_report.get("route_distribution_delta_count", -1)) == 0
            and bool(health_report.get("route_collapse_detected")) is False
            and float(health_report.get("shadow_match_rate", 0.0)) == 1.0,
        },
        {
            "check_id": "router_candidate_inputs_stay_bounded_and_nonexternal",
            "pass": bool(allowed_signal_classes)
            and bool(forbidden_signal_classes)
            and "same_host_live_hashed_provider_underlay_receipts" in allowed_signal_classes
            and "external_benchmarks" in forbidden_signal_classes
            and "cost_or_profit_signals" in forbidden_signal_classes
            and "human_preference_votes" in forbidden_signal_classes
            and "non_replayable_features" in forbidden_signal_classes
            and str(router_policy_registry.get("ratification_scope", "")).strip() == "STATIC_ROUTER_BASELINE_ONLY",
        },
        {
            "check_id": "control_surfaces_remain_order_locked_after_r4",
            "pass": _order_locked_progress_after_r4(
                overlay=overlay,
                next_contract=next_contract,
                resume=resume,
                reanchor=reanchor,
            ),
        },
        {
            "check_id": "scope_remains_bounded_after_r4",
            "pass": r4_terminal.get("router_shadow_cutover_allowed") is False
            and r4_terminal.get("learned_router_authorized") is False
            and r4_terminal.get("lobe_ratified") is False
            and r4_terminal.get("externality_widening_allowed") is False
            and r4_terminal.get("comparative_widening_allowed") is False
            and r4_terminal.get("commercial_activation_allowed") is False,
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.b04.r4.router_shadow_evaluation_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_B04_R4_ROUTER_SHADOW_EVALUATION_ARTIFACT_ONLY",
        "workstream_id": EXPECTED_CURRENT_STEP_ID,
        "static_router_summary": {
            "canonical_router_status": str(c005_receipt.get("canonical_router_status", "")).strip(),
            "ratification_decision": str(c005_receipt.get("ratification_decision", "")).strip(),
            "best_static_provider_adapter_id": str(selection_report.get("best_static_provider_adapter_underlay", {}).get("adapter_id", "")).strip(),
            "provider_underlay_ref": str(selection_report.get("provider_underlay_context", {}).get("provider_report_ref", "")).strip(),
        },
        "shadow_evaluation_summary": {
            "case_count": len(case_rows),
            "exact_path_match_count": exact_path_match_count,
            "fallback_case_ids": fallback_case_ids,
            "route_distribution_delta_count": int(health_report.get("route_distribution_delta_count", 0)),
            "shadow_match_rate": float(health_report.get("shadow_match_rate", 0.0)),
            "same_host_live_hashed_success_proven": bool(selection_report.get("provider_underlay_context", {}).get("same_host_live_hashed_success_proven")),
            "same_host_live_hashed_resilience_proven": bool(selection_report.get("provider_underlay_context", {}).get("same_host_live_hashed_resilience_proven")),
        },
        "router_cutover_summary": {
            "shadow_only_authorized": bool(router_promotion_law.get("shadow_evaluation_status", {}).get("shadow_only_authorized")),
            "canonical_static_router_retains_authority": bool(router_promotion_law.get("shadow_evaluation_status", {}).get("canonical_static_router_retains_authority")),
            "learned_router_cutover_allowed": bool(router_promotion_law.get("shadow_evaluation_status", {}).get("learned_router_cutover_allowed")),
            "multi_lobe_orchestration_allowed": bool(router_promotion_law.get("shadow_evaluation_status", {}).get("multi_lobe_orchestration_allowed")),
            "allowed_signal_classes": allowed_signal_classes,
            "forbidden_signal_classes": forbidden_signal_classes,
        },
        "checks": checks,
        "next_lawful_move": EXPECTED_NEXT_STEP_ID if status == "PASS" else "FIX_B04_R4_ROUTER_SHADOW_EVALUATION_DEFECT",
        "claim_boundary": "This receipt proves only that router shadow evaluation is ratified as a bounded, explainable, replayable shadow-only step under static-baseline control. It does not ratify router superiority, learned-router cutover, lobe promotion, externality widening, comparative claims, or commercial activation.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate B04.R4 router shadow evaluation ratification.")
    parser.add_argument("--selection-output", default=DEFAULT_SELECTION_REPORT_REL)
    parser.add_argument("--matrix-output", default=DEFAULT_MATRIX_REPORT_REL)
    parser.add_argument("--health-output", default=DEFAULT_HEALTH_REPORT_REL)
    parser.add_argument("--telemetry-output", default=DEFAULT_TELEMETRY_REL)
    parser.add_argument("--output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    telemetry_path = _resolve(root, str(args.telemetry_output))
    reports = build_wave2b_shadow_reports(root=root, telemetry_path=telemetry_path)
    selection_report = reports["selection_report"]
    matrix_report = reports["matrix_report"]
    health_report = reports["health_report"]

    write_json_stable(_resolve(root, str(args.selection_output)), selection_report)
    write_json_stable(_resolve(root, str(args.matrix_output)), matrix_report)
    write_json_stable(_resolve(root, str(args.health_output)), health_report)

    receipt = build_router_shadow_evaluation_ratification_receipt(
        root=root,
        selection_report=selection_report,
        matrix_report=matrix_report,
        health_report=health_report,
    )
    output = _resolve(root, str(args.output))
    _write_receipt(
        root=root,
        target=output,
        payload=receipt,
        allow_default_repo_write=args.allow_tracked_output_refresh,
    )
    summary = {
        "status": receipt["status"],
        "router_shadow_evaluation_ratification_status": receipt["status"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
