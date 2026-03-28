from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import router_ordered_proof_validate as ordered
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R5_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_r5_router_vs_best_adapter_proof_contract.json"
DEFAULT_R5_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/b04_r5_router_vs_best_adapter_terminal_state.json"
DEFAULT_R1_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/crucible_pressure_law_ratification_receipt.json"
DEFAULT_R2_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/adapter_lifecycle_law_ratification_receipt.json"
DEFAULT_R3_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/tournament_promotion_merge_law_ratification_receipt.json"
DEFAULT_R4_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_evaluation_law_contract.json"
DEFAULT_R4_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_terminal_state.json"
DEFAULT_ROUTER_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_SHADOW_MATRIX_REL = "KT_PROD_CLEANROOM/reports/router_shadow_eval_matrix.json"
DEFAULT_HEALTH_REL = "KT_PROD_CLEANROOM/reports/route_distribution_health.json"
DEFAULT_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json"
DEFAULT_ORDERED_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_ordered_proof_receipt.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_vs_best_adapter_proof_ratification_receipt.json"

EXPECTED_CURRENT_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
EXPECTED_EARNED_NEXT_STEP_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
EXPECTED_HOLD_NEXT_STEP_ID = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"


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
        raise RuntimeError("FAIL_CLOSED: tracked router-vs-best-adapter receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def _order_locked_progress_into_r5(
    *,
    overlay: Dict[str, Any],
    next_contract: Dict[str, Any],
    resume: Dict[str, Any],
    reanchor: Dict[str, Any],
) -> bool:
    return (
        str(next_contract.get("exact_next_counted_workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
        and str(next_contract.get("execution_mode", "")).strip() == "CIVILIZATION_RATIFICATION_ORDER_LOCKED__FIFTH_STEP_ONLY"
        and bool(next_contract.get("repo_state_executable_now")) is True
        and str(overlay.get("next_counted_workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
        and str(resume.get("exact_next_counted_workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
        and str(reanchor.get("next_lawful_move", "")).strip() == EXPECTED_CURRENT_STEP_ID
    )


def build_router_vs_best_adapter_proof_ratification_receipt(
    *,
    root: Path,
    shadow_matrix: Dict[str, Any],
    health_report: Dict[str, Any],
    scorecard: Dict[str, Any],
    ordered_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    current_head = _git_head(root)
    r5_contract = load_json(root / DEFAULT_R5_CONTRACT_REL)
    r5_terminal = load_json(root / DEFAULT_R5_TERMINAL_STATE_REL)
    r1_receipt = load_json(root / DEFAULT_R1_RECEIPT_REL)
    r2_receipt = load_json(root / DEFAULT_R2_RECEIPT_REL)
    r3_receipt = load_json(root / DEFAULT_R3_RECEIPT_REL)
    r4_contract = load_json(root / DEFAULT_R4_CONTRACT_REL)
    r4_terminal = load_json(root / DEFAULT_R4_TERMINAL_STATE_REL)
    router_policy_registry = load_json(root / DEFAULT_ROUTER_POLICY_REGISTRY_REL)
    overlay = load_json(root / DEFAULT_CURRENT_OVERLAY_REL)
    next_contract = load_json(root / DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    resume = load_json(root / DEFAULT_RESUME_BLOCKERS_REL)
    reanchor = load_json(root / DEFAULT_REANCHOR_PACKET_REL)

    current_state_authority = [
        str(item).strip()
        for item in overlay.get("authority_stack", {}).get("current_state_authority", [])
        if str(item).strip()
    ]
    superiority_earned = bool(scorecard.get("superiority_earned"))
    honest_hold = (
        superiority_earned is False
        and str(scorecard.get("overall_outcome", "")).strip() == "HOLD_STATIC_CANONICAL_BASELINE"
        and str(scorecard.get("route_quality_win_status", "")).strip() == "NOT_EARNED_SHADOW_MATCH_ONLY"
        and str(ordered_receipt.get("ordered_proof_outcome", "")).strip() == "PASS_HOLD_STATIC_CANONICAL_BASELINE"
        and str(ordered_receipt.get("exact_superiority_outcome", "")).strip() == "NOT_EARNED_STATIC_BASELINE_RETAINS_CANONICAL_STATUS"
    )
    earned_path = (
        superiority_earned is True
        and ordered_receipt.get("learned_router_cutover_allowed") is True
        and ordered_receipt.get("multi_lobe_promotion_allowed") is False
    )

    checks = [
        {
            "check_id": "r5_contract_and_terminal_state_bind_only_same_head_router_proof",
            "pass": str(r5_contract.get("workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
            and str(r5_contract.get("ratification_mode", "")).strip() == "RATIFICATION_ONLY_SAME_HEAD_ORDERED_PROOF_NO_CUTOVER_OR_LOBE_ADVANCE"
            and str(r5_terminal.get("current_state", "")).strip() == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF_RATIFIED_STATIC_HOLD"
            and r5_terminal.get("router_vs_best_adapter_proof_ratified") is True
            and r5_terminal.get("learned_router_authorized") is False,
        },
        {
            "check_id": "r5_consumes_r1_r2_r3_and_r4_authority_chain_without_using_r4_tracked_carrier_as_authority",
            "pass": str(r1_receipt.get("status", "")).strip() == "PASS"
            and str(r2_receipt.get("status", "")).strip() == "PASS"
            and str(r3_receipt.get("status", "")).strip() == "PASS"
            and any("b04_r1_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and any("b04_r2_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and any("b04_r3_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and str(r4_contract.get("workstream_id", "")).strip() == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
            and str(r4_terminal.get("current_state", "")).strip() == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFIED"
            and r4_terminal.get("router_vs_best_adapter_proof_ratified") is False
            and str(router_policy_registry.get("r5_same_head_proof_policy", {}).get("ratification_receipt_ref", "")).strip() == DEFAULT_RECEIPT_REL,
        },
        {
            "check_id": "ordered_proof_artifacts_pass_and_are_same_head",
            "pass": str(shadow_matrix.get("status", "")).strip() == "PASS"
            and str(health_report.get("status", "")).strip() == "PASS"
            and str(scorecard.get("status", "")).strip() == "PASS"
            and str(ordered_receipt.get("status", "")).strip() == "PASS"
            and str(shadow_matrix.get("current_git_head", "")).strip() == current_head
            and str(health_report.get("current_git_head", "")).strip() == current_head
            and str(scorecard.get("current_git_head", "")).strip() == current_head
            and str(ordered_receipt.get("current_git_head", "")).strip() == current_head
            and str(shadow_matrix.get("subject_head", "")).strip() == current_head
            and str(health_report.get("subject_head", "")).strip() == current_head
            and str(scorecard.get("subject_head", "")).strip() == current_head
            and str(ordered_receipt.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "router_vs_best_adapter_outcome_is_stated_honestly",
            "pass": honest_hold or earned_path,
        },
        {
            "check_id": "learned_router_and_lobe_progress_remain_fail_closed_without_earned_proof",
            "pass": (
                superiority_earned is True
                and ordered_receipt.get("learned_router_cutover_allowed") is True
            ) or (
                superiority_earned is False
                and ordered_receipt.get("learned_router_cutover_allowed") is False
                and ordered_receipt.get("multi_lobe_promotion_allowed") is False
                and r5_terminal.get("learned_router_authorized") is False
                and r5_terminal.get("lobe_ratified") is False
            ),
        },
        {
            "check_id": "control_surfaces_show_r5_was_the_exact_executable_step",
            "pass": _order_locked_progress_into_r5(
                overlay=overlay,
                next_contract=next_contract,
                resume=resume,
                reanchor=reanchor,
            ),
        },
        {
            "check_id": "scope_remains_bounded_after_r5",
            "pass": r5_terminal.get("externality_widening_allowed") is False
            and r5_terminal.get("comparative_widening_allowed") is False
            and r5_terminal.get("commercial_activation_allowed") is False
            and str(router_policy_registry.get("multi_lobe_orchestration_policy", {}).get("current_status", "")).strip() == "BLOCKED_PENDING_LEARNED_ROUTER_WIN",
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    next_lawful_move = (
        EXPECTED_EARNED_NEXT_STEP_ID
        if status == "PASS" and superiority_earned
        else EXPECTED_HOLD_NEXT_STEP_ID
        if status == "PASS"
        else "FIX_B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF_DEFECT"
    )

    return {
        "schema_id": "kt.b04.r5.router_vs_best_adapter_proof_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF_ARTIFACT_ONLY",
        "workstream_id": EXPECTED_CURRENT_STEP_ID,
        "router_proof_summary": {
            "canonical_router_status": str(ordered_receipt.get("canonical_router_status", "")).strip(),
            "ordered_proof_outcome": str(ordered_receipt.get("ordered_proof_outcome", "")).strip(),
            "exact_superiority_outcome": str(ordered_receipt.get("exact_superiority_outcome", "")).strip(),
            "router_superiority_earned": superiority_earned,
            "best_static_provider_adapter_id": str(scorecard.get("best_static_baseline", {}).get("provider_underlay", {}).get("adapter_id", "")).strip(),
            "learned_router_cutover_allowed": bool(ordered_receipt.get("learned_router_cutover_allowed")),
            "multi_lobe_promotion_allowed": bool(ordered_receipt.get("multi_lobe_promotion_allowed")),
        },
        "same_head_authority_summary": {
            "same_head_required": True,
            "shadow_matrix_ref": DEFAULT_SHADOW_MATRIX_REL,
            "health_report_ref": DEFAULT_HEALTH_REL,
            "scorecard_ref": DEFAULT_SCORECARD_REL,
            "ordered_proof_receipt_ref": DEFAULT_ORDERED_RECEIPT_REL,
        },
        "checks": checks,
        "next_lawful_move": next_lawful_move,
        "claim_boundary": "This receipt proves only the same-head router-versus-best-adapter ordered proof result on the current head. It does not authorize learned-router cutover, lobe promotion, externality widening, comparative claims, or commercial activation unless and until superiority is actually earned.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate B04.R5 router-versus-best-adapter proof on the current head.")
    parser.add_argument("--shadow-matrix-output", default=DEFAULT_SHADOW_MATRIX_REL)
    parser.add_argument("--health-output", default=DEFAULT_HEALTH_REL)
    parser.add_argument("--scorecard-output", default=DEFAULT_SCORECARD_REL)
    parser.add_argument("--ordered-proof-output", default=DEFAULT_ORDERED_RECEIPT_REL)
    parser.add_argument("--output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    base = ordered._build_base_reports(root=root)
    shadow_matrix = ordered.build_router_shadow_eval_matrix(root=root, base=base)
    health_report = ordered.build_route_distribution_health(root=root, base=base, shadow_matrix=shadow_matrix)
    scorecard = ordered.build_router_superiority_scorecard(root=root, base=base, health_report=health_report)
    ordered_receipt = ordered.build_router_ordered_proof_receipt(
        root=root,
        base=base,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
    )

    write_json_stable(_resolve(root, str(args.shadow_matrix_output)), shadow_matrix)
    write_json_stable(_resolve(root, str(args.health_output)), health_report)
    write_json_stable(_resolve(root, str(args.scorecard_output)), scorecard)
    write_json_stable(_resolve(root, str(args.ordered_proof_output)), ordered_receipt)

    receipt = build_router_vs_best_adapter_proof_ratification_receipt(
        root=root,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
        ordered_receipt=ordered_receipt,
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
        "router_superiority_earned": receipt["router_proof_summary"]["router_superiority_earned"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
