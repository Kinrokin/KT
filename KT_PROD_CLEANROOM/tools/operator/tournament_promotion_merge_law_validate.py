from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R3_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_r3_tournament_promotion_merge_law_contract.json"
DEFAULT_R3_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/b04_r3_tournament_promotion_merge_terminal_state.json"
DEFAULT_R1_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/crucible_pressure_law_ratification_receipt.json"
DEFAULT_R2_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/adapter_lifecycle_law_ratification_receipt.json"
DEFAULT_TOURNAMENT_LAW_REL = "KT_PROD_CLEANROOM/governance/tournament_law.json"
DEFAULT_PROMOTION_LAW_REL = "KT_PROD_CLEANROOM/governance/promotion_engine_law.json"
DEFAULT_MERGE_LAW_REL = "KT_PROD_CLEANROOM/governance/merge_law.json"
DEFAULT_TOURNAMENT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/tournament_receipt.json"
DEFAULT_PROMOTION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/promotion_receipt.json"
DEFAULT_MERGE_OUTCOME_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/merge_outcome_receipt.json"
DEFAULT_TOURNAMENT_READINESS_REL = "KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json"
DEFAULT_ROLLBACK_DRILL_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/rollback_drill_receipt.json"
DEFAULT_MAIN_MERGE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/main_merge_receipt.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/tournament_promotion_merge_law_ratification_receipt.json"

EXPECTED_CURRENT_STEP_ID = "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"
EXPECTED_NEXT_STEP_ID = "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
EXPECTED_EXECUTION_MODE = "CIVILIZATION_RATIFICATION_ORDER_LOCKED__FOURTH_STEP_ONLY"
EXPECTED_TOURNAMENT_CLASSES = [
    "BASELINE_VS_ADAPTER",
    "ADAPTER_VS_ADAPTER",
    "STRESS_PRESSURE",
    "REGRESSION_GUARD",
    "SAFETY_ADVERSARIAL",
]
EXPECTED_ALLOWED_FOLLOW_ON_STEPS = {
    "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION",
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
        raise RuntimeError("FAIL_CLOSED: tracked tournament-promotion-merge receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def _order_locked_progress_after_r3(
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


def build_tournament_promotion_merge_law_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    r3_contract = load_json(root / DEFAULT_R3_CONTRACT_REL)
    r3_terminal = load_json(root / DEFAULT_R3_TERMINAL_STATE_REL)
    r1_receipt = load_json(root / DEFAULT_R1_RECEIPT_REL)
    r2_receipt = load_json(root / DEFAULT_R2_RECEIPT_REL)
    tournament_law = load_json(root / DEFAULT_TOURNAMENT_LAW_REL)
    promotion_law = load_json(root / DEFAULT_PROMOTION_LAW_REL)
    merge_law = load_json(root / DEFAULT_MERGE_LAW_REL)
    tournament_receipt = load_json(root / DEFAULT_TOURNAMENT_RECEIPT_REL)
    promotion_receipt = load_json(root / DEFAULT_PROMOTION_RECEIPT_REL)
    merge_outcome_receipt = load_json(root / DEFAULT_MERGE_OUTCOME_RECEIPT_REL)
    tournament_readiness = load_json(root / DEFAULT_TOURNAMENT_READINESS_REL)
    rollback_drill_receipt = load_json(root / DEFAULT_ROLLBACK_DRILL_RECEIPT_REL)
    main_merge_receipt = load_json(root / DEFAULT_MAIN_MERGE_RECEIPT_REL)
    overlay = load_json(root / DEFAULT_CURRENT_OVERLAY_REL)
    next_contract = load_json(root / DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    resume = load_json(root / DEFAULT_RESUME_BLOCKERS_REL)
    reanchor = load_json(root / DEFAULT_REANCHOR_PACKET_REL)

    tournament_classes = [
        str(row.get("tournament_class_id", "")).strip()
        for row in tournament_law.get("tournament_registry", [])
    ]
    current_state_authority = [
        str(item).strip()
        for item in overlay.get("authority_stack", {}).get("current_state_authority", [])
        if str(item).strip()
    ]
    promotion_criteria = [str(row).strip() for row in promotion_law.get("promotion_criteria", [])]
    demotion_criteria = [str(row).strip() for row in promotion_law.get("demotion_criteria", [])]
    merge_rules = [str(row).strip() for row in merge_law.get("merge_admissibility_rules", [])]
    post_merge_rules = [str(row).strip() for row in merge_law.get("post_merge_rules", [])]

    checks = [
        {
            "check_id": "r3_contract_and_terminal_state_bind_only_selection_arena_ratification",
            "pass": str(r3_contract.get("workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
            and str(r3_contract.get("ratification_mode", "")).strip() == "RATIFICATION_ONLY_NO_ROUTER_OR_LOBE_ADVANCE"
            and str(r3_terminal.get("current_state", "")).strip() == "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFIED"
            and r3_terminal.get("tournament_promotion_merge_ratified") is True
            and r3_terminal.get("router_shadow_ratified") is False,
        },
        {
            "check_id": "r3_consumes_r1_and_r2_authority_chain",
            "pass": str(r1_receipt.get("status", "")).strip() == "PASS"
            and str(r2_receipt.get("status", "")).strip() == "PASS"
            and any("b04_r1_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and any("b04_r2_authoritative_receipt_" in item.lower() for item in current_state_authority)
            and DEFAULT_R1_RECEIPT_REL in tournament_law.get("authority_refs", [])
            and DEFAULT_R2_RECEIPT_REL in tournament_law.get("authority_refs", [])
            and DEFAULT_R2_RECEIPT_REL in promotion_law.get("authority_refs", [])
            and DEFAULT_R2_RECEIPT_REL in merge_law.get("authority_refs", []),
        },
        {
            "check_id": "finite_tournament_registry_is_bound",
            "pass": tournament_classes == EXPECTED_TOURNAMENT_CLASSES
            and all(bool(row.get("purpose")) for row in tournament_law.get("tournament_registry", [])),
        },
        {
            "check_id": "tournament_showability_remains_blocked_and_bounded",
            "pass": tournament_law.get("showability_boundary", {}).get("public_showability_allowed") is False
            and str(tournament_readiness.get("status", "")).strip() == "BLOCKED"
            and str(tournament_readiness.get("tournament_gate_status", "")).strip() == "BLOCKED"
            and str(tournament_receipt.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "promotion_and_demotion_rules_are_explicit_and_no_manual_bypass_exists",
            "pass": len(promotion_criteria) >= 5
            and len(demotion_criteria) >= 4
            and promotion_law.get("manual_override_rule", {}).get("manual_promotion_allowed") is False
            and promotion_law.get("manual_override_rule", {}).get("manual_demotion_allowed") is False
            and str(promotion_receipt.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "router_candidate_pool_entry_remains_future_gated",
            "pass": str(promotion_law.get("router_candidate_pool_entry_rule", {}).get("future_step_required", "")).strip() == EXPECTED_NEXT_STEP_ID
            and promotion_law.get("router_candidate_pool_entry_rule", {}).get("router_entry_authorized_now") is False
            and "crucibles and tournaments" in str(promotion_law.get("router_candidate_pool_entry_rule", {}).get("rule_text", "")).lower(),
        },
        {
            "check_id": "merge_rules_require_lineage_rollback_and_recrucible",
            "pass": len(merge_rules) >= 5
            and len(post_merge_rules) >= 3
            and merge_law.get("direct_router_admission_allowed") is False
            and any("lineage" in rule.lower() for rule in merge_rules)
            and any("rollback" in rule.lower() for rule in merge_rules)
            and any("crucible" in rule.lower() for rule in post_merge_rules)
            and str(merge_outcome_receipt.get("status", "")).strip() == "PASS"
            and str(main_merge_receipt.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "rollback_and_bounded_merge_receipts_exist",
            "pass": str(rollback_drill_receipt.get("status", "")).strip() == "PASS"
            and str(merge_outcome_receipt.get("merge_admissibility_status", "")).strip() == "ROLLBACK_BOUND_AND_RECEIPTED",
        },
        {
            "check_id": "control_surfaces_remain_order_locked_after_r3",
            "pass": _order_locked_progress_after_r3(
                overlay=overlay,
                next_contract=next_contract,
                resume=resume,
                reanchor=reanchor,
            ),
        },
        {
            "check_id": "scope_remains_bounded_after_r3",
            "pass": r3_terminal.get("learned_router_authorized") is False
            and r3_terminal.get("lobe_ratified") is False
            and r3_terminal.get("externality_widening_allowed") is False
            and r3_terminal.get("comparative_widening_allowed") is False
            and r3_terminal.get("commercial_activation_allowed") is False,
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.b04.r3.tournament_promotion_merge_law_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_ARTIFACT_ONLY",
        "workstream_id": EXPECTED_CURRENT_STEP_ID,
        "tournament_class_summary": {
            "class_ids": tournament_classes,
            "class_count": len(tournament_classes),
            "public_showability_allowed": bool(tournament_law.get("showability_boundary", {}).get("public_showability_allowed")),
            "historical_readiness_status": str(tournament_readiness.get("status", "")).strip(),
        },
        "promotion_rule_summary": {
            "promotion_criteria_count": len(promotion_criteria),
            "demotion_criteria_count": len(demotion_criteria),
            "router_candidate_pool_rule": str(promotion_law.get("router_candidate_pool_entry_rule", {}).get("rule_text", "")).strip(),
            "router_candidate_pool_authorized_now": bool(promotion_law.get("router_candidate_pool_entry_rule", {}).get("router_entry_authorized_now")),
        },
        "merge_rule_summary": {
            "merge_rule_count": len(merge_rules),
            "post_merge_rule_count": len(post_merge_rules),
            "direct_router_admission_allowed": bool(merge_law.get("direct_router_admission_allowed")),
            "historical_merge_method": str(main_merge_receipt.get("merge_method", "")).strip(),
        },
        "bounded_evidence_summary": {
            "tournament_receipt_status": str(tournament_receipt.get("status", "")).strip(),
            "promotion_receipt_status": str(promotion_receipt.get("status", "")).strip(),
            "merge_outcome_status": str(merge_outcome_receipt.get("status", "")).strip(),
            "rollback_drill_status": str(rollback_drill_receipt.get("status", "")).strip(),
        },
        "checks": checks,
        "next_lawful_move": EXPECTED_NEXT_STEP_ID if status == "PASS" else "FIX_B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_DEFECT",
        "claim_boundary": "This receipt proves only that the bounded tournament, promotion, and merge selection arena is ratified. It does not ratify router shadow, learned-router cutover, lobes, externality, comparative claims, or commercial widening.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate B04.R3 tournament, promotion, and merge law ratification.")
    parser.add_argument("--output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    receipt = build_tournament_promotion_merge_law_receipt(root=root)
    output = _resolve(root, str(args.output))
    _write_receipt(
        root=root,
        target=output,
        payload=receipt,
        allow_default_repo_write=args.allow_tracked_output_refresh,
    )
    summary = {
        "status": receipt["status"],
        "tournament_promotion_merge_law_ratification_status": receipt["status"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
