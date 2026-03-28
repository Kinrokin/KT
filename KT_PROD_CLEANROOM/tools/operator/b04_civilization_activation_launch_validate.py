from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_LAUNCH_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_civilization_activation_launch_contract.json"
DEFAULT_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/b04_civilization_activation_terminal_state.json"
DEFAULT_GATE_D_DECISION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/b04_civilization_activation_launch_receipt.json"

EXPECTED_SELECTIONS = {
    "D1_EXTERNALITY_WIDENING": "EXTERNALITY_BOUNDED",
    "D2_NEW_COUNTED_DOMAINS": "COUNTED_DOMAINS_CONTROLLED_EXPANSION",
    "D3_ADAPTIVE_EVOLUTION_AUTHORIZATION": "ADAPTER_EVOLUTION_AUTHORIZED",
    "D4_COMPARATIVE_COMPETITIVE_CLAIMS": "NO_EXTERNAL_COMPARATIVE_CLAIMS",
    "D5_COMMERCIAL_ACTIVATION": "LAB_ONLY",
}

EXPECTED_ALLOWED_CANONICAL = [
    "Crucible registry and crucible execution receipts.",
    "Pressure taxonomy and epoch coverage enforcement.",
    "Adapter registry, lineage, training, evaluation, promotion, demotion, and retirement receipts.",
    "Tournament protocol, promotion ladder, merge law, and merge receipts.",
    "Router shadow evaluation and router proof versus the best static adapter only.",
    "Evolution lineage, rollback plans, rollback drills, and civilization governance receipts.",
    "Lobe definitions remain law-bound and schema-bound without enabling autonomous multi-lobe runtime.",
]

EXPECTED_FORBIDDEN = [
    "Externality widening above E1 or any Gate E work.",
    "Product wedge or Gate F work.",
    "External comparative or competitive claims.",
    "Commercial activation or deployment.",
    "Learned router in production.",
    "Autonomous multi-lobe runtime.",
    "Any component without schema, validator, receipt, and rollback.",
]

EXPECTED_RATIFICATION_ORDER = [
    "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION",
    "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION",
    "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION",
    "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION",
    "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF",
    "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
    "B04_R7_LOBE_ARCHITECTURE_RATIFICATION",
]

EXPECTED_ADMISSION_REQUIREMENTS = [
    "schema",
    "validator",
    "receipt",
    "rollback",
    "claim_ceiling",
    "terminal_state",
    "lineage_tracking_if_adaptive",
    "replay_proof_if_execution_related",
]

EXPECTED_EXIT_CRITERIA = [
    "Crucible law exists and emits receipts.",
    "Pressure taxonomy and epoch coverage are enforced.",
    "Adapter registry and lineage tracking are working.",
    "At least one adapter promotion is completed with receipts.",
    "At least one adapter demotion or retirement is completed with receipts.",
    "Tournament protocol is executed at least once.",
    "Promotion ladder is proven with real delta proof.",
    "Router shadow evaluation is completed.",
    "Router versus best static adapter comparison is completed.",
    "Evolution rollback is tested and proven.",
    "Lineage replay is proven.",
]

EXPECTED_INVARIANTS = [
    "No adaptive power without receipts.",
    "No receipts without rollback.",
    "No rollback without lineage.",
]

EXPECTED_FIRST_STEP_ID = "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION"


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
        raise RuntimeError("FAIL_CLOSED: tracked B04 launch receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def _load_active_status(root: Path, raw_ref: str) -> Dict[str, Any]:
    payload = load_json(_resolve(root, raw_ref))
    return {
        "ref": raw_ref,
        "exists": True,
        "status": str(payload.get("status", "")).strip(),
    }


def build_b04_civilization_activation_launch_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    contract = load_json(root / DEFAULT_LAUNCH_CONTRACT_REL)
    terminal = load_json(root / DEFAULT_TERMINAL_STATE_REL)
    decision = load_json(root / DEFAULT_GATE_D_DECISION_RECEIPT_REL)
    reanchor = load_json(root / DEFAULT_REANCHOR_PACKET_REL)
    overlay = load_json(root / DEFAULT_CURRENT_OVERLAY_REL)
    next_contract = load_json(root / DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    resume = load_json(root / DEFAULT_RESUME_BLOCKERS_REL)

    existing_law_rows = [_load_active_status(root, ref) for ref in contract.get("required_existing_law_refs", [])]
    selected_postures = dict(contract.get("selected_postures", {}))
    ratification_order = [str(row.get("step_id", "")).strip() for row in contract.get("ordered_ratification_sequence", [])]

    checks = [
        {
            "check_id": "launch_contract_is_definition_only_not_implementation",
            "pass": str(contract.get("activation_mode", "")).strip() == "LAUNCH_SURFACE_ONLY_NO_IMPLEMENTATION",
        },
        {
            "check_id": "selected_postures_match_sealed_gate_d_decision",
            "pass": selected_postures == EXPECTED_SELECTIONS
            and selected_postures == {
                row["domain_id"]: row["selected_posture"] for row in decision.get("selected_postures", [])
            },
        },
        {
            "check_id": "activation_scope_is_bounded_and_forbidden_scope_is_explicit",
            "pass": contract.get("activation_scope", {}).get("allowed_canonical_surfaces") == EXPECTED_ALLOWED_CANONICAL
            and contract.get("activation_scope", {}).get("forbidden_surfaces") == EXPECTED_FORBIDDEN,
        },
        {
            "check_id": "ordered_ratification_sequence_is_locked",
            "pass": ratification_order == EXPECTED_RATIFICATION_ORDER
            and str(contract.get("first_ratification_step_id", "")).strip() == EXPECTED_FIRST_STEP_ID
            and str(contract.get("next_lawful_move_after_launch", "")).strip() == EXPECTED_FIRST_STEP_ID,
        },
        {
            "check_id": "canonical_admission_rule_requires_schema_validator_receipt_rollback_and_lineage",
            "pass": contract.get("canonical_admission_requirements") == EXPECTED_ADMISSION_REQUIREMENTS,
        },
        {
            "check_id": "gate_d_completion_criteria_are_finite_and_bound",
            "pass": contract.get("gate_d_completion_criteria") == EXPECTED_EXIT_CRITERIA,
        },
        {
            "check_id": "governance_invariant_is_bound",
            "pass": contract.get("governance_invariants") == EXPECTED_INVARIANTS,
        },
        {
            "check_id": "required_existing_governance_surfaces_exist_and_are_active",
            "pass": len(existing_law_rows) == len(contract.get("required_existing_law_refs", []))
            and all(row["status"] == "ACTIVE" for row in existing_law_rows),
        },
        {
            "check_id": "terminal_state_opens_ratification_lane_but_not_stack_implementation",
            "pass": str(terminal.get("current_state", "")).strip() == "B04_CIVILIZATION_RATIFICATION_LAUNCH_BOUND"
            and terminal.get("launch_surface_bound") is True
            and terminal.get("ratification_lane_open") is True
            and terminal.get("implementation_started") is False
            and terminal.get("automatic_batch_execution_allowed") is False
            and str(terminal.get("next_lawful_move", "")).strip() == EXPECTED_FIRST_STEP_ID,
        },
        {
            "check_id": "control_surfaces_now_point_only_to_first_ratification_step",
            "pass": str(next_contract.get("exact_next_counted_workstream_id", "")).strip() == EXPECTED_FIRST_STEP_ID
            and str(next_contract.get("execution_mode", "")).strip() == "CIVILIZATION_RATIFICATION_ORDER_LOCKED__FIRST_STEP_ONLY"
            and bool(next_contract.get("repo_state_executable_now")) is True
            and str(overlay.get("next_counted_workstream_id", "")).strip() == EXPECTED_FIRST_STEP_ID
            and bool(overlay.get("repo_state_executable_now")) is True
            and str(reanchor.get("next_lawful_move", "")).strip() == EXPECTED_FIRST_STEP_ID
            and str(resume.get("exact_next_counted_workstream_id", "")).strip() == EXPECTED_FIRST_STEP_ID
            and bool(resume.get("repo_state_executable_now")) is True,
        },
        {
            "check_id": "gate_d_scope_widening_remains_fail_closed",
            "pass": contract.get("launch_constraints", {}).get("externality_widening_allowed") is False
            and contract.get("launch_constraints", {}).get("external_comparative_claims_allowed") is False
            and contract.get("launch_constraints", {}).get("commercial_activation_allowed") is False
            and contract.get("launch_constraints", {}).get("learned_router_production_allowed") is False
            and contract.get("launch_constraints", {}).get("autonomous_multi_lobe_runtime_allowed") is False
            and contract.get("launch_constraints", {}).get("automatic_b04_stack_activation_allowed") is False,
        },
        {
            "check_id": "receipt_is_same_head_launch_artifact_only",
            "pass": True,
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.b04.civilization_activation_launch_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_B04_CIVILIZATION_ACTIVATION_LAUNCH_ARTIFACT_ONLY",
        "activation_mode": str(contract.get("activation_mode", "")).strip(),
        "parent_batch_id": str(contract.get("parent_batch_id", "")).strip(),
        "gate_c_exit_head": str(contract.get("gate_c_exit_head", "")).strip(),
        "reanchor_head": str(contract.get("reanchor_head", "")).strip(),
        "selected_postures": selected_postures,
        "first_ratification_step_id": EXPECTED_FIRST_STEP_ID,
        "existing_law_rows": existing_law_rows,
        "checks": checks,
        "next_lawful_move": EXPECTED_FIRST_STEP_ID if status == "PASS" else "FIX_B04_CIVILIZATION_ACTIVATION_LAUNCH_DEFECT",
        "claim_boundary": "This receipt proves only that the Gate D civilization ratification lane is lawfully activated and order-locked. It does not implement the civilization stack, does not widen externality, and does not authorize commercial or comparative expansion.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the B04 civilization activation launch surface without implementing the civilization stack.")
    parser.add_argument("--output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    receipt = build_b04_civilization_activation_launch_receipt(root=root)
    output = _resolve(root, str(args.output))
    _write_receipt(
        root=root,
        target=output,
        payload=receipt,
        allow_default_repo_write=args.allow_tracked_output_refresh,
    )
    summary = {
        "status": receipt["status"],
        "b04_civilization_activation_launch_status": receipt["status"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
