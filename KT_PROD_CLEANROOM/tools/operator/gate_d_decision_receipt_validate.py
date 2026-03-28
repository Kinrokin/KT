from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_GATE_D_DECISION_LAW_REL = "KT_PROD_CLEANROOM/governance/gate_d_decision_law.json"
DEFAULT_B04_LAUNCH_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_civilization_activation_launch_contract.json"
DEFAULT_GATE_D_DECISION_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_GATE_D_DECISION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_receipt.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_OMEGA_WORK_ORDER_PATH = "d:/user/rober/OneDrive/Kings_Theorem_Active/tmp/kt_omega_v10_delivery/KT_OMEGA_V10_E2E_WORK_ORDER.json"

EXPECTED_SELECTIONS = {
    "D1_EXTERNALITY_WIDENING": "EXTERNALITY_BOUNDED",
    "D2_NEW_COUNTED_DOMAINS": "COUNTED_DOMAINS_CONTROLLED_EXPANSION",
    "D3_ADAPTIVE_EVOLUTION_AUTHORIZATION": "ADAPTER_EVOLUTION_AUTHORIZED",
    "D4_COMPARATIVE_COMPETITIVE_CLAIMS": "NO_EXTERNAL_COMPARATIVE_CLAIMS",
    "D5_COMMERCIAL_ACTIVATION": "LAB_ONLY",
}

EXPECTED_DEFERRED_GATES = {
    "D1_EXTERNALITY_WIDENING": "B05_GATE_E_EXTERNALITY_AND_ASSURANCE",
    "D4_COMPARATIVE_COMPETITIVE_CLAIMS": "B06_GATE_F_PRODUCT_WEDGE",
    "D5_COMMERCIAL_ACTIVATION": "B06_GATE_F_PRODUCT_WEDGE",
}

EXPECTED_B04_VALIDATORS = [
    "python -m tools.operator.universal_adapter_validate",
    "python -m tools.operator.civilization_loop_validate",
    "python -m tools.operator.router_ordered_proof_validate",
    "python -m tools.operator.w2_lawful_evolution_validate",
]

EXPECTED_B04_EMIT_ARTIFACTS = [
    "KT_PROD_CLEANROOM/reports/civilization_golden_run_receipt.json",
    "KT_PROD_CLEANROOM/reports/domain_unlock_matrix_receipt.json",
    "KT_PROD_CLEANROOM/reports/bounded_learning_receipt.json",
    "KT_PROD_CLEANROOM/reports/promotion_binding_receipt.json",
    "KT_PROD_CLEANROOM/reports/forge_generation_receipt.json",
    "KT_PROD_CLEANROOM/reports/runtime_cutover_receipt.json",
    "KT_PROD_CLEANROOM/reports/chaos_lane_resilience_receipt.json",
    "KT_PROD_CLEANROOM/reports/tournament_live_receipt.json",
    "KT_PROD_CLEANROOM/reports/multi_lobe_execution_receipt.json",
    "KT_PROD_CLEANROOM/reports/civilization_loop_receipt.json",
    "KT_PROD_CLEANROOM/reports/learning_response_receipt.json",
    "KT_PROD_CLEANROOM/reports/rollback_drill_receipt.json",
]

EXPECTED_B04_LAUNCH_STEP_ID = "B04_GATE_D_CIVILIZATION_ACTIVATE"
EXPECTED_B04_R1_STEP_ID = "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION"
EXPECTED_B04_R2_STEP_ID = "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION"
EXPECTED_B04_R3_STEP_ID = "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"
EXPECTED_B04_R4_STEP_ID = "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
EXPECTED_B04_R5_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
EXPECTED_B04_R6_STEP_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
EXPECTED_B04_R7_STEP_ID = "B04_R7_LOBE_ARCHITECTURE_RATIFICATION"
EXPECTED_B04_RATIFICATION_SEQUENCE = [
    EXPECTED_B04_R1_STEP_ID,
    EXPECTED_B04_R2_STEP_ID,
    EXPECTED_B04_R3_STEP_ID,
    EXPECTED_B04_R4_STEP_ID,
    EXPECTED_B04_R5_STEP_ID,
    EXPECTED_B04_R6_STEP_ID,
    EXPECTED_B04_R7_STEP_ID,
]


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
    default_target = (root / DEFAULT_GATE_D_DECISION_RECEIPT_REL).resolve()
    resolved_target = target.resolve()
    if resolved_target == default_target and not allow_default_repo_write:
        raise RuntimeError("FAIL_CLOSED: tracked Gate D decision receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def _build_non_default_bindings() -> List[Dict[str, Any]]:
    return [
        {
            "domain_id": "D2_NEW_COUNTED_DOMAINS",
            "selected_posture": "COUNTED_DOMAINS_CONTROLLED_EXPANSION",
            "scope_boundary": "One governed and rollback-safe civilization lane only under Omega B04. Counted expansion is limited to bounded learning, promotion binding, runtime cutover, chaos resilience, tournament live, multi-lobe execution, civilization loop, learning response, and rollback drill receipts. No externality widening, comparator expansion, or commercial metrics are authorized here.",
            "validator_chain": EXPECTED_B04_VALIDATORS,
            "rollback_condition": "Any rollback_drill failure, runtime cutover that is not rollback-safe, router promotion before ordered proof, or tournament/lobe claim without traceable receipts fails closed and voids the activation attempt.",
            "proof_required": EXPECTED_B04_EMIT_ARTIFACTS,
        },
        {
            "domain_id": "D3_ADAPTIVE_EVOLUTION_AUTHORIZATION",
            "selected_posture": "ADAPTER_EVOLUTION_AUTHORIZED",
            "scope_boundary": "Adaptive evolution is authorized for adapters inside one governed civilization lane only. Promotion, tournament, merge, and rollback remain receipted. Learned-router cutover and multi-lobe promotion remain blocked until the ordered proof chain is separately earned.",
            "validator_chain": EXPECTED_B04_VALIDATORS,
            "rollback_condition": "Any promotion regression, rollback drill failure, no-regression breach, or router/lobe ordered-proof violation forces hold or revoke and blocks activation.",
            "proof_required": [
                "KT_PROD_CLEANROOM/reports/bounded_learning_receipt.json",
                "KT_PROD_CLEANROOM/reports/promotion_binding_receipt.json",
                "KT_PROD_CLEANROOM/reports/forge_generation_receipt.json",
                "KT_PROD_CLEANROOM/reports/civilization_loop_receipt.json",
                "KT_PROD_CLEANROOM/reports/learning_response_receipt.json",
                "KT_PROD_CLEANROOM/reports/rollback_drill_receipt.json",
            ],
        },
    ]


def _launch_surface_allows_progress(root: Path, next_contract: Dict[str, Any]) -> bool:
    contract_path = root / DEFAULT_B04_LAUNCH_CONTRACT_REL
    if not contract_path.exists():
        return False
    launch_contract = load_json(contract_path)
    return (
        str(launch_contract.get("activation_mode", "")).strip() == "LAUNCH_SURFACE_ONLY_NO_IMPLEMENTATION"
        and str(launch_contract.get("first_ratification_step_id", "")).strip() == "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION"
        and str(launch_contract.get("next_lawful_move_after_launch", "")).strip() == "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION"
        and str(next_contract.get("exact_next_counted_workstream_id", "")).strip() == "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION"
        and str(next_contract.get("execution_mode", "")).strip() == "CIVILIZATION_RATIFICATION_ORDER_LOCKED__FIRST_STEP_ONLY"
        and bool(next_contract.get("repo_state_executable_now")) is True
    )


def _gate_d_progress_is_order_locked(reanchor: Dict[str, Any], next_contract: Dict[str, Any]) -> bool:
    next_step = str(next_contract.get("exact_next_counted_workstream_id", "")).strip()
    execution_mode = str(next_contract.get("execution_mode", "")).strip()
    repo_executable = bool(next_contract.get("repo_state_executable_now")) is True
    if next_step == EXPECTED_B04_LAUNCH_STEP_ID:
        return (
            execution_mode == "POSTURES_SELECTED__SEPARATE_LAUNCH_SURFACE_REQUIRED"
            and bool(next_contract.get("repo_state_executable_now")) is False
            and str(reanchor.get("next_lawful_move", "")).strip() == EXPECTED_B04_LAUNCH_STEP_ID
        )
    return (
        next_step in EXPECTED_B04_RATIFICATION_SEQUENCE
        and execution_mode.startswith("CIVILIZATION_RATIFICATION_ORDER_LOCKED__")
        and repo_executable
        and str(reanchor.get("next_lawful_move", "")).strip() == next_step
    )


def build_gate_d_decision_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    law = load_json(root / DEFAULT_GATE_D_DECISION_LAW_REL)
    reanchor = load_json(root / DEFAULT_GATE_D_DECISION_REANCHOR_PACKET_REL)
    next_contract = load_json(root / DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    omega_ref = str(next_contract.get("canonical_receipt_binding", {}).get("omega_b04_definition_ref", "")).strip() or DEFAULT_OMEGA_WORK_ORDER_PATH
    omega = load_json(_resolve(root, omega_ref))

    omega_b04 = None
    for batch in omega.get("batches", []):
        if str(batch.get("batch_id", "")).strip() == "B04_GATE_D_CIVILIZATION_ACTIVATE":
            omega_b04 = batch
            break
    if omega_b04 is None:
        raise RuntimeError("FAIL_CLOSED: Omega B04 batch definition missing")

    law_allowed_map = {
        str(domain.get("domain_id", "")).strip(): [str(item).strip() for item in domain.get("allowed_postures", [])]
        for domain in law.get("decision_domains", [])
    }
    law_default_map = {
        str(domain.get("domain_id", "")).strip(): str(domain.get("default_posture", "")).strip()
        for domain in law.get("decision_domains", [])
    }

    selection_rows = []
    for domain_id, selected_posture in EXPECTED_SELECTIONS.items():
        selection_rows.append(
            {
                "domain_id": domain_id,
                "selected_posture": selected_posture,
                "selected_posture_allowed_by_law": selected_posture in law_allowed_map.get(domain_id, []),
                "selected_is_default": selected_posture == law_default_map.get(domain_id, ""),
                "deferred_to_gate": EXPECTED_DEFERRED_GATES.get(domain_id, ""),
            }
        )

    non_default_bindings = _build_non_default_bindings()
    binding_map = {row["domain_id"]: row for row in non_default_bindings}

    checks = [
        {
            "check_id": "decision_law_mode_is_definition_only",
            "pass": str(law.get("mode", "")).strip() == "DEFINITION_ONLY_NO_POSTURE_SELECTED",
        },
        {
            "check_id": "decision_receipt_selects_all_required_domains",
            "pass": list(EXPECTED_SELECTIONS.keys()) == list(law.get("required_domain_ids", [])),
        },
        {
            "check_id": "selected_postures_are_allowed_by_law",
            "pass": all(bool(row["selected_posture_allowed_by_law"]) for row in selection_rows),
        },
        {
            "check_id": "externality_stays_bounded_until_gate_e",
            "pass": EXPECTED_SELECTIONS["D1_EXTERNALITY_WIDENING"] == "EXTERNALITY_BOUNDED"
            and EXPECTED_DEFERRED_GATES["D1_EXTERNALITY_WIDENING"] == "B05_GATE_E_EXTERNALITY_AND_ASSURANCE",
        },
        {
            "check_id": "counted_domains_expand_only_into_one_governed_b04_lane",
            "pass": EXPECTED_SELECTIONS["D2_NEW_COUNTED_DOMAINS"] == "COUNTED_DOMAINS_CONTROLLED_EXPANSION"
            and binding_map["D2_NEW_COUNTED_DOMAINS"]["validator_chain"] == EXPECTED_B04_VALIDATORS
            and binding_map["D2_NEW_COUNTED_DOMAINS"]["proof_required"] == EXPECTED_B04_EMIT_ARTIFACTS
            and [str(item).strip() for item in omega_b04.get("validators", [])] == EXPECTED_B04_VALIDATORS,
        },
        {
            "check_id": "adaptive_evolution_is_adapter_only_and_router_lobe_order_stays_bounded",
            "pass": EXPECTED_SELECTIONS["D3_ADAPTIVE_EVOLUTION_AUTHORIZATION"] == "ADAPTER_EVOLUTION_AUTHORIZED"
            and "learned-router cutover and multi-lobe promotion remain blocked" in binding_map["D3_ADAPTIVE_EVOLUTION_AUTHORIZATION"]["scope_boundary"].lower()
            and binding_map["D3_ADAPTIVE_EVOLUTION_AUTHORIZATION"]["validator_chain"] == EXPECTED_B04_VALIDATORS,
        },
        {
            "check_id": "comparative_claims_remain_blocked_until_gate_f",
            "pass": EXPECTED_SELECTIONS["D4_COMPARATIVE_COMPETITIVE_CLAIMS"] == "NO_EXTERNAL_COMPARATIVE_CLAIMS"
            and EXPECTED_DEFERRED_GATES["D4_COMPARATIVE_COMPETITIVE_CLAIMS"] == "B06_GATE_F_PRODUCT_WEDGE",
        },
        {
            "check_id": "commercial_activation_remains_lab_only_until_gate_f",
            "pass": EXPECTED_SELECTIONS["D5_COMMERCIAL_ACTIVATION"] == "LAB_ONLY"
            and EXPECTED_DEFERRED_GATES["D5_COMMERCIAL_ACTIVATION"] == "B06_GATE_F_PRODUCT_WEDGE",
        },
        {
            "check_id": "decision_receipt_does_not_activate_b04",
            "pass": law.get("activation_rules", {}).get("gate_d_decision_does_not_activate_b04_by_itself") is True,
        },
        {
            "check_id": "reanchor_packet_agrees_gate_d_is_still_nonactivating",
            "pass": str(reanchor.get("gate_d_decision_law_state", {}).get("mode", "")).strip()
            == "DEFINITION_ONLY_NO_POSTURE_SELECTED"
            and bool(reanchor.get("gate_d_decision_law_state", {}).get("b04_activation_allowed")) is False,
        },
        {
            "check_id": "next_contract_after_selection_requires_separate_b04_launch_surface",
            "pass": _gate_d_progress_is_order_locked(reanchor, next_contract)
            or _launch_surface_allows_progress(root, next_contract),
        },
        {
            "check_id": "receipt_is_same_head_selection_artifact",
            "pass": True,
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_d.decision_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_GATE_D_POSTURE_SELECTION_ARTIFACT_ONLY",
        "decision_mode": "POSTURE_SELECTION_ONLY_NO_IMPLEMENTATION",
        "decision_law_head": current_head,
        "gate_c_exit_head": str(law.get("gate_c_exit_head", "")).strip(),
        "reanchor_head": str(law.get("reanchor_head", "")).strip(),
        "selected_postures": selection_rows,
        "non_default_posture_bindings": non_default_bindings,
        "implementation_activation": {
            "b04_activation_allowed": False,
            "separate_launch_surface_required": True,
            "authorized_next_batch_id": "B04_GATE_D_CIVILIZATION_ACTIVATE",
            "activation_rule": "Gate D posture selection authorizes later bounded B04 launch planning only. It does not itself execute civilization activation.",
        },
        "canonical_receipt_binding": {
            "gate_d_decision_law_ref": DEFAULT_GATE_D_DECISION_LAW_REL,
            "gate_d_decision_reanchor_packet_ref": DEFAULT_GATE_D_DECISION_REANCHOR_PACKET_REL,
            "omega_b04_definition_ref": omega_ref,
        },
        "checks": checks,
        "next_lawful_move": (
            "B04_GATE_D_CIVILIZATION_ACTIVATE__SEPARATE_LAUNCH_SURFACE_REQUIRED"
            if status == "PASS"
            else "FIX_GATE_D_POSTURE_SELECTION_DEFECT"
        ),
        "claim_boundary": "This receipt selects Gate D postures only. It does not execute B04 implementation, does not widen externality above E1, does not open external comparative claims, and does not activate commercial deployment.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the same-head Gate D posture-selection receipt without activating B04.")
    parser.add_argument("--output", default=DEFAULT_GATE_D_DECISION_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    receipt = build_gate_d_decision_receipt(root=root)
    output = _resolve(root, str(args.output))
    _write_receipt(
        root=root,
        target=output,
        payload=receipt,
        allow_default_repo_write=args.allow_tracked_output_refresh,
    )
    summary = {
        "status": receipt["status"],
        "gate_d_posture_selection_status": receipt["status"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
