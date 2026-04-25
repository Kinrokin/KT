from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_third_successor_bridge_bound_tranche as third_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_REDESIGN_WORK_ORDER_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_redesign_campaign_work_order.json"
DEFAULT_THEOREM_TARGET_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_next_theorem_target.json"
DEFAULT_MUTATION_PACK_REL = "KT_PROD_CLEANROOM/reports/reportability_bridge_holdout_mutation_pack.json"
DEFAULT_THIRD_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_THIRD_BRIDGE_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_BRIDGE_SCORECARD}"
DEFAULT_THIRD_HARNESS_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_HARNESS_SCORECARD}"
DEFAULT_THIRD_INVENTORY_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_INVENTORY_RECEIPT}"
DEFAULT_THIRD_ROW_PANEL_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_ROW_PANEL}"
DEFAULT_ROUTE_BEARING_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_ROUTE_BEARING_INDEX_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_index.json"
DEFAULT_ROUTE_BEARING_PREREG_REL = "KT_PROD_CLEANROOM/reports/route_bearing_battery_preregistration.json"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

LEAD_BRIDGE_ID = "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1"
SECONDARY_BRIDGE_ID = "RB_TYPED_CAUSAL_SCHEMA_BRIDGE_V1"
GUARDRAIL_BRIDGE_ID = "RB_CALIBRATED_REASON_REFUSAL_BRIDGE_V1"

OUTPUT_MUTATION_MATERIALITY_CONTRACT = "cohort0_mutation_materiality_contract.json"
OUTPUT_MUTATION_BANK = "cohort0_route_bearing_mutation_bank_v1.json"
OUTPUT_MUTATION_ADMISSION_RECEIPT = "cohort0_mutation_admission_receipt_v1.json"
OUTPUT_NEW_FAMILY_CONTRACT = "cohort0_new_route_bearing_family_contract.json"
OUTPUT_FAMILY_PROSPECT_REGISTRY = "cohort0_family_prospect_registry_v1.json"
OUTPUT_FAMILY_NOVELTY_RECEIPT = "cohort0_family_novelty_receipt_v1.json"
OUTPUT_DUAL_LANE_CONTROLLER = "cohort0_dual_lane_successor_controller.json"
OUTPUT_DUAL_LANE_WAVE_BOARD = "cohort0_dual_lane_wave_board.json"
OUTPUT_DUAL_LANE_PROMOTION_RECEIPT = "cohort0_dual_lane_promotion_receipt.json"
OUTPUT_DUAL_LANE_REJECTION_RECEIPT = "cohort0_dual_lane_rejection_receipt.json"
OUTPUT_DUAL_LANE_COMPARATIVE_SUMMARY = "cohort0_dual_lane_comparative_summary.json"
OUTPUT_DUAL_LANE_LAUNCH_RECEIPT = "cohort0_dual_lane_launch_receipt.json"
OUTPUT_REPORT = "COHORT0_DUAL_LANE_SUCCESSOR_CONTROLLER_REPORT.md"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object: {path.as_posix()}")
    return payload


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _require_same_subject_head(packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: dual-lane controller requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    redesign_work_order: Dict[str, Any],
    theorem_target: Dict[str, Any],
    mutation_pack: Dict[str, Any],
    third_execution_receipt: Dict[str, Any],
    third_bridge_scorecard: Dict[str, Any],
    third_harness_scorecard: Dict[str, Any],
    third_inventory_receipt: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    route_bearing_prereg: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (redesign_work_order, "gate d redesign campaign work order"),
        (theorem_target, "gate d next theorem target"),
        (mutation_pack, "reportability bridge mutation pack"),
        (third_execution_receipt, "third successor execution receipt"),
        (third_bridge_scorecard, "third successor bridge coupling scorecard"),
        (third_harness_scorecard, "third successor fixed harness scorecard"),
        (third_inventory_receipt, "third successor inventory boundary receipt"),
        (third_row_panel, "third successor row panel"),
        (route_bearing_manifest, "route-bearing stage pack manifest"),
        (route_bearing_index, "route-bearing stage pack index"),
        (route_bearing_prereg, "route-bearing battery preregistration"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked")
    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block must remain active")

    if str(redesign_work_order.get("next_lawful_move", "")).strip() != setup_tranche.EXPECTED_PRIMARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: redesign work order primary move mismatch")
    if str(theorem_target.get("theorem_target_id", "")).strip() != "ONE_FENCED_FAMILY_INTERVENTIONAL_ROUTE_CONSEQUENCE_ON_MATERIALLY_CHANGED_SUBSTRATE":
        raise RuntimeError("FAIL_CLOSED: theorem target mismatch")

    if str(third_execution_receipt.get("execution_status", "")).strip() != "PASS__THIRD_WAVE_BRIDGE_BOUND_STRENGTHENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: third-wave bridge-bound strengthening must exist before dual-lane launch")
    if str(third_execution_receipt.get("selected_bridge_candidate_id", "")).strip() != LEAD_BRIDGE_ID:
        raise RuntimeError("FAIL_CLOSED: unexpected lead bridge candidate")
    if not bool(third_execution_receipt.get("bridge_alignment_visible", False)):
        raise RuntimeError("FAIL_CLOSED: third-wave bridge alignment must be visible")
    if not bool(third_execution_receipt.get("fixed_harness_route_consequence_signal_nonzero", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness signal must remain nonzero")
    if not bool(third_execution_receipt.get("fixed_harness_stable_vs_second_wave", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness must remain stable versus second wave")
    if not bool(third_execution_receipt.get("route_bearing_family_inventory_exhausted_on_saved_head", False)):
        raise RuntimeError("FAIL_CLOSED: saved-head route-bearing inventory must be exhausted before dual-lane launch")
    if bool(third_execution_receipt.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked")
    if bool(third_execution_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain closed")
    if bool(third_execution_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed")

    if str(mutation_pack.get("execution_status", "")).strip() != "SETUP_BOUND__READY_FOR_FIRST_VARIANTS":
        raise RuntimeError("FAIL_CLOSED: mutation pack must remain setup-bound")
    if str(route_bearing_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing manifest must PASS")
    if str(route_bearing_prereg.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing prereg must PASS")


def _route_ring_family_ids(third_inventory_receipt: Dict[str, Any]) -> List[str]:
    return [str(item).strip() for item in third_inventory_receipt.get("route_bearing_current_family_ids", []) if str(item).strip()]


def _route_ring_legacy_family_ids(third_inventory_receipt: Dict[str, Any]) -> List[str]:
    return [str(item).strip() for item in third_inventory_receipt.get("route_bearing_legacy_family_ids", []) if str(item).strip()]


def _mutation_bank(
    *,
    mutation_pack: Dict[str, Any],
    third_bridge_scorecard: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    lead_bridge_id: str,
) -> Dict[str, Any]:
    mutation_dimensions = [str(item).strip() for item in mutation_pack.get("mutation_dimensions", []) if str(item).strip()]
    rows_by_case = {
        str(row.get("case_id", "")).strip(): row
        for row in third_row_panel.get("rows", [])
        if isinstance(row, dict) and str(row.get("case_id", "")).strip()
    }
    high_consequence_case_ids = [
        str(item).strip()
        for item in third_bridge_scorecard.get("high_consequence_case_ids", [])
        if str(item).strip()
    ]
    vector_by_family = {
        "REPLACEMENT_WITNESS__RIVAL_FRAME_COUNTERREAD_BOUNDARY_GOVERNOR": {
            "vector_id": "RIVAL_FRAME_COUNTERREAD_BOUNDARY_GOVERNOR_MUTATION",
            "required_changed_axes": [
                "rival_frame_structure",
                "counterread_burden",
                "boundary_governor_pressure",
            ],
            "mutation_goal": "Create new route-bearing pressure by changing rival-frame persistence, counterread timing, and boundary commitment pressure together.",
        },
        "STRATEGIST_CONSEQUENCE_CHAIN": {
            "vector_id": "TEMPORAL_CHAIN_ROLLBACK_MUTATION",
            "required_changed_axes": [
                "consequence_chain_geometry",
                "abstain_commit_tension",
                "witness_selection_dependency",
            ],
            "mutation_goal": "Create new route-bearing pressure by changing temporal dependency, deferred rollback risk, and commit-vs-review economics together.",
        },
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
            "vector_id": "ADMISSIBILITY_FAIL_CLOSED_MUTATION",
            "required_changed_axes": [
                "admissibility_fail_closed_interaction",
                "boundary_governor_pressure",
                "counterread_burden",
            ],
            "mutation_goal": "Create new route-bearing pressure by changing admissibility failure geometry, repair order cost, and rival interpretation burden together.",
        },
    }
    invalid_if = [
        "paraphrase_only",
        "formatting_only",
        "namespace_only",
        "role_label_only",
        "same_failure_logic_with_shuffled_wording_only",
        "no_new_route_bearing_consequence_condition",
    ]
    candidates: List[Dict[str, Any]] = []
    for case_id in high_consequence_case_ids:
        row = rows_by_case.get(case_id)
        if not row:
            continue
        family_id = str(row.get("current_family_id", "")).strip()
        family_vector = vector_by_family.get(family_id)
        if not family_vector:
            continue
        candidates.append(
            {
                "mutation_candidate_id": f"MUTATION::{case_id}",
                "source_case_id": case_id,
                "source_family_id": family_id,
                "source_legacy_family_id": str(row.get("legacy_family_id", "")).strip(),
                "variant_type": str(row.get("variant_type", "")).strip(),
                "lead_bridge_candidate_id": lead_bridge_id,
                "mutation_vector_id": family_vector["vector_id"],
                "required_changed_axes": family_vector["required_changed_axes"],
                "seeded_mutation_dimensions": mutation_dimensions,
                "invalid_if": invalid_if,
                "mutation_goal": family_vector["mutation_goal"],
                "must_preserve": [
                    "same_head_comparator_lock",
                    "fixed_causal_harness",
                    "counted_boundary_blocked",
                ],
            }
        )
    return {
        "schema_id": "kt.operator.cohort0_route_bearing_mutation_bank.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This bank seeds materially new route-bearing mutations only. "
            "It is an execution launch surface, not theorem proof."
        ),
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "lead_bridge_candidate_id": lead_bridge_id,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def _family_prospect_registry(
    *,
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    current_route_ring_family_ids: Sequence[str],
) -> Dict[str, Any]:
    route_index_rows = [
        row for row in route_bearing_index.get("rows", [])
        if isinstance(row, dict)
    ]
    visible_variants_by_family: Dict[str, List[str]] = {}
    held_out_variants_by_family: Dict[str, List[str]] = {}
    for row in route_index_rows:
        family_id = str(row.get("family_id", "")).strip()
        variant = str(row.get("case_variant", "")).strip()
        visibility = str(row.get("pack_visibility", "")).strip()
        if not family_id or not variant:
            continue
        target = visible_variants_by_family if visibility == "VISIBLE_TO_AUTHORING" else held_out_variants_by_family
        target.setdefault(family_id, []).append(variant)

    prospects: List[Dict[str, Any]] = []
    for family_row in route_bearing_manifest.get("family_rows", []):
        if not isinstance(family_row, dict):
            continue
        family_id = str(family_row.get("family_id", "")).strip()
        if not family_id or family_id in set(current_route_ring_family_ids):
            continue
        if str(family_row.get("family_category", "")).strip() != "SPECIALIST_WEDGE":
            continue
        if not bool(family_row.get("kaggle_target_eligible", False)):
            continue
        prospects.append(
            {
                "family_id": family_id,
                "family_category": str(family_row.get("family_category", "")).strip(),
                "target_lobe_id": str(family_row.get("target_lobe_id", "")).strip(),
                "acceptance_metric": str(family_row.get("acceptance_metric", "")).strip(),
                "alpha_liability": str(family_row.get("alpha_liability", "")).strip(),
                "visible_case_count": int(family_row.get("visible_case_count", 0)),
                "held_out_case_count": int(family_row.get("held_out_case_count", 0)),
                "visible_case_variants": visible_variants_by_family.get(family_id, []),
                "held_out_case_variants": held_out_variants_by_family.get(family_id, []),
                "novelty_gate": {
                    "must_not_match_current_route_ring": True,
                    "must_add_new_route_bearing_structure": True,
                    "must_add_new_failure_cost_geometry_or_boundary_logic": True,
                },
            }
        )

    return {
        "schema_id": "kt.operator.cohort0_family_prospect_registry.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This registry seeds materially new route-bearing family prospects only. "
            "It is a discovery launch surface, not theorem proof."
        ),
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "prospect_count": len(prospects),
        "prospects": prospects,
    }


def _mutation_materiality_contract(
    *,
    mutation_pack: Dict[str, Any],
    lead_bridge_id: str,
    secondary_bridge_id: str,
    guardrail_bridge_id: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_mutation_materiality_contract.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This contract defines what counts as materially new mutation inventory for Lane A. "
            "It does not execute mutations or claim theorem movement."
        ),
        "execution_status": "BOUND__READY_FOR_MUTATION_GENERATION",
        "lead_bridge_candidate_id": lead_bridge_id,
        "secondary_bridge_candidate_id": secondary_bridge_id,
        "guardrail_bridge_candidate_id": guardrail_bridge_id,
        "allowed_changed_axes": [
            "rival_frame_structure",
            "counterread_burden",
            "boundary_governor_pressure",
            "consequence_chain_geometry",
            "abstain_commit_tension",
            "witness_selection_dependency",
            "admissibility_fail_closed_interaction",
        ],
        "seeded_mutation_dimensions": mutation_pack.get("mutation_dimensions", []),
        "invalid_if": [
            "paraphrase_only",
            "formatting_only",
            "namespace_only",
            "role_label_only",
            "cosmetic_ambiguity_without_new_route_bearing_consequence",
            "same_failure_logic_with_shuffled_wording_only",
        ],
        "required_preservation": [
            "same_head_comparator_lock",
            "fixed_causal_harness_lock",
            "same_head_counted_reentry_block",
        ],
    }


def _new_family_contract(
    *,
    current_route_ring_family_ids: Sequence[str],
    lead_bridge_id: str,
    secondary_bridge_id: str,
    guardrail_bridge_id: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_new_route_bearing_family_contract.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This contract defines what counts as a materially new route-bearing family for Lane B. "
            "It does not execute family discovery or claim theorem movement."
        ),
        "execution_status": "BOUND__READY_FOR_FAMILY_DISCOVERY",
        "excluded_current_route_ring_family_ids": list(current_route_ring_family_ids),
        "lead_bridge_candidate_id": lead_bridge_id,
        "secondary_bridge_candidate_id": secondary_bridge_id,
        "guardrail_bridge_candidate_id": guardrail_bridge_id,
        "novelty_requirements": [
            "new_route_bearing_structure",
            "new_failure_cost_geometry_or_boundary_logic",
            "not_a_relabel_of_the_exhausted_saved_head_ring",
            "not_a_control_family",
        ],
        "required_preservation": [
            "same_head_comparator_lock",
            "fixed_causal_harness_lock",
            "same_head_counted_reentry_block",
        ],
    }


def _comparative_summary(
    *,
    mutation_bank: Dict[str, Any],
    family_registry: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_dual_lane_comparative_summary.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": "This summary binds dual-lane launch roles only. It does not claim execution results.",
        "lane_a_role": "BATTERING_RAM",
        "lane_b_role": "SIEGE_ENGINE",
        "allocation_weights": {
            "lane_a_mutation_generation_assault": 0.7,
            "lane_b_new_route_bearing_family_discovery": 0.3,
        },
        "lane_a_candidate_count": int(mutation_bank.get("candidate_count", 0)),
        "lane_b_prospect_count": int(family_registry.get("prospect_count", 0)),
        "success_ladder": [
            "materially_new_route_bearing_inventory",
            "bridge_retention",
            "fixed_harness_retention",
            "dominance_broadening",
            "reentry_prep_eligibility_only_after_prior_tiers",
        ],
    }


def _markdown_report(execution_manifest: Dict[str, Any], outputs: Sequence[str]) -> str:
    lines: List[str] = []
    lines.append("# COHORT0 Dual-Lane Successor Controller Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{execution_manifest['generated_utc']}`")
    lines.append(f"- Subject head: `{execution_manifest['subject_head']}`")
    lines.append(f"- Lead bridge: `{execution_manifest['lead_bridge_candidate_id']}`")
    lines.append("")
    lines.append("## What Bound")
    lines.append("")
    for item in execution_manifest["completed_now"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Claim Boundary")
    lines.append("")
    lines.append(execution_manifest["claim_boundary"])
    lines.append("")
    lines.append("## Outputs")
    lines.append("")
    for output in outputs:
        lines.append(f"- `{output}`")
    lines.append("")
    return "\n".join(lines)


def run_dual_lane_successor_controller_tranche(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    redesign_work_order_path: Path,
    theorem_target_path: Path,
    mutation_pack_path: Path,
    third_execution_receipt_path: Path,
    third_bridge_scorecard_path: Path,
    third_harness_scorecard_path: Path,
    third_inventory_receipt_path: Path,
    third_row_panel_path: Path,
    route_bearing_manifest_path: Path,
    route_bearing_index_path: Path,
    route_bearing_prereg_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    reports_root = reports_root.resolve()
    reports_root.mkdir(parents=True, exist_ok=True)

    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    redesign_work_order = _load_json_required(redesign_work_order_path, label="gate d redesign campaign work order")
    theorem_target = _load_json_required(theorem_target_path, label="gate d next theorem target")
    mutation_pack = _load_json_required(mutation_pack_path, label="reportability bridge mutation pack")
    third_execution_receipt = _load_json_required(third_execution_receipt_path, label="third successor execution receipt")
    third_bridge_scorecard = _load_json_required(third_bridge_scorecard_path, label="third successor bridge coupling scorecard")
    third_harness_scorecard = _load_json_required(third_harness_scorecard_path, label="third successor fixed harness scorecard")
    third_inventory_receipt = _load_json_required(third_inventory_receipt_path, label="third successor inventory boundary receipt")
    third_row_panel = _load_json_required(third_row_panel_path, label="third successor row panel")
    route_bearing_manifest = _load_json_required(route_bearing_manifest_path, label="route-bearing stage pack manifest")
    route_bearing_index = _load_json_required(route_bearing_index_path, label="route-bearing stage pack index")
    route_bearing_prereg = _load_json_required(route_bearing_prereg_path, label="route-bearing battery preregistration")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        redesign_work_order=redesign_work_order,
        theorem_target=theorem_target,
        mutation_pack=mutation_pack,
        third_execution_receipt=third_execution_receipt,
        third_bridge_scorecard=third_bridge_scorecard,
        third_harness_scorecard=third_harness_scorecard,
        third_inventory_receipt=third_inventory_receipt,
        third_row_panel=third_row_panel,
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        route_bearing_prereg=route_bearing_prereg,
    )

    subject_head = _require_same_subject_head(
        [
            verdict_packet,
            reentry_block,
            redesign_work_order,
            theorem_target,
            mutation_pack,
            third_execution_receipt,
            third_bridge_scorecard,
            third_harness_scorecard,
            third_inventory_receipt,
            third_row_panel,
            route_bearing_manifest,
            route_bearing_index,
            route_bearing_prereg,
        ]
    )
    if subject_head != setup_tranche.EXPECTED_SUBJECT_HEAD:
        raise RuntimeError("FAIL_CLOSED: unexpected subject head for dual-lane controller launch")

    current_route_ring_family_ids = _route_ring_family_ids(third_inventory_receipt)
    current_route_ring_legacy_family_ids = _route_ring_legacy_family_ids(third_inventory_receipt)
    mutation_materiality_contract = _mutation_materiality_contract(
        mutation_pack=mutation_pack,
        lead_bridge_id=LEAD_BRIDGE_ID,
        secondary_bridge_id=SECONDARY_BRIDGE_ID,
        guardrail_bridge_id=GUARDRAIL_BRIDGE_ID,
    )
    mutation_bank = _mutation_bank(
        mutation_pack=mutation_pack,
        third_bridge_scorecard=third_bridge_scorecard,
        third_row_panel=third_row_panel,
        lead_bridge_id=LEAD_BRIDGE_ID,
    )
    mutation_admission_receipt = {
        "schema_id": "kt.operator.cohort0_mutation_admission_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": "This receipt launches Lane A only. It does not claim mutation execution results.",
        "execution_status": "PASS__LANE_A_MUTATION_GENERATION_AUTHORIZED__NOT_EXECUTED",
        "lead_bridge_candidate_id": LEAD_BRIDGE_ID,
        "fixed_causal_harness_locked": True,
        "candidate_count": mutation_bank.get("candidate_count", 0),
    }

    new_family_contract = _new_family_contract(
        current_route_ring_family_ids=current_route_ring_family_ids,
        lead_bridge_id=LEAD_BRIDGE_ID,
        secondary_bridge_id=SECONDARY_BRIDGE_ID,
        guardrail_bridge_id=GUARDRAIL_BRIDGE_ID,
    )
    family_prospect_registry = _family_prospect_registry(
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        current_route_ring_family_ids=current_route_ring_family_ids,
    )
    family_novelty_receipt = {
        "schema_id": "kt.operator.cohort0_family_novelty_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": "This receipt launches Lane B only. It does not claim family discovery execution results.",
        "execution_status": "PASS__LANE_B_FAMILY_DISCOVERY_AUTHORIZED__NOT_EXECUTED",
        "excluded_current_route_ring_family_ids": current_route_ring_family_ids,
        "prospect_count": family_prospect_registry.get("prospect_count", 0),
    }

    comparative_summary = _comparative_summary(
        mutation_bank=mutation_bank,
        family_registry=family_prospect_registry,
    )
    controller = {
        "schema_id": "kt.operator.cohort0_dual_lane_successor_controller.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This controller launches dual-lane successor work only. "
            "It keeps counted reentry blocked and does not claim Gate D movement."
        ),
        "execution_status": "PASS__DUAL_LANE_CONTROLLER_BOUND__NOT_EXECUTED",
        "lead_bridge_candidate_id": LEAD_BRIDGE_ID,
        "secondary_bridge_candidate_id": SECONDARY_BRIDGE_ID,
        "guardrail_bridge_candidate_id": GUARDRAIL_BRIDGE_ID,
        "shared_locked_core": {
            "same_head_comparator_locked": True,
            "same_head_counted_reentry_blocked": True,
            "gate_d_closed": True,
            "gate_e_closed": True,
            "fixed_causal_harness_ref": (reports_root / OUTPUT_DUAL_LANE_WAVE_BOARD).resolve().as_posix(),
            "current_route_ring_family_ids": current_route_ring_family_ids,
            "current_route_ring_legacy_family_ids": current_route_ring_legacy_family_ids,
        },
        "lanes": {
            "lane_a_mutation_generation_assault": {
                "role": "BATTERING_RAM",
                "allocation_weight": 0.7,
                "contract_ref": (reports_root / OUTPUT_MUTATION_MATERIALITY_CONTRACT).resolve().as_posix(),
                "bank_ref": (reports_root / OUTPUT_MUTATION_BANK).resolve().as_posix(),
                "status": "AUTHORIZED__NOT_EXECUTED",
            },
            "lane_b_new_route_bearing_family_discovery": {
                "role": "SIEGE_ENGINE",
                "allocation_weight": 0.3,
                "contract_ref": (reports_root / OUTPUT_NEW_FAMILY_CONTRACT).resolve().as_posix(),
                "registry_ref": (reports_root / OUTPUT_FAMILY_PROSPECT_REGISTRY).resolve().as_posix(),
                "status": "AUTHORIZED__NOT_EXECUTED",
            },
        },
    }
    wave_board = {
        "schema_id": "kt.operator.cohort0_dual_lane_wave_board.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": "This board tracks dual-lane launch state only. It does not claim execution results.",
        "execution_status": "PASS__DUAL_LANE_LAUNCHED__AWAITING_EXECUTION",
        "lead_bridge_candidate_id": LEAD_BRIDGE_ID,
        "lane_statuses": {
            "lane_a_mutation_generation_assault": "AUTHORIZED__NOT_EXECUTED",
            "lane_b_new_route_bearing_family_discovery": "AUTHORIZED__NOT_EXECUTED",
        },
        "immediate_operator_order": [
            "Run Lane A mutation generation against the lead bridge with the fixed harness unchanged.",
            "Run Lane B novelty screen over prospect families in parallel.",
            "Reject non-material mutations and non-novel families automatically before scoring.",
            "Keep counted reentry blocked until executed dual-lane evidence exists.",
        ],
        "inventory_boundary": {
            "current_route_ring_family_ids": current_route_ring_family_ids,
            "current_route_ring_exhausted_on_saved_head": True,
            "next_expansion_requirement": third_execution_receipt.get("next_expansion_requirement", ""),
        },
    }
    promotion_receipt = {
        "schema_id": "kt.operator.cohort0_dual_lane_promotion_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": "EMPTY__AWAITING_DUAL_LANE_EXECUTION",
        "promotions": [],
    }
    rejection_receipt = {
        "schema_id": "kt.operator.cohort0_dual_lane_rejection_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": "EMPTY__AWAITING_DUAL_LANE_EXECUTION",
        "rejections": [],
    }
    launch_receipt = {
        "schema_id": "kt.operator.cohort0_dual_lane_launch_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": "This receipt records dual-lane launch only. It does not claim mutation or family execution results.",
        "execution_status": "PASS__DUAL_LANE_LAUNCH_BOUND__NOT_EXECUTED",
        "lead_bridge_candidate_id": LEAD_BRIDGE_ID,
        "route_bearing_family_inventory_exhausted_on_saved_head": True,
        "lane_a_candidate_count": mutation_bank.get("candidate_count", 0),
        "lane_b_prospect_count": family_prospect_registry.get("prospect_count", 0),
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": setup_tranche.EXPECTED_PRIMARY_MOVE,
        "secondary_parallel_move": setup_tranche.EXPECTED_SECONDARY_MOVE,
    }
    execution_manifest = {
        "schema_id": "kt.operator.cohort0_dual_lane_launch_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This tranche binds the dual-lane successor launch only. "
            "It does not execute Lane A or Lane B and does not change theorem state."
        ),
        "execution_status": "PASS__DUAL_LANE_LAUNCH_BOUND__NOT_EXECUTED",
        "lead_bridge_candidate_id": LEAD_BRIDGE_ID,
        "completed_now": [
            "Bound Lane A mutation-generation launch around the current lead bridge and fixed harness.",
            "Bound Lane B family-discovery launch around materially new route-bearing prospects outside the exhausted saved-head ring.",
            "Locked the same-head comparator and counted-boundary status across both lanes.",
            "Seeded the mutation bank from high-consequence cases on the current widened ring.",
            "Seeded the family prospect registry from preregistered route-bearing families outside the current saved-head inventory.",
        ],
    }

    artifact_payloads = {
        OUTPUT_MUTATION_MATERIALITY_CONTRACT: mutation_materiality_contract,
        OUTPUT_MUTATION_BANK: mutation_bank,
        OUTPUT_MUTATION_ADMISSION_RECEIPT: mutation_admission_receipt,
        OUTPUT_NEW_FAMILY_CONTRACT: new_family_contract,
        OUTPUT_FAMILY_PROSPECT_REGISTRY: family_prospect_registry,
        OUTPUT_FAMILY_NOVELTY_RECEIPT: family_novelty_receipt,
        OUTPUT_DUAL_LANE_CONTROLLER: controller,
        OUTPUT_DUAL_LANE_WAVE_BOARD: wave_board,
        OUTPUT_DUAL_LANE_PROMOTION_RECEIPT: promotion_receipt,
        OUTPUT_DUAL_LANE_REJECTION_RECEIPT: rejection_receipt,
        OUTPUT_DUAL_LANE_COMPARATIVE_SUMMARY: comparative_summary,
        OUTPUT_DUAL_LANE_LAUNCH_RECEIPT: launch_receipt,
    }
    output_paths: List[str] = []
    for filename, payload in artifact_payloads.items():
        payload["subject_head"] = subject_head
        path = (reports_root / filename).resolve()
        write_json_stable(path, payload)
        output_paths.append(f"KT_PROD_CLEANROOM/reports/{filename}")

    manifest_path = (reports_root / "cohort0_dual_lane_launch_manifest.json").resolve()
    write_json_stable(manifest_path, execution_manifest)
    output_paths.append("KT_PROD_CLEANROOM/reports/cohort0_dual_lane_launch_manifest.json")

    report_text = _markdown_report(execution_manifest, output_paths)
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    _write_text(report_path, report_text)
    output_paths.append(f"KT_PROD_CLEANROOM/reports/{OUTPUT_REPORT}")

    return {
        "execution_manifest": execution_manifest,
        "launch_receipt": launch_receipt,
        "outputs": output_paths,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bind the dual-lane successor controller for mutation generation and new family discovery.")
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--redesign-work-order", default=DEFAULT_REDESIGN_WORK_ORDER_REL)
    parser.add_argument("--theorem-target", default=DEFAULT_THEOREM_TARGET_REL)
    parser.add_argument("--mutation-pack", default=DEFAULT_MUTATION_PACK_REL)
    parser.add_argument("--third-execution-receipt", default=DEFAULT_THIRD_EXECUTION_RECEIPT_REL)
    parser.add_argument("--third-bridge-scorecard", default=DEFAULT_THIRD_BRIDGE_SCORECARD_REL)
    parser.add_argument("--third-harness-scorecard", default=DEFAULT_THIRD_HARNESS_SCORECARD_REL)
    parser.add_argument("--third-inventory-receipt", default=DEFAULT_THIRD_INVENTORY_RECEIPT_REL)
    parser.add_argument("--third-row-panel", default=DEFAULT_THIRD_ROW_PANEL_REL)
    parser.add_argument("--route-bearing-manifest", default=DEFAULT_ROUTE_BEARING_MANIFEST_REL)
    parser.add_argument("--route-bearing-index", default=DEFAULT_ROUTE_BEARING_INDEX_REL)
    parser.add_argument("--route-bearing-prereg", default=DEFAULT_ROUTE_BEARING_PREREG_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_dual_lane_successor_controller_tranche(
        verdict_packet_path=_resolve(root, str(args.verdict_packet)),
        reentry_block_path=_resolve(root, str(args.reentry_block)),
        redesign_work_order_path=_resolve(root, str(args.redesign_work_order)),
        theorem_target_path=_resolve(root, str(args.theorem_target)),
        mutation_pack_path=_resolve(root, str(args.mutation_pack)),
        third_execution_receipt_path=_resolve(root, str(args.third_execution_receipt)),
        third_bridge_scorecard_path=_resolve(root, str(args.third_bridge_scorecard)),
        third_harness_scorecard_path=_resolve(root, str(args.third_harness_scorecard)),
        third_inventory_receipt_path=_resolve(root, str(args.third_inventory_receipt)),
        third_row_panel_path=_resolve(root, str(args.third_row_panel)),
        route_bearing_manifest_path=_resolve(root, str(args.route_bearing_manifest)),
        route_bearing_index_path=_resolve(root, str(args.route_bearing_index)),
        route_bearing_prereg_path=_resolve(root, str(args.route_bearing_prereg)),
        reports_root=_resolve(root, str(args.reports_root)),
    )
    receipt = payload["launch_receipt"]
    print(
        {
            "status": receipt["status"],
            "execution_status": receipt["execution_status"],
            "lead_bridge_candidate_id": receipt["lead_bridge_candidate_id"],
            "lane_a_candidate_count": receipt["lane_a_candidate_count"],
            "lane_b_prospect_count": receipt["lane_b_prospect_count"],
            "output_count": len(payload["outputs"]),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
