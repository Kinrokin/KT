from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator import cohort0_dual_lane_successor_controller_tranche as controller_tranche
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_third_successor_bridge_bound_tranche as third_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_DUAL_LANE_CONTROLLER_REL = f"KT_PROD_CLEANROOM/reports/{controller_tranche.OUTPUT_DUAL_LANE_CONTROLLER}"
DEFAULT_DUAL_LANE_LAUNCH_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{controller_tranche.OUTPUT_DUAL_LANE_LAUNCH_RECEIPT}"
DEFAULT_MUTATION_BANK_REL = f"KT_PROD_CLEANROOM/reports/{controller_tranche.OUTPUT_MUTATION_BANK}"
DEFAULT_MUTATION_CONTRACT_REL = f"KT_PROD_CLEANROOM/reports/{controller_tranche.OUTPUT_MUTATION_MATERIALITY_CONTRACT}"
DEFAULT_FAMILY_REGISTRY_REL = f"KT_PROD_CLEANROOM/reports/{controller_tranche.OUTPUT_FAMILY_PROSPECT_REGISTRY}"
DEFAULT_NEW_FAMILY_CONTRACT_REL = f"KT_PROD_CLEANROOM/reports/{controller_tranche.OUTPUT_NEW_FAMILY_CONTRACT}"
DEFAULT_THIRD_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_THIRD_BRIDGE_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_BRIDGE_SCORECARD}"
DEFAULT_THIRD_HARNESS_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_HARNESS_SCORECARD}"
DEFAULT_THIRD_ROW_PANEL_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_ROW_PANEL}"
DEFAULT_ROUTE_BEARING_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_ROUTE_BEARING_INDEX_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_index.json"
DEFAULT_ROUTE_BEARING_PREREG_REL = "KT_PROD_CLEANROOM/reports/route_bearing_battery_preregistration.json"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_LANE_A_SCORECARD = "cohort0_dual_lane_lane_a_mutation_scorecard.json"
OUTPUT_LANE_B_SCORECARD = "cohort0_dual_lane_lane_b_family_scorecard.json"
OUTPUT_COMPARATIVE_SUMMARY = "cohort0_dual_lane_first_execution_comparative_summary.json"
OUTPUT_EXECUTION_WAVE_BOARD = "cohort0_dual_lane_first_execution_wave_board.json"
OUTPUT_EXECUTION_MANIFEST = "cohort0_dual_lane_first_execution_manifest.json"
OUTPUT_EXECUTION_RECEIPT = "cohort0_dual_lane_first_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_DUAL_LANE_FIRST_EXECUTION_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: dual-lane first execution requires one same-head authority line")
    return next(iter(heads))


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    dual_lane_controller: Dict[str, Any],
    dual_lane_launch_receipt: Dict[str, Any],
    mutation_bank: Dict[str, Any],
    mutation_contract: Dict[str, Any],
    family_registry: Dict[str, Any],
    new_family_contract: Dict[str, Any],
    third_execution_receipt: Dict[str, Any],
    third_bridge_scorecard: Dict[str, Any],
    third_harness_scorecard: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    route_bearing_prereg: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (dual_lane_controller, "dual-lane successor controller"),
        (dual_lane_launch_receipt, "dual-lane launch receipt"),
        (mutation_bank, "route-bearing mutation bank"),
        (mutation_contract, "mutation materiality contract"),
        (family_registry, "family prospect registry"),
        (new_family_contract, "new family contract"),
        (third_execution_receipt, "third successor execution receipt"),
        (third_bridge_scorecard, "third successor bridge scorecard"),
        (third_harness_scorecard, "third successor fixed harness scorecard"),
        (third_row_panel, "third successor row panel"),
        (route_bearing_manifest, "route-bearing stage pack manifest"),
        (route_bearing_index, "route-bearing stage pack index"),
        (route_bearing_prereg, "route-bearing preregistration"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain blocked")
    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block must remain active")

    if str(dual_lane_controller.get("execution_status", "")).strip() != "PASS__DUAL_LANE_CONTROLLER_BOUND__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: dual-lane controller must be bound before first execution")
    if str(dual_lane_launch_receipt.get("execution_status", "")).strip() != "PASS__DUAL_LANE_LAUNCH_BOUND__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: dual-lane launch receipt must be bound before first execution")
    if str(dual_lane_launch_receipt.get("lead_bridge_candidate_id", "")).strip() != controller_tranche.LEAD_BRIDGE_ID:
        raise RuntimeError("FAIL_CLOSED: unexpected lead bridge for dual-lane execution")
    if bool(dual_lane_launch_receipt.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked")
    if bool(dual_lane_launch_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain closed")
    if bool(dual_lane_launch_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed")

    if str(mutation_bank.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: mutation bank must remain authorized but unexecuted")
    if str(family_registry.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: family registry must remain authorized but unexecuted")
    if str(mutation_contract.get("execution_status", "")).strip() != "BOUND__READY_FOR_MUTATION_GENERATION":
        raise RuntimeError("FAIL_CLOSED: mutation contract must remain bound")
    if str(new_family_contract.get("execution_status", "")).strip() != "BOUND__READY_FOR_FAMILY_DISCOVERY":
        raise RuntimeError("FAIL_CLOSED: new-family contract must remain bound")

    if str(third_execution_receipt.get("execution_status", "")).strip() != "PASS__THIRD_WAVE_BRIDGE_BOUND_STRENGTHENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: third-wave bridge-bound strengthening must exist")
    if str(third_execution_receipt.get("selected_bridge_candidate_id", "")).strip() != controller_tranche.LEAD_BRIDGE_ID:
        raise RuntimeError("FAIL_CLOSED: third-wave selected bridge mismatch")
    if not bool(third_execution_receipt.get("bridge_alignment_visible", False)):
        raise RuntimeError("FAIL_CLOSED: bridge alignment must remain visible")
    if not bool(third_execution_receipt.get("fixed_harness_route_consequence_signal_nonzero", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness signal must remain nonzero")
    if not bool(third_execution_receipt.get("fixed_harness_stable_vs_second_wave", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness must remain stable")
    if not bool(third_execution_receipt.get("route_bearing_family_inventory_exhausted_on_saved_head", False)):
        raise RuntimeError("FAIL_CLOSED: saved-head route-bearing inventory must remain exhausted")

    if str(route_bearing_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing manifest must PASS")
    if str(route_bearing_index.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing index must PASS")
    if str(route_bearing_prereg.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing preregistration must PASS")


def _lane_a_scorecard(
    *,
    mutation_bank: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    third_bridge_scorecard: Dict[str, Any],
    third_harness_scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    rows_by_case = {
        str(row.get("case_id", "")).strip(): row
        for row in third_row_panel.get("rows", [])
        if isinstance(row, dict) and str(row.get("case_id", "")).strip()
    }
    family_metrics = {
        str(family_id).strip(): metrics
        for family_id, metrics in dict(third_bridge_scorecard.get("family_metrics", {})).items()
        if str(family_id).strip()
    }
    wrong_route_total = float(
        third_harness_scorecard.get("interventions", {}).get("FORCED_WRONG_ROUTE_PRIMARY", {}).get("total_cost", 0.0)
    )
    witness_ablation_total = float(
        third_harness_scorecard.get("interventions", {}).get("WITNESS_ABLATION_PRIMARY", {}).get("total_cost", 0.0)
    )
    scored: List[Dict[str, Any]] = []
    for candidate in mutation_bank.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        case_id = str(candidate.get("source_case_id", "")).strip()
        row = rows_by_case.get(case_id)
        if not row:
            continue
        family_id = str(candidate.get("source_family_id", "")).strip()
        family_selected = dict(family_metrics.get(family_id, {})).get("selected_bridge", {})
        materiality_score = _round_float(
            min(1.0, len(candidate.get("required_changed_axes", [])) / 3.0)
            * 0.6
            + min(1.0, len(candidate.get("seeded_mutation_dimensions", [])) / 5.0) * 0.4
        )
        bridge_retention_score = _round_float(
            (
                float(family_selected.get("reason_exact_accuracy", 0.0))
                + float(family_selected.get("reason_admissible_accuracy", 0.0))
            )
            / 2.0
        )
        wrong_route_cost = float(row.get("wrong_route_cost", 0.0))
        observed_route_margin = float(row.get("observed_route_margin", 0.0))
        consequence_pressure_score = _round_float(
            (wrong_route_cost / max(1.0, wrong_route_total / 10.0)) * 0.7
            + min(1.0, observed_route_margin / 1.5) * 0.3
        )
        harness_retention_score = _round_float(
            min(1.0, wrong_route_cost / 2.0) * 0.7
            + min(1.0, witness_ablation_total / max(1.0, wrong_route_total)) * 0.3
        )
        composite_score = _round_float(
            materiality_score * 0.2
            + bridge_retention_score * 0.3
            + consequence_pressure_score * 0.3
            + harness_retention_score * 0.2
        )
        scored.append(
            {
                "mutation_candidate_id": str(candidate.get("mutation_candidate_id", "")).strip(),
                "source_case_id": case_id,
                "source_family_id": family_id,
                "source_legacy_family_id": str(candidate.get("source_legacy_family_id", "")).strip(),
                "variant_type": str(candidate.get("variant_type", "")).strip(),
                "materiality_gate_pass": materiality_score >= 1.0,
                "bridge_retention_visible": bridge_retention_score >= 1.0
                and bool(row.get("selected_bridge_reason_exact", False))
                and bool(row.get("selected_bridge_reason_admissible", False)),
                "route_consequence_visible": wrong_route_cost > 0.0,
                "materiality_score": materiality_score,
                "bridge_retention_score": bridge_retention_score,
                "consequence_pressure_score": consequence_pressure_score,
                "harness_retention_score": harness_retention_score,
                "composite_priority_score": composite_score,
                "wrong_route_cost": _round_float(wrong_route_cost),
                "observed_route_margin": _round_float(observed_route_margin),
                "selected_bridge_reason_label": str(row.get("selected_bridge_reason_label", "")).strip(),
            }
        )

    scored.sort(
        key=lambda item: (
            -float(item.get("composite_priority_score", 0.0)),
            -float(item.get("wrong_route_cost", 0.0)),
            str(item.get("mutation_candidate_id", "")),
        )
    )
    survivors: List[Dict[str, Any]] = []
    seen_families: set[str] = set()
    for item in scored:
        family_id = str(item.get("source_family_id", "")).strip()
        if family_id in seen_families:
            continue
        if len(survivors) >= 2:
            break
        if not bool(item.get("materiality_gate_pass", False)):
            continue
        if not bool(item.get("bridge_retention_visible", False)):
            continue
        if not bool(item.get("route_consequence_visible", False)):
            continue
        survivors.append(item)
        seen_families.add(family_id)

    survivor_ids = {str(item.get("mutation_candidate_id", "")).strip() for item in survivors}
    rejected: List[Dict[str, Any]] = []
    reserves: List[Dict[str, Any]] = []
    for item in scored:
        candidate_id = str(item.get("mutation_candidate_id", "")).strip()
        if candidate_id in survivor_ids:
            continue
        if not bool(item.get("materiality_gate_pass", False)):
            rejected.append(
                {
                    "lane": "lane_a_mutation_generation_assault",
                    "item_id": candidate_id,
                    "disposition": "REJECTED__NON_MATERIAL",
                }
            )
            continue
        reserves.append(
            {
                "lane": "lane_a_mutation_generation_assault",
                "item_id": candidate_id,
                "disposition": "RESERVE__SURVIVOR_BUDGET_EXCEEDED",
            }
        )

    return {
        "schema_id": "kt.operator.cohort0_dual_lane_lane_a_mutation_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This scorecard executes Lane A candidate scoring on the current bridge-bound source row panel only. "
            "It does not execute generated mutation text or claim theorem movement."
        ),
        "execution_status": "PASS__LANE_A_FIRST_CONCURRENT_SCORING_EXECUTED",
        "lane_role": "BATTERING_RAM",
        "lead_bridge_candidate_id": controller_tranche.LEAD_BRIDGE_ID,
        "candidate_count": len(scored),
        "survivor_count": len(survivors),
        "survivors": survivors,
        "reserves": reserves,
        "rejections": rejected,
        "candidates": scored,
    }


def _canonical_visible_variant_count(prospect: Dict[str, Any]) -> int:
    visible_variants = {str(item).strip() for item in prospect.get("visible_case_variants", []) if str(item).strip()}
    canonical = {"ADVERSARIAL", "AMBIGUITY_BOUNDARY", "GOVERNED_EXECUTION", "MIXED_PRESSURE"}
    return len(visible_variants & canonical)


def _lane_b_scorecard(
    *,
    family_registry: Dict[str, Any],
    dual_lane_controller: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
) -> Tuple[Dict[str, Any], bool]:
    shared_core = dict(dual_lane_controller.get("shared_locked_core", {}))
    current_ring_current = {str(item).strip() for item in shared_core.get("current_route_ring_family_ids", []) if str(item).strip()}
    current_ring_legacy = {str(item).strip() for item in shared_core.get("current_route_ring_legacy_family_ids", []) if str(item).strip()}
    case_ref_raw = str(route_bearing_manifest.get("authoritative_stage_pack_cases_ref", "")).strip()
    stage_pack_cases_available = bool(case_ref_raw) and Path(case_ref_raw).expanduser().exists()

    scored: List[Dict[str, Any]] = []
    for prospect in family_registry.get("prospects", []):
        if not isinstance(prospect, dict):
            continue
        family_id = str(prospect.get("family_id", "")).strip()
        legacy_overlap = family_id in current_ring_legacy
        current_overlap = family_id in current_ring_current
        novelty_gate_pass = not legacy_overlap and not current_overlap
        visible_variant_score = _round_float(_canonical_visible_variant_count(prospect) / 4.0)
        held_out_ready = "HELD_OUT_MUTATION" in {
            str(item).strip() for item in prospect.get("held_out_case_variants", []) if str(item).strip()
        }
        pack_readiness_score = _round_float(
            visible_variant_score * 0.7
            + (1.0 if held_out_ready else 0.0) * 0.3
        )
        comparator_relevance_score = _round_float(
            1.0
            if str(prospect.get("acceptance_metric", "")).strip() and str(prospect.get("alpha_liability", "")).strip()
            else 0.0
        )
        target_ready_score = _round_float(1.0 if str(prospect.get("target_lobe_id", "")).strip() else 0.0)
        composite_score = _round_float(
            (1.0 if novelty_gate_pass else 0.0) * 0.45
            + pack_readiness_score * 0.25
            + comparator_relevance_score * 0.2
            + target_ready_score * 0.1
        )
        scored.append(
            {
                "family_id": family_id,
                "novelty_gate_pass": novelty_gate_pass,
                "legacy_ring_overlap_detected": legacy_overlap,
                "current_ring_overlap_detected": current_overlap,
                "pack_readiness_score": pack_readiness_score,
                "comparator_relevance_score": comparator_relevance_score,
                "target_ready_score": target_ready_score,
                "composite_priority_score": composite_score,
                "visible_case_count": int(prospect.get("visible_case_count", 0)),
                "held_out_case_count": int(prospect.get("held_out_case_count", 0)),
                "visible_case_variants": list(prospect.get("visible_case_variants", [])),
                "held_out_case_variants": list(prospect.get("held_out_case_variants", [])),
            }
        )

    scored.sort(
        key=lambda item: (
            -int(bool(item.get("novelty_gate_pass", False))),
            -float(item.get("composite_priority_score", 0.0)),
            str(item.get("family_id", "")),
        )
    )
    survivors = [item for item in scored if bool(item.get("novelty_gate_pass", False))][:2]
    survivor_ids = {str(item.get("family_id", "")).strip() for item in survivors}
    rejected: List[Dict[str, Any]] = []
    reserves: List[Dict[str, Any]] = []
    for item in scored:
        family_id = str(item.get("family_id", "")).strip()
        if family_id in survivor_ids:
            continue
        if not bool(item.get("novelty_gate_pass", False)):
            disposition = "REJECTED__LEGACY_ROUTE_RING_OVERLAP" if bool(item.get("legacy_ring_overlap_detected", False)) else "REJECTED__NOT_MATERIALLY_NEW"
            rejected.append(
                {
                    "lane": "lane_b_new_route_bearing_family_discovery",
                    "item_id": family_id,
                    "disposition": disposition,
                }
            )
            continue
        reserves.append(
            {
                "lane": "lane_b_new_route_bearing_family_discovery",
                "item_id": family_id,
                "disposition": "RESERVE__SURVIVOR_BUDGET_EXCEEDED",
            }
        )

    return (
        {
            "schema_id": "kt.operator.cohort0_dual_lane_lane_b_family_scorecard.v1",
            "status": "PASS",
            "generated_utc": utc_now_iso_z(),
            "claim_boundary": (
                "This scorecard executes Lane B novelty and pack-readiness screening only. "
                "The referenced stage-pack case payload is not live on disk, so this tranche does not claim family-level bridge or harness execution."
            ),
            "execution_status": "PASS__LANE_B_FIRST_CONCURRENT_SCREENING_EXECUTED",
            "lane_role": "SIEGE_ENGINE",
            "lead_bridge_candidate_id": controller_tranche.LEAD_BRIDGE_ID,
            "stage_pack_case_execution_available": stage_pack_cases_available,
            "prospect_count": len(scored),
            "survivor_count": len(survivors),
            "survivors": survivors,
            "reserves": reserves,
            "rejections": rejected,
            "prospects": scored,
            "ranking_tie_breaker": "alphabetical_family_id_after_equal_screen_scores",
        },
        stage_pack_cases_available,
    )


def _comparative_summary(
    *,
    lane_a_scorecard: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    stage_pack_cases_available: bool,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_dual_lane_first_execution_comparative_summary.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This summary compares first concurrent lane execution only. "
            "It does not claim reentry admissibility or Gate D movement."
        ),
        "execution_status": "PASS__DUAL_LANE_FIRST_CONCURRENT_SUMMARY_EMITTED",
        "lane_a_execution_mode": "SOURCE_ROW_PANEL_SCREENING_AND_PRIORITY_SCORING",
        "lane_b_execution_mode": "NOVELTY_AND_PACK_READINESS_SCREENING_ONLY",
        "lane_b_case_execution_available": stage_pack_cases_available,
        "lane_a_survivor_ids": [str(item.get("mutation_candidate_id", "")).strip() for item in lane_a_scorecard.get("survivors", [])],
        "lane_b_survivor_ids": [str(item.get("family_id", "")).strip() for item in lane_b_scorecard.get("survivors", [])],
        "lane_a_candidate_count": int(lane_a_scorecard.get("candidate_count", 0)),
        "lane_b_prospect_count": int(lane_b_scorecard.get("prospect_count", 0)),
        "immediate_stronger_lane": "lane_a_mutation_generation_assault",
        "deeper_proof_lane": "lane_b_new_route_bearing_family_discovery",
        "next_wave_rule": [
            "Advance the top 1-2 survivors per lane only.",
            "Keep the fixed harness, same-head comparator, and counted-boundary lock unchanged.",
            "Do not narrate readjudication until a later executed wave broadens dominance materially.",
        ],
    }


def _markdown_report(execution_manifest: Dict[str, Any], outputs: Sequence[str]) -> str:
    lines: List[str] = []
    lines.append("# COHORT0 Dual-Lane First Execution Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{execution_manifest['generated_utc']}`")
    lines.append(f"- Subject head: `{execution_manifest['subject_head']}`")
    lines.append(f"- Lead bridge: `{execution_manifest['lead_bridge_candidate_id']}`")
    lines.append("")
    lines.append("## What Ran")
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


def run_dual_lane_first_execution_tranche(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    dual_lane_controller_path: Path,
    dual_lane_launch_receipt_path: Path,
    mutation_bank_path: Path,
    mutation_contract_path: Path,
    family_registry_path: Path,
    new_family_contract_path: Path,
    third_execution_receipt_path: Path,
    third_bridge_scorecard_path: Path,
    third_harness_scorecard_path: Path,
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
    dual_lane_controller = _load_json_required(dual_lane_controller_path, label="dual-lane successor controller")
    dual_lane_launch_receipt = _load_json_required(dual_lane_launch_receipt_path, label="dual-lane launch receipt")
    mutation_bank = _load_json_required(mutation_bank_path, label="route-bearing mutation bank")
    mutation_contract = _load_json_required(mutation_contract_path, label="mutation materiality contract")
    family_registry = _load_json_required(family_registry_path, label="family prospect registry")
    new_family_contract = _load_json_required(new_family_contract_path, label="new family contract")
    third_execution_receipt = _load_json_required(third_execution_receipt_path, label="third successor execution receipt")
    third_bridge_scorecard = _load_json_required(third_bridge_scorecard_path, label="third successor bridge scorecard")
    third_harness_scorecard = _load_json_required(third_harness_scorecard_path, label="third successor fixed harness scorecard")
    third_row_panel = _load_json_required(third_row_panel_path, label="third successor row panel")
    route_bearing_manifest = _load_json_required(route_bearing_manifest_path, label="route-bearing stage pack manifest")
    route_bearing_index = _load_json_required(route_bearing_index_path, label="route-bearing stage pack index")
    route_bearing_prereg = _load_json_required(route_bearing_prereg_path, label="route-bearing preregistration")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        dual_lane_controller=dual_lane_controller,
        dual_lane_launch_receipt=dual_lane_launch_receipt,
        mutation_bank=mutation_bank,
        mutation_contract=mutation_contract,
        family_registry=family_registry,
        new_family_contract=new_family_contract,
        third_execution_receipt=third_execution_receipt,
        third_bridge_scorecard=third_bridge_scorecard,
        third_harness_scorecard=third_harness_scorecard,
        third_row_panel=third_row_panel,
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        route_bearing_prereg=route_bearing_prereg,
    )

    subject_head = _require_same_subject_head(
        [
            verdict_packet,
            reentry_block,
            dual_lane_controller,
            dual_lane_launch_receipt,
            mutation_bank,
            mutation_contract,
            family_registry,
            new_family_contract,
            third_execution_receipt,
            third_bridge_scorecard,
            third_harness_scorecard,
            third_row_panel,
            route_bearing_manifest,
            route_bearing_index,
            route_bearing_prereg,
        ]
    )
    if subject_head != setup_tranche.EXPECTED_SUBJECT_HEAD:
        raise RuntimeError("FAIL_CLOSED: unexpected subject head for dual-lane first execution")

    lane_a_scorecard = _lane_a_scorecard(
        mutation_bank=mutation_bank,
        third_row_panel=third_row_panel,
        third_bridge_scorecard=third_bridge_scorecard,
        third_harness_scorecard=third_harness_scorecard,
    )
    lane_b_scorecard, stage_pack_cases_available = _lane_b_scorecard(
        family_registry=family_registry,
        dual_lane_controller=dual_lane_controller,
        route_bearing_manifest=route_bearing_manifest,
    )
    comparative_summary = _comparative_summary(
        lane_a_scorecard=lane_a_scorecard,
        lane_b_scorecard=lane_b_scorecard,
        stage_pack_cases_available=stage_pack_cases_available,
    )

    promotion_receipt = {
        "schema_id": "kt.operator.cohort0_dual_lane_promotion_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": "This receipt promotes only first-wave dual-lane survivors for next comparative execution. It is not a theorem receipt.",
        "execution_status": "PASS__FIRST_CONCURRENT_SURVIVORS_SELECTED",
        "promotions": [
            {
                "lane": "lane_a_mutation_generation_assault",
                "item_id": str(item.get("mutation_candidate_id", "")).strip(),
                "source_family_id": str(item.get("source_family_id", "")).strip(),
            }
            for item in lane_a_scorecard.get("survivors", [])
        ]
        + [
            {
                "lane": "lane_b_new_route_bearing_family_discovery",
                "item_id": str(item.get("family_id", "")).strip(),
            }
            for item in lane_b_scorecard.get("survivors", [])
        ],
    }
    rejection_receipt = {
        "schema_id": "kt.operator.cohort0_dual_lane_rejection_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": "This receipt records first-wave dual-lane non-promotions only. It is not a theorem receipt.",
        "execution_status": "PASS__FIRST_CONCURRENT_NON_PROMOTIONS_RECORDED",
        "rejections": list(lane_a_scorecard.get("rejections", [])) + list(lane_b_scorecard.get("rejections", [])),
        "reserves": list(lane_a_scorecard.get("reserves", [])) + list(lane_b_scorecard.get("reserves", [])),
    }
    execution_wave_board = {
        "schema_id": "kt.operator.cohort0_dual_lane_first_execution_wave_board.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": "This board tracks first concurrent dual-lane execution state only. It does not claim theorem movement.",
        "execution_status": "PASS__DUAL_LANE_FIRST_CONCURRENT_SCREENING_EXECUTED",
        "lane_statuses": {
            "lane_a_mutation_generation_assault": "EXECUTED__SURVIVORS_SELECTED",
            "lane_b_new_route_bearing_family_discovery": "EXECUTED__SURVIVORS_SELECTED",
        },
        "lane_a_survivor_ids": [str(item.get("mutation_candidate_id", "")).strip() for item in lane_a_scorecard.get("survivors", [])],
        "lane_b_survivor_ids": [str(item.get("family_id", "")).strip() for item in lane_b_scorecard.get("survivors", [])],
        "counted_boundary_blocked": True,
    }

    execution_manifest = {
        "schema_id": "kt.operator.cohort0_dual_lane_first_execution_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "lead_bridge_candidate_id": controller_tranche.LEAD_BRIDGE_ID,
        "claim_boundary": (
            "This tranche executes first concurrent dual-lane screening and survivor selection only. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": "PASS__DUAL_LANE_FIRST_CONCURRENT_SCREENING_EXECUTED",
        "completed_now": [
            "Executed Lane A source-row screening and priority scoring over all seeded mutation candidates.",
            "Executed Lane B novelty and pack-readiness screening over all seeded family prospects.",
            "Selected the top 1-2 survivors per lane for the next comparative wave.",
            "Kept the lead bridge, fixed harness, same-head comparator, and counted-boundary lock unchanged.",
        ],
    }
    execution_receipt = {
        "schema_id": "kt.operator.cohort0_dual_lane_first_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This receipt records first concurrent dual-lane screening only. "
            "It does not claim mutation-text execution, family-level bridge execution, Gate D reopening, or Gate E opening."
        ),
        "execution_status": execution_manifest["execution_status"],
        "lead_bridge_candidate_id": controller_tranche.LEAD_BRIDGE_ID,
        "lane_a_candidate_count": int(lane_a_scorecard.get("candidate_count", 0)),
        "lane_b_prospect_count": int(lane_b_scorecard.get("prospect_count", 0)),
        "lane_a_survivor_count": int(lane_a_scorecard.get("survivor_count", 0)),
        "lane_b_survivor_count": int(lane_b_scorecard.get("survivor_count", 0)),
        "lane_a_survivor_ids": [str(item.get("mutation_candidate_id", "")).strip() for item in lane_a_scorecard.get("survivors", [])],
        "lane_b_survivor_ids": [str(item.get("family_id", "")).strip() for item in lane_b_scorecard.get("survivors", [])],
        "lane_b_case_execution_available": stage_pack_cases_available,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": setup_tranche.EXPECTED_PRIMARY_MOVE,
        "secondary_parallel_move": setup_tranche.EXPECTED_SECONDARY_MOVE,
    }

    lane_a_scorecard["subject_head"] = subject_head
    lane_b_scorecard["subject_head"] = subject_head
    comparative_summary["subject_head"] = subject_head

    artifact_payloads = {
        OUTPUT_LANE_A_SCORECARD: lane_a_scorecard,
        OUTPUT_LANE_B_SCORECARD: lane_b_scorecard,
        OUTPUT_COMPARATIVE_SUMMARY: comparative_summary,
        OUTPUT_EXECUTION_WAVE_BOARD: execution_wave_board,
        controller_tranche.OUTPUT_DUAL_LANE_PROMOTION_RECEIPT: promotion_receipt,
        controller_tranche.OUTPUT_DUAL_LANE_REJECTION_RECEIPT: rejection_receipt,
        OUTPUT_EXECUTION_MANIFEST: execution_manifest,
        OUTPUT_EXECUTION_RECEIPT: execution_receipt,
    }
    output_paths: List[str] = []
    for filename, payload in artifact_payloads.items():
        path = (reports_root / filename).resolve()
        write_json_stable(path, payload)
        output_paths.append(f"KT_PROD_CLEANROOM/reports/{filename}")

    report_text = _markdown_report(execution_manifest, output_paths)
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    _write_text(report_path, report_text)
    output_paths.append(f"KT_PROD_CLEANROOM/reports/{OUTPUT_REPORT}")

    return {
        "execution_manifest": execution_manifest,
        "execution_receipt": execution_receipt,
        "outputs": output_paths,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute the first concurrent dual-lane successor screening wave.")
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--dual-lane-controller", default=DEFAULT_DUAL_LANE_CONTROLLER_REL)
    parser.add_argument("--dual-lane-launch-receipt", default=DEFAULT_DUAL_LANE_LAUNCH_RECEIPT_REL)
    parser.add_argument("--mutation-bank", default=DEFAULT_MUTATION_BANK_REL)
    parser.add_argument("--mutation-contract", default=DEFAULT_MUTATION_CONTRACT_REL)
    parser.add_argument("--family-registry", default=DEFAULT_FAMILY_REGISTRY_REL)
    parser.add_argument("--new-family-contract", default=DEFAULT_NEW_FAMILY_CONTRACT_REL)
    parser.add_argument("--third-execution-receipt", default=DEFAULT_THIRD_EXECUTION_RECEIPT_REL)
    parser.add_argument("--third-bridge-scorecard", default=DEFAULT_THIRD_BRIDGE_SCORECARD_REL)
    parser.add_argument("--third-harness-scorecard", default=DEFAULT_THIRD_HARNESS_SCORECARD_REL)
    parser.add_argument("--third-row-panel", default=DEFAULT_THIRD_ROW_PANEL_REL)
    parser.add_argument("--route-bearing-manifest", default=DEFAULT_ROUTE_BEARING_MANIFEST_REL)
    parser.add_argument("--route-bearing-index", default=DEFAULT_ROUTE_BEARING_INDEX_REL)
    parser.add_argument("--route-bearing-prereg", default=DEFAULT_ROUTE_BEARING_PREREG_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_dual_lane_first_execution_tranche(
        verdict_packet_path=_resolve(root, str(args.verdict_packet)),
        reentry_block_path=_resolve(root, str(args.reentry_block)),
        dual_lane_controller_path=_resolve(root, str(args.dual_lane_controller)),
        dual_lane_launch_receipt_path=_resolve(root, str(args.dual_lane_launch_receipt)),
        mutation_bank_path=_resolve(root, str(args.mutation_bank)),
        mutation_contract_path=_resolve(root, str(args.mutation_contract)),
        family_registry_path=_resolve(root, str(args.family_registry)),
        new_family_contract_path=_resolve(root, str(args.new_family_contract)),
        third_execution_receipt_path=_resolve(root, str(args.third_execution_receipt)),
        third_bridge_scorecard_path=_resolve(root, str(args.third_bridge_scorecard)),
        third_harness_scorecard_path=_resolve(root, str(args.third_harness_scorecard)),
        third_row_panel_path=_resolve(root, str(args.third_row_panel)),
        route_bearing_manifest_path=_resolve(root, str(args.route_bearing_manifest)),
        route_bearing_index_path=_resolve(root, str(args.route_bearing_index)),
        route_bearing_prereg_path=_resolve(root, str(args.route_bearing_prereg)),
        reports_root=_resolve(root, str(args.reports_root)),
    )
    receipt = payload["execution_receipt"]
    print(
        {
            "status": receipt["status"],
            "execution_status": receipt["execution_status"],
            "lane_a_survivor_count": receipt["lane_a_survivor_count"],
            "lane_b_survivor_count": receipt["lane_b_survivor_count"],
            "lane_b_case_execution_available": receipt["lane_b_case_execution_available"],
            "output_count": len(payload["outputs"]),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
