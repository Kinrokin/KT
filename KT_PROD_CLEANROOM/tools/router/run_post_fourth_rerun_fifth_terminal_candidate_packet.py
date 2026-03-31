from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


_AUDIT_TERMINAL_SUITE_REF = (
    "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/DOWNSTREAM_DIVERSITY_AUDIT_TERMINAL_SUITE_V1.json"
)
_FROZEN_INTER_GATE_STATE = "GATE_D_POST_FOURTH_RERUN_STATIC_HOLD__COUNTED_LANE_CLOSED"


def _ordered_unique(items: Sequence[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in items:
        cleaned = str(item).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


def _validate_current_state_overlay(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.current_campaign_state_overlay.v1":
        raise RuntimeError("FAIL_CLOSED: current state overlay schema mismatch")

    lawful_standing = packet.get("current_lawful_gate_standing")
    if not isinstance(lawful_standing, dict):
        raise RuntimeError("FAIL_CLOSED: current lawful gate standing missing")
    if str(lawful_standing.get("inter_gate_state", "")).strip() != _FROZEN_INTER_GATE_STATE:
        raise RuntimeError("FAIL_CLOSED: current state is not the post-fourth-rerun static hold")
    if str(packet.get("next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: next counted workstream is not blocked R6")
    if bool(packet.get("repo_state_executable_now", False)):
        raise RuntimeError("FAIL_CLOSED: counted lane must remain closed")


def _validate_material_change_target(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.post_fourth_rerun_material_change_target_packet.v1":
        raise RuntimeError("FAIL_CLOSED: post-fourth-rerun target packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: post-fourth-rerun target packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: post-fourth-rerun target packet must be PASS")

    questions = packet.get("questions")
    current_hold = packet.get("current_router_hold_summary")
    if not isinstance(questions, dict) or not isinstance(current_hold, dict):
        raise RuntimeError("FAIL_CLOSED: post-fourth-rerun target packet summaries missing")
    if not bool(questions.get("router_branch_selected", False)):
        raise RuntimeError("FAIL_CLOSED: router branch is not selected")
    if bool(questions.get("pivot_branch_available", False)):
        raise RuntimeError("FAIL_CLOSED: non-router pivot remains available")
    if not bool(questions.get("requires_new_terminal_adapter_beyond_current_four", False)):
        raise RuntimeError("FAIL_CLOSED: target packet no longer requires new downstream terminal breadth")


def _validate_lobe_role_registry(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.governance.lobe_role_registry.v1":
        raise RuntimeError("FAIL_CLOSED: lobe role registry schema mismatch")
    if str(packet.get("status", "")).strip() != "ACTIVE":
        raise RuntimeError("FAIL_CLOSED: lobe role registry must be ACTIVE")


def _validate_lobe_cooperation_matrix(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.lobe_cooperation_matrix.v1":
        raise RuntimeError("FAIL_CLOSED: lobe cooperation matrix schema mismatch")
    if str(packet.get("status", "")).strip() != "ACTIVE":
        raise RuntimeError("FAIL_CLOSED: lobe cooperation matrix must be ACTIVE")


def _validate_routing_delta_matrix(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.routing_delta_matrix.v1":
        raise RuntimeError("FAIL_CLOSED: routing delta matrix schema mismatch")
    if str(packet.get("status", "")).strip() != "ACTIVE":
        raise RuntimeError("FAIL_CLOSED: routing delta matrix must be ACTIVE")


def _cooperation_index(packet: Dict[str, Any]) -> Dict[str, List[str]]:
    rows = packet.get("rows")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: lobe cooperation rows missing")
    index: Dict[str, List[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("relationship", "")).strip() != "required_guard":
            continue
        primary = str(row.get("primary_lobe", "")).strip()
        if not primary:
            continue
        guards = _ordered_unique(row.get("paired_with", []))
        if guards:
            index[primary] = guards
    return index


def _domain_index(packet: Dict[str, Any]) -> Dict[str, List[str]]:
    rows = packet.get("rows")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: routing delta rows missing")
    index: Dict[str, List[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        domain_tag = str(row.get("expected_domain_tag", "")).strip()
        adapter_ids = _ordered_unique(row.get("expected_adapter_ids", []))
        if not domain_tag:
            continue
        for adapter_id in adapter_ids:
            index.setdefault(adapter_id, [])
            if domain_tag not in index[adapter_id]:
                index[adapter_id].append(domain_tag)
    return index


def _candidate_overlap_flags(*, lobe_id: str, role: str) -> List[str]:
    flags: List[str] = []
    if role == "default_generalist":
        flags.append("GENERALIST_OVERLAP_RISK")
    if role == "quantitative_reasoning":
        flags.append("MATH_OVERLAP_RISK")
    if role == "creative_generation":
        flags.append("WRITER_OVERLAP_RISK")
    if lobe_id == "lobe.censor.v1":
        flags.append("GUARD_ONLY_NOT_TERMINAL")
    return flags


def _candidate_score(*, role: str, required_guards: Sequence[str]) -> int:
    score = 0
    if role == "governance_audit":
        score += 30
    elif role == "creative_generation":
        score += 16
    elif role == "quantitative_reasoning":
        score += 8
    elif role == "default_generalist":
        score -= 20
    else:
        score += 2
    if required_guards:
        score += 6
    return score


def build_post_fourth_rerun_fifth_terminal_candidate_packet(
    *,
    current_state_overlay: Dict[str, Any],
    material_change_target_packet: Dict[str, Any],
    lobe_role_registry: Dict[str, Any],
    lobe_cooperation_matrix: Dict[str, Any],
    routing_delta_matrix: Dict[str, Any],
    current_state_overlay_ref: str,
    material_change_target_packet_ref: str,
    lobe_role_registry_ref: str,
    lobe_cooperation_matrix_ref: str,
    routing_delta_matrix_ref: str,
) -> Dict[str, Any]:
    _validate_current_state_overlay(current_state_overlay)
    _validate_material_change_target(material_change_target_packet)
    _validate_lobe_role_registry(lobe_role_registry)
    _validate_lobe_cooperation_matrix(lobe_cooperation_matrix)
    _validate_routing_delta_matrix(routing_delta_matrix)

    frozen_summary = material_change_target_packet.get("current_router_hold_summary")
    if not isinstance(frozen_summary, dict):
        raise RuntimeError("FAIL_CLOSED: frozen router hold summary missing")
    frozen_terminals = _ordered_unique(frozen_summary.get("frozen_terminal_adapters", []))
    if len(frozen_terminals) != 4:
        raise RuntimeError("FAIL_CLOSED: expected preserved four-terminal hold summary")

    cooperation_by_lobe = _cooperation_index(lobe_cooperation_matrix)
    domain_by_lobe = _domain_index(routing_delta_matrix)

    entries = lobe_role_registry.get("entries")
    if not isinstance(entries, list):
        raise RuntimeError("FAIL_CLOSED: lobe role registry entries missing")

    viable_candidates: List[Dict[str, Any]] = []
    blocked_candidates: List[Dict[str, Any]] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        lobe_id = str(entry.get("lobe_id", "")).strip()
        role = str(entry.get("role", "")).strip()
        status = str(entry.get("status", "")).strip()
        if not lobe_id:
            continue

        required_guards = cooperation_by_lobe.get(lobe_id, [])
        domain_tags = domain_by_lobe.get(lobe_id, [])
        overlap_flags = _candidate_overlap_flags(lobe_id=lobe_id, role=role)

        blocker = ""
        reasons: List[str] = []
        recommended_route_pattern = ""
        recommended_suite_ref = ""

        if lobe_id in frozen_terminals:
            blocker = "ALREADY_IN_FROZEN_FOUR_TERMINAL_SET"
        elif lobe_id == "lobe.censor.v1":
            blocker = "REQUIRED_GUARD_NOT_TERMINAL_CANDIDATE"
        elif role == "default_generalist":
            blocker = "DEFAULT_GENERALIST_OVERLAP__NOT_NEW_TERMINAL_BREADTH"

        if status == "RATIFIED_ROUTER_BASELINE":
            reasons.append("ratified_router_baseline")
        elif status == "RATIFIED_REQUIRED_GUARD":
            reasons.append("ratified_required_guard")
        if role:
            reasons.append(f"role::{role}")
        if required_guards:
            reasons.append("required_guard_semantics_already_defined")
        if domain_tags:
            reasons.append("routing_domain_evidence_present")

        if lobe_id == "lobe.auditor.v1":
            recommended_route_pattern = "lobe.censor.v1 -> lobe.auditor.v1"
            recommended_suite_ref = _AUDIT_TERMINAL_SUITE_REF
            reasons.append("lowest_overlap_with_current_four_terminal_set")
        elif lobe_id == "lobe.muse.v1":
            reasons.append("creative_terminal_possible_but_writer_overlap_risk")
        elif lobe_id == "lobe.quant.v1":
            reasons.append("quant_terminal_possible_but_math_overlap_risk")
        elif lobe_id == "lobe.strategist.v1":
            reasons.append("generalist_overlap_prevents_new_terminal_breadth")

        candidate = {
            "adapter_id": lobe_id,
            "role": role,
            "status": status,
            "domain_tags": domain_tags,
            "required_guard_ids": required_guards,
            "overlap_flags": overlap_flags,
            "recommended_route_pattern": recommended_route_pattern,
            "recommended_suite_ref": recommended_suite_ref,
            "selection_reasons": reasons,
        }

        if blocker:
            candidate["blocker"] = blocker
            blocked_candidates.append(candidate)
            continue

        candidate["score"] = _candidate_score(role=role, required_guards=required_guards)
        viable_candidates.append(candidate)

    viable_candidates.sort(key=lambda item: (-int(item["score"]), item["adapter_id"]))
    blocked_candidates.sort(key=lambda item: item["adapter_id"])

    if not viable_candidates:
        raise RuntimeError("FAIL_CLOSED: no viable fifth-terminal candidate remains after exclusions")

    primary_candidate = dict(viable_candidates[0])
    secondary_candidates = viable_candidates[1:]

    if primary_candidate["adapter_id"] != "lobe.auditor.v1":
        raise RuntimeError("FAIL_CLOSED: expected auditor to remain the strongest distinct fifth-terminal candidate")

    candidate_sentence = (
        "On a new lab head, try to earn a fifth terminal through `lobe.censor.v1 -> lobe.auditor.v1`, "
        "making `lobe.auditor.v1` the downstream terminal while preserving the current four-terminal paths and "
        "the already-ratified guard semantics for governance routing."
    )

    return {
        "schema_id": "kt.post_fourth_rerun_fifth_terminal_candidate_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It does not reopen the counted lane, does not count as R5 evidence, "
            "does not earn router superiority, and cannot unlock R6. Its only job is to choose the strongest concrete "
            "fifth-terminal candidate from the currently ratified router inventory so the next lab cycle has a bounded target."
        ),
        "branch_posture": "ROUTER_BRANCH_ACTIVE__FIFTH_TERMINAL_CANDIDATE_SELECTED",
        "questions": {
            "counted_lane_closed_now": True,
            "static_baseline_still_canonical": True,
            "router_branch_selected": True,
            "requires_new_lab_head": True,
            "requires_new_terminal_beyond_current_four": True,
            "primary_candidate_selected": True,
            "primary_candidate_has_distinct_terminal_breadth": primary_candidate["adapter_id"] not in frozen_terminals,
            "primary_candidate_preserves_existing_guard_semantics": bool(primary_candidate["required_guard_ids"]),
            "primary_candidate_is_not_generalist_overlap": "GENERALIST_OVERLAP_RISK" not in primary_candidate["overlap_flags"],
        },
        "frozen_four_terminal_summary": {
            "frozen_terminal_adapters": frozen_terminals,
            "frozen_terminal_adapter_count": len(frozen_terminals),
            "frozen_four_terminal_lab_head": str(frozen_summary.get("frozen_four_terminal_lab_head", "")).strip(),
        },
        "candidate_selection_sentence": candidate_sentence,
        "primary_candidate": primary_candidate,
        "secondary_candidates": secondary_candidates,
        "blocked_candidates": blocked_candidates,
        "primary_candidate_requirements": [
            "Use a genuinely new lab head rather than reusing the preserved four-terminal head.",
            "Keep `lobe.auditor.v1` as the downstream terminal instead of collapsing back into the current four-terminal set.",
            "Preserve the required `lobe.censor.v1` guard semantics already defined for governance routing.",
            "Keep rerun, fresh-entrant, shadow, and tournament-like constraints green on the new head.",
            "Preserve the current four-terminal paths while adding the fifth terminal path.",
        ],
        "non_success_conditions": [
            "The new path collapses back into `lobe.code.specialist.v1`, `lobe.writer.specialist.v1`, `lobe.math.specialist.v1`, or `lobe.research.specialist.v1` as the downstream terminal.",
            "The path drops the required `lobe.censor.v1` guard semantics for governance routing.",
            "The candidate survives only as route-pair novelty without durable downstream terminal breadth.",
            "The candidate fails rerun, fresh-entrant, shadow, or tournament-like constraints on the new head.",
        ],
        "source_packet_refs": {
            "current_state_overlay_ref": current_state_overlay_ref,
            "material_change_target_packet_ref": material_change_target_packet_ref,
            "lobe_role_registry_ref": lobe_role_registry_ref,
            "lobe_cooperation_matrix_ref": lobe_cooperation_matrix_ref,
            "routing_delta_matrix_ref": routing_delta_matrix_ref,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select the strongest concrete fifth-terminal router lab candidate after the fourth counted static hold."
    )
    parser.add_argument("--current-state-overlay", required=True)
    parser.add_argument("--material-change-target-packet", required=True)
    parser.add_argument("--lobe-role-registry", required=True)
    parser.add_argument("--lobe-cooperation-matrix", required=True)
    parser.add_argument("--routing-delta-matrix", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    current_state_overlay_ref = str(args.current_state_overlay)
    material_change_target_packet_ref = str(args.material_change_target_packet)
    lobe_role_registry_ref = str(args.lobe_role_registry)
    lobe_cooperation_matrix_ref = str(args.lobe_cooperation_matrix)
    routing_delta_matrix_ref = str(args.routing_delta_matrix)

    packet = build_post_fourth_rerun_fifth_terminal_candidate_packet(
        current_state_overlay=_load_json_dict(_resolve(root, current_state_overlay_ref), name="current_state_overlay"),
        material_change_target_packet=_load_json_dict(
            _resolve(root, material_change_target_packet_ref),
            name="material_change_target_packet",
        ),
        lobe_role_registry=_load_json_dict(_resolve(root, lobe_role_registry_ref), name="lobe_role_registry"),
        lobe_cooperation_matrix=_load_json_dict(
            _resolve(root, lobe_cooperation_matrix_ref),
            name="lobe_cooperation_matrix",
        ),
        routing_delta_matrix=_load_json_dict(_resolve(root, routing_delta_matrix_ref), name="routing_delta_matrix"),
        current_state_overlay_ref=current_state_overlay_ref,
        material_change_target_packet_ref=material_change_target_packet_ref,
        lobe_role_registry_ref=lobe_role_registry_ref,
        lobe_cooperation_matrix_ref=lobe_cooperation_matrix_ref,
        routing_delta_matrix_ref=routing_delta_matrix_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["primary_candidate"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
