from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R5_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_vs_best_adapter_proof_receipt.json"
DEFAULT_ORDERED_PROOF_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_ordered_proof_receipt.json"
DEFAULT_HEALTH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_route_distribution_health.json"
DEFAULT_SELECTION_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_selection_receipt.json"
DEFAULT_SHADOW_MATRIX_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_shadow_eval_matrix.json"
DEFAULT_STAGE_PACK_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_ALPHA_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/alpha_should_lose_here_manifest.json"
DEFAULT_ORACLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_scorecard.json"
DEFAULT_FOLLOWTHROUGH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_shadow_followthrough_packet.json"

VERDICT_POSTURE = "RESIDUAL_ALPHA_DOMINANCE_PACKET_EMITTED__R5_CEILING_STILL_ACTIVE"
NEXT_MOVE = "AUTHOR_SINGLE_AXIS_CRUCIBLE_INPUTS_AND_EXECUTE_LAB_ONLY_SWEEPS"

STATUS_STATIC_HOLD = "RIGHTFUL_STATIC_HOLD__CONTROL_FAMILY"
STATUS_ABSTAIN = "FAIL_CLOSED_DE_RISKING_SIGNAL__NOT_DIRECT_SUPERIORITY"
STATUS_MIXED = "MIXED_SPECIALIST_AND_FAIL_CLOSED_SIGNAL__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY"
STATUS_SPECIALIST = "SPECIALIST_ROUTE_SIGNAL_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY"
STATUS_PARTIAL = "PARTIAL_SPECIALIST_SIGNAL__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY"
STATUS_NO_SIGNAL = "NO_SPECIALIST_SIGNAL_PRESENT"

PRESSURE_HINTS: Dict[str, Tuple[str, str]] = {
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": ("adversarial_ambiguity", "governed_execution_burden"),
    "BETA_SECOND_ORDER_REFRAME": ("ambiguity_boundary", "second_order_reframing"),
    "BOUNDARY_ABSTENTION_CONTROL": ("abstention_calibration", "overclaim_guard"),
    "CHILD_ANOMALY_PRESERVATION": ("cross_domain_overlay", "anomaly_preservation"),
    "P2_SIGNAL_NOISE_SEPARATION": ("signal_noise_density", "decoy_constraint_pressure"),
    "SCOUT_SPARSE_SEARCH": ("sparse_search_branching", "candidate_exploration"),
    "STATIC_NO_ROUTE_CONTROL": ("hold_constant", "no_regression_guard"),
    "STRATEGIST_CONSEQUENCE_CHAIN": ("causal_branching", "step_order_pressure"),
}


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip() if ref_field else ""
    authoritative_path = _resolve(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    subject_heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet requires one consistent subject head")
    return next(iter(subject_heads))


def _validate_inputs(
    *,
    r5_receipt: Dict[str, Any],
    ordered_receipt: Dict[str, Any],
    health_report: Dict[str, Any],
    selection_receipt: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
    stage_pack_manifest: Dict[str, Any],
    alpha_manifest: Dict[str, Any],
    oracle_scorecard: Dict[str, Any],
    followthrough_packet: Dict[str, Any],
) -> None:
    if str(r5_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed R5 receipt must PASS")
    if str(r5_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_RESIDUAL_ALPHA_DOMINANCE_PACKET":
        raise RuntimeError("FAIL_CLOSED: recomposed R5 receipt must require residual alpha dominance packet")
    if bool(r5_receipt.get("router_proof_summary", {}).get("material_advance_detected")) is not True:
        raise RuntimeError("FAIL_CLOSED: recomposed R5 receipt must show material advance")
    if bool(r5_receipt.get("router_proof_summary", {}).get("router_superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet only applies before superiority is earned")
    if str(ordered_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed ordered proof receipt must PASS")
    if bool(ordered_receipt.get("material_advance_detected")) is not True:
        raise RuntimeError("FAIL_CLOSED: recomposed ordered proof receipt must show material advance")
    if str(health_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed route distribution health must PASS")
    if int(health_report.get("route_distribution_delta_count", 0)) <= 0:
        raise RuntimeError("FAIL_CLOSED: recomposed route distribution health must keep nonzero route deltas")
    if bool(health_report.get("exact_path_universality_broken")) is not True:
        raise RuntimeError("FAIL_CLOSED: recomposed route distribution health must keep exact-path universality broken")
    if str(selection_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router selection receipt must PASS")
    if not isinstance(selection_receipt.get("case_rows"), list) or not selection_receipt.get("case_rows"):
        raise RuntimeError("FAIL_CLOSED: recomposed router selection receipt case_rows missing/invalid")
    if str(shadow_matrix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow eval matrix must PASS")
    if not isinstance(shadow_matrix.get("rows"), list) or not shadow_matrix.get("rows"):
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow eval matrix rows missing/invalid")
    if str(stage_pack_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing stage pack manifest must PASS")
    if str(alpha_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha-should-lose manifest must PASS")
    if str(oracle_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle router local scorecard must PASS")
    if str(followthrough_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow followthrough packet must PASS")


def _index_manifest_rows(rows: Sequence[Dict[str, Any]], *, key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: manifest row must be object")
        row_key = str(row.get(key, "")).strip()
        if not row_key:
            raise RuntimeError(f"FAIL_CLOSED: manifest row missing {key}")
        out[row_key] = row
    return out


def _family_status(*, family_id: str, family_category: str, route_count: int, abstain_count: int, exact_match_count: int) -> str:
    if family_id == "STATIC_NO_ROUTE_CONTROL" or family_category == "STATIC_CONTROL":
        return STATUS_STATIC_HOLD
    if family_category == "ABSTENTION_CONTROL" and route_count == 0 and abstain_count > 0:
        return STATUS_ABSTAIN
    if route_count > 0 and abstain_count > 0:
        return STATUS_MIXED
    if route_count > 0 and exact_match_count == 0:
        return STATUS_SPECIALIST
    if route_count > 0:
        return STATUS_PARTIAL
    return STATUS_NO_SIGNAL


def _family_explanation(*, status: str, family_row: Dict[str, Any], route_count: int) -> str:
    family_id = str(family_row.get("family_id", "")).strip()
    target_lobe_id = str(family_row.get("target_lobe_id", "")).strip()
    alpha_liability = str(family_row.get("alpha_liability", "")).strip()
    if status == STATUS_STATIC_HOLD:
        return "Static control family still holds on alpha as intended; this is a guardrail, not a residual defect."
    if status == STATUS_ABSTAIN:
        return "Lawful abstention is still the right de-risking move here; this family is proving fail-closed discipline rather than specialist supremacy."
    if status == STATUS_MIXED:
        return (
            f"{family_id} now shows both specialist routing and fail-closed abstention against alpha. "
            f"That is real signal for {target_lobe_id or 'the admissible path'}, but it still has not converted into branch-level superiority."
        )
    if status == STATUS_SPECIALIST:
        return f"{family_id} routes cleanly away from alpha on {route_count} cases because the preregistered liability remains live: {alpha_liability}"
    if status == STATUS_PARTIAL:
        return f"{family_id} shows partial specialist route signal for {target_lobe_id or 'the nominated lobe'}, but some static overlap remains and superiority is still not earned."
    return f"{family_id} is not yet producing enough route-bearing signal to justify a stronger counted claim."


def _next_focus(*, status: str, family_row: Dict[str, Any]) -> str:
    family_id = str(family_row.get("family_id", "")).strip()
    if status == STATUS_STATIC_HOLD:
        return f"{family_id}__HOLD_CONSTANT_AND_USE_AS_NO_REGRESSION_CONTROL"
    if status == STATUS_ABSTAIN:
        return f"{family_id}__SHARPEN_ABSTENTION_CALIBRATION_AND_HANDOFF_DISCIPLINE"
    return f"{family_id}__SHARPEN_ROUTE_VALUE_UNTIL_ALPHA_CANONICAL_HOLD_BREAKS_ON_FENCED_TASKS"


def _pressure_axes(family_id: str) -> Tuple[str, str]:
    return PRESSURE_HINTS.get(family_id, ("cross_domain_overlay", "adversarial_ambiguity"))


def _family_rows(
    *,
    manifest_rows: Sequence[Dict[str, Any]],
    alpha_rows: Dict[str, Dict[str, Any]],
    shadow_rows: Sequence[Dict[str, Any]],
    selection_rows: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    shadow_by_family: Dict[str, List[Dict[str, Any]]] = {}
    for row in shadow_rows:
        family_id = str(row.get("family_id", "")).strip()
        shadow_by_family.setdefault(family_id, []).append(row)
    selection_by_family: Dict[str, List[Dict[str, Any]]] = {}
    for row in selection_rows:
        family_id = str(row.get("family_id", "")).strip()
        selection_by_family.setdefault(family_id, []).append(row)

    out: List[Dict[str, Any]] = []
    for manifest_row in manifest_rows:
        family_id = str(manifest_row.get("family_id", "")).strip()
        family_category = str(manifest_row.get("family_category", "")).strip()
        shadow_family_rows = shadow_by_family.get(family_id, [])
        selection_family_rows = selection_by_family.get(family_id, [])
        route_count = sum(1 for row in shadow_family_rows if str(row.get("shadow_policy_outcome", "")).strip() == "ROUTE_TO_SPECIALIST")
        abstain_count = sum(1 for row in shadow_family_rows if str(row.get("shadow_policy_outcome", "")).strip() == "ABSTAIN_FOR_REVIEW")
        stay_static_count = sum(1 for row in shadow_family_rows if str(row.get("shadow_policy_outcome", "")).strip() == "STAY_STATIC_BASELINE")
        exact_match_count = sum(1 for row in shadow_family_rows if bool(row.get("exact_path_match")))
        divergence_count = sum(1 for row in shadow_family_rows if bool(row.get("divergence_from_static")))
        route_targets = sorted(
            {
                str(adapter_id).strip()
                for row in selection_family_rows
                for adapter_id in row.get("selected_adapter_ids", [])
                if str(adapter_id).strip()
            }
        )
        alpha_row = alpha_rows.get(family_id, {})
        status = _family_status(
            family_id=family_id,
            family_category=family_category,
            route_count=route_count,
            abstain_count=abstain_count,
            exact_match_count=exact_match_count,
        )
        primary_axis, secondary_axis = _pressure_axes(family_id)
        out.append(
            {
                "family_id": family_id,
                "family_category": family_category,
                "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
                "case_count": int(manifest_row.get("case_count", len(shadow_family_rows))),
                "visible_case_count": int(manifest_row.get("visible_case_count", 0)),
                "held_out_case_count": int(manifest_row.get("held_out_case_count", 0)),
                "route_case_count": route_count,
                "abstain_case_count": abstain_count,
                "stay_static_case_count": stay_static_count,
                "exact_path_match_count": exact_match_count,
                "divergence_count": divergence_count,
                "route_target_ids": route_targets,
                "alpha_liability": str(manifest_row.get("alpha_liability", "")).strip(),
                "alpha_should_lose_here_because": str(alpha_row.get("alpha_should_lose_here_because", "")).strip(),
                "acceptance_metric": str(manifest_row.get("acceptance_metric", "")).strip(),
                "residual_status": status,
                "residual_explanation": _family_explanation(status=status, family_row=manifest_row, route_count=route_count),
                "next_focus": _next_focus(status=status, family_row=manifest_row),
                "single_axis_pressure_primary": primary_axis,
                "single_axis_pressure_secondary": secondary_axis,
            }
        )
    return out


def _build_wedge_spec(
    *,
    subject_head: str,
    current_head: str,
    family_rows: Sequence[Dict[str, Any]],
    route_policy_outcomes: Sequence[str],
) -> Dict[str, Any]:
    spec_rows: List[Dict[str, Any]] = []
    for row in family_rows:
        status = str(row.get("residual_status", "")).strip()
        family_id = str(row.get("family_id", "")).strip()
        if status == STATUS_STATIC_HOLD:
            success_condition = "Static alpha remains stable with no regression under recomposed replay."
            failure_condition = "Any forced routing or abstention appears on this no-route control family."
        elif status == STATUS_ABSTAIN:
            success_condition = "Abstention remains correctly triggered with lower overclaim risk and explicit review handoff."
            failure_condition = "Forced routing or forced commitment displaces lawful abstention."
        else:
            success_condition = "Specialist route value strengthens enough to improve fenced-family proof beyond the current recomposed R5 ceiling."
            failure_condition = "Family stays route-bearing in shadow only but still fails to move superiority-relevant proof objects."
        spec_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(row.get("target_lobe_id", "")).strip(),
                "residual_status": status,
                "alpha_liability": str(row.get("alpha_liability", "")).strip(),
                "alpha_should_lose_here_because": str(row.get("alpha_should_lose_here_because", "")).strip(),
                "preserved_policy_outcomes": list(route_policy_outcomes),
                "primary_pressure_axis": str(row.get("single_axis_pressure_primary", "")).strip(),
                "secondary_pressure_axis": str(row.get("single_axis_pressure_secondary", "")).strip(),
                "next_focus": str(row.get("next_focus", "")).strip(),
                "new_admissible_eval_family": f"{family_id}__RESIDUAL_ALPHA_DOMINANCE",
                "success_condition": success_condition,
                "failure_condition": failure_condition,
                "held_out_preservation_rule": "Held-out mutation rows remain grading-only and cannot be consumed during authoring.",
            }
        )
    return {
        "schema_id": "kt.operator.cohort0_residual_alpha_dominance_wedge_spec.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This wedge spec narrows only the next lab-side alpha-dominance recovery pass. "
            "It does not reopen the counted lane or authorize learned routing."
        ),
        "route_policy_outcomes_preserved": list(route_policy_outcomes),
        "rows": spec_rows,
    }


def _build_packet(
    *,
    subject_head: str,
    current_head: str,
    r5_receipt_path: Path,
    ordered_receipt_path: Path,
    health_path: Path,
    selection_path: Path,
    shadow_path: Path,
    stage_pack_manifest_path: Path,
    alpha_manifest_path: Path,
    oracle_scorecard_path: Path,
    followthrough_path: Path,
    wedge_spec_path: Path,
    ordered_receipt: Dict[str, Any],
    health_report: Dict[str, Any],
    family_rows: Sequence[Dict[str, Any]],
    followthrough_packet: Dict[str, Any],
) -> Dict[str, Any]:
    static_hold_families = [row["family_id"] for row in family_rows if row["residual_status"] == STATUS_STATIC_HOLD]
    abstain_families = [row["family_id"] for row in family_rows if row["residual_status"] == STATUS_ABSTAIN]
    specialist_signal_families = [
        row["family_id"]
        for row in family_rows
        if row["residual_status"] in {STATUS_SPECIALIST, STATUS_MIXED, STATUS_PARTIAL}
    ]
    champion_id = str(followthrough_packet.get("promotion_followthrough", {}).get("candidate_adapter_id", "")).strip() or "lobe.alpha.v1"
    return {
        "schema_id": "kt.operator.cohort0_residual_alpha_dominance_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "verdict_posture": VERDICT_POSTURE,
        "claim_boundary": (
            "This packet explains only why alpha still retains canonical static authority after recomposed R5 materially advanced. "
            "It does not claim router superiority, learned-router authorization, or Gate E/F opening."
        ),
        "source_refs": {
            "recomposed_r5_receipt_ref": r5_receipt_path.as_posix(),
            "recomposed_ordered_proof_receipt_ref": ordered_receipt_path.as_posix(),
            "recomposed_route_distribution_health_ref": health_path.as_posix(),
            "recomposed_router_selection_receipt_ref": selection_path.as_posix(),
            "recomposed_router_shadow_eval_matrix_ref": shadow_path.as_posix(),
            "route_bearing_stage_pack_manifest_ref": stage_pack_manifest_path.as_posix(),
            "alpha_should_lose_here_manifest_ref": alpha_manifest_path.as_posix(),
            "oracle_router_local_scorecard_ref": oracle_scorecard_path.as_posix(),
            "recomposed_router_shadow_followthrough_packet_ref": followthrough_path.as_posix(),
        },
        "emitted_surfaces": {
            "residual_alpha_dominance_wedge_spec_ref": wedge_spec_path.as_posix(),
        },
        "current_ceiling_summary": {
            "best_static_adapter_id": "lobe.alpha.v1",
            "current_tournament_champion_adapter_id": champion_id,
            "router_superiority_earned": False,
            "material_advance_detected": True,
            "ordered_proof_outcome": str(ordered_receipt.get("ordered_proof_outcome", "")).strip(),
            "exact_superiority_outcome": str(ordered_receipt.get("exact_superiority_outcome", "")).strip(),
            "learned_router_candidate_status": str(ordered_receipt.get("learned_router_candidate_status", "")).strip(),
        },
        "proof_object_movement": dict(ordered_receipt.get("proof_object_deltas", {})),
        "residual_alpha_dominance_summary": {
            "route_distribution_delta_count": int(health_report.get("route_distribution_delta_count", 0)),
            "exact_path_universality_broken": bool(health_report.get("exact_path_universality_broken")),
            "shadow_match_rate": float(health_report.get("shadow_match_rate", 0.0)),
            "unique_route_target_count": len(health_report.get("unique_route_targets", [])),
            "static_hold_families": static_hold_families,
            "abstention_control_families": abstain_families,
            "specialist_signal_families": specialist_signal_families,
        },
        "residual_blockers": [
            {
                "blocker_id": "STATIC_ALPHA_REMAINS_CANONICAL_COMPARATOR",
                "evidence": "best_static_adapter_id=lobe.alpha.v1 | router_superiority_earned=false",
                "why_it_matters": "Route-bearing movement exists, but alpha still retains branch-level canonical authority.",
            },
            {
                "blocker_id": "SPECIALIST_SIGNAL_HAS_NOT_YET_CONVERTED_INTO_SUPERIORITY",
                "evidence": f"specialist_signal_family_count={len(specialist_signal_families)} | route_distribution_delta_count={int(health_report.get('route_distribution_delta_count', 0))}",
                "why_it_matters": "The branch has real differentiation now, but it still needs fenced-family proof strong enough to break alpha's remaining hold.",
            },
            {
                "blocker_id": "LEARNED_ROUTER_AUTHORIZATION_STILL_BLOCKED",
                "evidence": str(ordered_receipt.get("learned_router_candidate_status", "")).strip(),
                "why_it_matters": "Counted-lane advancement still depends on stronger bounded evidence before any learned-router move is lawful.",
            },
        ],
        "family_rows": list(family_rows),
        "next_lawful_move": NEXT_MOVE,
    }


def run_residual_alpha_dominance_packet_tranche(
    *,
    r5_receipt_path: Path,
    ordered_receipt_path: Path,
    health_report_path: Path,
    selection_receipt_path: Path,
    shadow_matrix_path: Path,
    stage_pack_manifest_path: Path,
    alpha_manifest_path: Path,
    oracle_scorecard_path: Path,
    followthrough_packet_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_r5_receipt_path, r5_receipt = _resolve_authoritative(
        root, r5_receipt_path.resolve(), "authoritative_recomposed_router_vs_best_adapter_proof_receipt_ref", "recomposed R5 receipt"
    )
    authoritative_ordered_receipt_path, ordered_receipt = _resolve_authoritative(
        root, ordered_receipt_path.resolve(), "authoritative_recomposed_router_ordered_proof_receipt_ref", "recomposed ordered proof receipt"
    )
    authoritative_health_path, health_report = _resolve_authoritative(
        root, health_report_path.resolve(), "authoritative_recomposed_route_distribution_health_ref", "recomposed route health"
    )
    authoritative_selection_path, selection_receipt = _resolve_authoritative(
        root, selection_receipt_path.resolve(), "authoritative_recomposed_router_selection_receipt_ref", "recomposed selection receipt"
    )
    authoritative_shadow_path, shadow_matrix = _resolve_authoritative(
        root, shadow_matrix_path.resolve(), "authoritative_recomposed_router_shadow_eval_matrix_ref", "recomposed shadow matrix"
    )
    authoritative_stage_pack_manifest_path, stage_pack_manifest = _resolve_authoritative(
        root, stage_pack_manifest_path.resolve(), "authoritative_route_bearing_stage_pack_manifest_ref", "route-bearing stage pack manifest"
    )
    authoritative_alpha_manifest_path, alpha_manifest = _resolve_authoritative(
        root, alpha_manifest_path.resolve(), "authoritative_alpha_should_lose_here_manifest_ref", "alpha-should-lose manifest"
    )
    authoritative_oracle_scorecard_path, oracle_scorecard = _resolve_authoritative(
        root, oracle_scorecard_path.resolve(), "authoritative_oracle_router_local_scorecard_ref", "oracle router local scorecard"
    )
    authoritative_followthrough_path, followthrough_packet = _resolve_authoritative(
        root, followthrough_packet_path.resolve(), "authoritative_recomposed_router_shadow_followthrough_packet_ref", "recomposed router shadow followthrough packet"
    )

    _validate_inputs(
        r5_receipt=r5_receipt,
        ordered_receipt=ordered_receipt,
        health_report=health_report,
        selection_receipt=selection_receipt,
        shadow_matrix=shadow_matrix,
        stage_pack_manifest=stage_pack_manifest,
        alpha_manifest=alpha_manifest,
        oracle_scorecard=oracle_scorecard,
        followthrough_packet=followthrough_packet,
    )

    subject_head = _resolve_subject_head(
        packets=[
            r5_receipt,
            ordered_receipt,
            health_report,
            selection_receipt,
            shadow_matrix,
            stage_pack_manifest,
            alpha_manifest,
            oracle_scorecard,
            followthrough_packet,
        ]
    )

    manifest_rows = stage_pack_manifest.get("family_rows", [])
    alpha_rows = _index_manifest_rows(alpha_manifest.get("rows", []), key="family_id")
    family_rows = _family_rows(
        manifest_rows=manifest_rows,
        alpha_rows=alpha_rows,
        shadow_rows=shadow_matrix.get("rows", []),
        selection_rows=selection_receipt.get("case_rows", []),
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_residual_alpha_dominance_packet").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    wedge_spec_path = (target_root / "cohort0_residual_alpha_dominance_wedge_spec.json").resolve()
    packet_path = (target_root / "cohort0_residual_alpha_dominance_packet.json").resolve()

    wedge_spec = _build_wedge_spec(
        subject_head=subject_head,
        current_head=current_head,
        family_rows=family_rows,
        route_policy_outcomes=["ROUTE_TO_SPECIALIST", "STAY_STATIC_BASELINE", "ABSTAIN_FOR_REVIEW"],
    )
    write_json_stable(wedge_spec_path, wedge_spec)

    packet = _build_packet(
        subject_head=subject_head,
        current_head=current_head,
        r5_receipt_path=authoritative_r5_receipt_path,
        ordered_receipt_path=authoritative_ordered_receipt_path,
        health_path=authoritative_health_path,
        selection_path=authoritative_selection_path,
        shadow_path=authoritative_shadow_path,
        stage_pack_manifest_path=authoritative_stage_pack_manifest_path,
        alpha_manifest_path=authoritative_alpha_manifest_path,
        oracle_scorecard_path=authoritative_oracle_scorecard_path,
        followthrough_path=authoritative_followthrough_path,
        wedge_spec_path=wedge_spec_path,
        ordered_receipt=ordered_receipt,
        health_report=health_report,
        family_rows=family_rows,
        followthrough_packet=followthrough_packet,
    )
    write_json_stable(packet_path, packet)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_packet = dict(packet)
    tracked_packet["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_DOMINANCE_PACKET"
    tracked_packet["authoritative_cohort0_residual_alpha_dominance_packet_ref"] = packet_path.as_posix()
    write_json_stable((reports_root / "cohort0_residual_alpha_dominance_packet.json").resolve(), tracked_packet)

    tracked_wedge_spec = dict(wedge_spec)
    tracked_wedge_spec["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_DOMINANCE_WEDGE_SPEC"
    tracked_wedge_spec["authoritative_cohort0_residual_alpha_dominance_wedge_spec_ref"] = wedge_spec_path.as_posix()
    write_json_stable((reports_root / "cohort0_residual_alpha_dominance_wedge_spec.json").resolve(), tracked_wedge_spec)

    return {
        "cohort0_residual_alpha_dominance_wedge_spec": wedge_spec,
        "cohort0_residual_alpha_dominance_packet": packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Emit the residual alpha dominance packet after recomposed R5 materially advances without earning superiority.")
    ap.add_argument("--r5-receipt", default=DEFAULT_R5_RECEIPT_REL)
    ap.add_argument("--ordered-receipt", default=DEFAULT_ORDERED_PROOF_REL)
    ap.add_argument("--health-report", default=DEFAULT_HEALTH_REL)
    ap.add_argument("--selection-receipt", default=DEFAULT_SELECTION_REL)
    ap.add_argument("--shadow-matrix", default=DEFAULT_SHADOW_MATRIX_REL)
    ap.add_argument("--stage-pack-manifest", default=DEFAULT_STAGE_PACK_MANIFEST_REL)
    ap.add_argument("--alpha-manifest", default=DEFAULT_ALPHA_MANIFEST_REL)
    ap.add_argument("--oracle-scorecard", default=DEFAULT_ORACLE_SCORECARD_REL)
    ap.add_argument("--followthrough-packet", default=DEFAULT_FOLLOWTHROUGH_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_residual_alpha_dominance_packet_tranche(
        r5_receipt_path=_resolve(root, str(args.r5_receipt)),
        ordered_receipt_path=_resolve(root, str(args.ordered_receipt)),
        health_report_path=_resolve(root, str(args.health_report)),
        selection_receipt_path=_resolve(root, str(args.selection_receipt)),
        shadow_matrix_path=_resolve(root, str(args.shadow_matrix)),
        stage_pack_manifest_path=_resolve(root, str(args.stage_pack_manifest)),
        alpha_manifest_path=_resolve(root, str(args.alpha_manifest)),
        oracle_scorecard_path=_resolve(root, str(args.oracle_scorecard)),
        followthrough_packet_path=_resolve(root, str(args.followthrough_packet)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    packet = payload["cohort0_residual_alpha_dominance_packet"]
    print(
        json.dumps(
            {
                "status": packet["status"],
                "verdict_posture": packet["verdict_posture"],
                "family_count": len(packet["family_rows"]),
                "next_lawful_move": packet["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
