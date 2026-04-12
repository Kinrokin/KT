from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_RESIDUAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_packet.json"
DEFAULT_RESIDUAL_WEDGE_SPEC_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_wedge_spec.json"
DEFAULT_R5_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_vs_best_adapter_proof_receipt.json"
DEFAULT_ORDERED_PROOF_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_ordered_proof_receipt.json"
DEFAULT_HEALTH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_route_distribution_health.json"
DEFAULT_CRUCIBLE_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_crucible_escalation_packet.json"
DEFAULT_ALPHA_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/alpha_should_lose_here_manifest.json"
DEFAULT_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/route_policy_outcome_registry.json"
DEFAULT_ORACLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_scorecard.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"

DEFAULT_REPORTS = {
    "counted_lane_verdict_grammar": "counted_lane_verdict_grammar.json",
    "pre_mortem_failure_map": "pre_mortem_failure_map.json",
    "governance_roi_scorecard": "governance_roi_scorecard.json",
    "alpha_liability_registry": "alpha_liability_registry.json",
    "lab_to_counted_transfer_guard": "lab_to_counted_transfer_guard.json",
    "externalization_readiness_packet": "externalization_readiness_packet.json",
    "receipt": "cohort0_counted_lane_hardening_receipt.json",
}

NEXT_MOVE = "AUTHOR_SINGLE_AXIS_CRUCIBLE_INPUTS_AND_EXECUTE_LAB_ONLY_SWEEPS"
VERDICT_POSTURE = "COUNTED_LANE_HARDENING_BOUND__COUNTED_CEILING_UNCHANGED"


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
        raise RuntimeError("FAIL_CLOSED: counted-lane hardening could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: counted-lane hardening requires one consistent subject head")
    return next(iter(subject_heads))


def _validate_inputs(
    *,
    residual_packet: Dict[str, Any],
    residual_wedge_spec: Dict[str, Any],
    r5_receipt: Dict[str, Any],
    ordered_receipt: Dict[str, Any],
    health_report: Dict[str, Any],
    crucible_packet: Dict[str, Any],
    alpha_manifest: Dict[str, Any],
    policy_registry: Dict[str, Any],
    oracle_scorecard: Dict[str, Any],
    overlay: Dict[str, Any],
    next_workstream: Dict[str, Any],
    resume_blockers: Dict[str, Any],
) -> None:
    if str(residual_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet must PASS")
    if str(residual_packet.get("next_lawful_move", "")).strip() != NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet next move mismatch")
    if str(residual_wedge_spec.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance wedge spec must PASS")
    if str(r5_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed R5 receipt must PASS")
    if bool(r5_receipt.get("router_proof_summary", {}).get("router_superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: counted-lane hardening applies only before superiority is earned")
    if str(ordered_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed ordered proof receipt must PASS")
    if bool(ordered_receipt.get("material_advance_detected")) is not True:
        raise RuntimeError("FAIL_CLOSED: ordered proof must show material advance")
    if str(health_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed route distribution health must PASS")
    if int(health_report.get("route_distribution_delta_count", 0)) <= 0:
        raise RuntimeError("FAIL_CLOSED: recomposed health must show nonzero route deltas")
    if str(crucible_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: crucible escalation packet must PASS")
    if str(alpha_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha manifest must PASS")
    if str(policy_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route policy outcome registry must PASS")
    if str(oracle_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle scorecard must PASS")
    if overlay.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: overlay must keep counted lane closed")
    if next_workstream.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: next workstream contract must keep counted lane closed")
    if resume_blockers.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: resume blockers must keep counted lane closed")


def _index_rows(rows: Sequence[Dict[str, Any]], *, key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: expected object row while indexing")
        row_key = str(row.get(key, "")).strip()
        if not row_key:
            raise RuntimeError(f"FAIL_CLOSED: indexed row missing key {key}")
        out[row_key] = row
    return out


def _build_verdict_grammar(*, subject_head: str, current_head: str, residual_packet: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.counted_lane_verdict_grammar.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This grammar constrains interpretation only. It does not move the counted lane by itself.",
        "active_current_verdict": {
            "verdict_id": "GATE_D_MATERIALLY_ADVANCED__REMAIN_AT_R5_CEILING",
            "why": str(residual_packet.get("current_ceiling_summary", {}).get("exact_superiority_outcome", "")).strip(),
        },
        "allowed_verdicts": [
            {"verdict_id": "GATE_D_MATERIALLY_ADVANCED__REMAIN_AT_R5_CEILING", "counts_as_counted_progress": True, "allows_R6": False, "meaning": "Proof objects moved materially, but alpha remains canonical and superiority is still unearned."},
            {"verdict_id": "FENCED_FAMILY_ROUTE_VALUE_EARNED", "counts_as_counted_progress": True, "allows_R6": False, "meaning": "One or more fenced families prove route-bearing value or de-risking, but branch-level superiority is still unearned."},
            {"verdict_id": "LEARNED_ROUTER_CANDIDATE_ADMISSIBLE_NOT_AUTHORIZED", "counts_as_counted_progress": True, "allows_R6": False, "meaning": "A learned-router candidate is signal-present but still blocked pending ordered proof and authorization law."},
            {"verdict_id": "RESIDUAL_ALPHA_DOMINANCE_PRIMARY_BLOCKER", "counts_as_counted_progress": False, "allows_R6": False, "meaning": "Residual alpha dominance remains the principal blocker preventing superiority."},
            {"verdict_id": "TAXONOMY_WEAKNESS_EXPOSED", "counts_as_counted_progress": False, "allows_R6": False, "meaning": "The current lobe/family split is the blocker rather than insufficient pressure alone."},
            {"verdict_id": "COUNTED_LANE_UNCHANGED", "counts_as_counted_progress": False, "allows_R6": False, "meaning": "A tranche ran but did not move counted proof objects."},
            {"verdict_id": "COUNTED_LANE_CONTAMINATION_DETECTED__RESULT_VOID", "counts_as_counted_progress": False, "allows_R6": False, "meaning": "The result is void because lab and counted lanes were mixed unlawfully."},
            {"verdict_id": "ROUTER_SUPERIORITY_EARNED", "counts_as_counted_progress": True, "allows_R6": True, "meaning": "Router superiority is actually earned by ordered proof on the lawful substrate."},
        ],
        "prohibited_readings": [
            "Do not narrate material advance as router superiority.",
            "Do not treat lab-only crucible wins as counted-lane proof.",
            "Do not treat learned-router-candidate signal as learned-router authorization.",
            "Do not treat fenced-family route value as Gate E/F opening.",
        ],
    }


def _build_pre_mortem_failure_map(*, subject_head: str, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.pre_mortem_failure_map.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This map enumerates foreseeable failure classes for the next tranche. It is preventative, not promotional.",
        "rows": [
            {"failure_id": "FALSE_POSITIVE_SUPERIORITY_READ", "what_can_fail": "Specialist-family signal is mistaken for branch-level superiority.", "false_positive_trigger": "R5 still says router_superiority_earned=false but downstream narration says otherwise.", "void_condition": "Any result interpreted as superiority without a fresh lawful R5 earn."},
            {"failure_id": "COUNTED_LANE_CONTAMINATION", "what_can_fail": "Lab crucible output is allowed to impersonate counted proof.", "false_positive_trigger": "Pressure sweeps modify counted claims without passing transfer guard.", "void_condition": "Any counted-lane result derived directly from crucible output without named transfer surfaces."},
            {"failure_id": "CONTROL_REGRESSION", "what_can_fail": "Static and abstention controls drift while specialists improve.", "false_positive_trigger": "Route value rises but rightful control families stop holding.", "void_condition": "STATIC_NO_ROUTE_CONTROL or BOUNDARY_ABSTENTION_CONTROL regresses."},
            {"failure_id": "ATTRIBUTION_LOSS", "what_can_fail": "Too many pressure axes move at once and wedge sharpening becomes uninterpretable.", "false_positive_trigger": "Composite overload results appear before single-axis evidence exists.", "void_condition": "No named single-axis wedge sharpening can be attached to the result."},
            {"failure_id": "CLAIM_CEILING_DRIFT", "what_can_fail": "The branch starts speaking beyond its actual proof class.", "false_positive_trigger": "Gate E/F, commercialization, or learned-router claims appear while R6 remains blocked.", "void_condition": "Any output exceeds current verdict grammar and counted-lane ceiling."},
        ],
    }


def _build_governance_roi_scorecard(
    *,
    subject_head: str,
    current_head: str,
    residual_packet: Dict[str, Any],
    policy_registry: Dict[str, Any],
    overlay: Dict[str, Any],
) -> Dict[str, Any]:
    family_rows = residual_packet.get("family_rows", [])
    has_abstention = any(str(row.get("residual_status", "")).strip() == "FAIL_CLOSED_DE_RISKING_SIGNAL__NOT_DIRECT_SUPERIORITY" for row in family_rows)
    has_static_control = any(str(row.get("residual_status", "")).strip() == "RIGHTFUL_STATIC_HOLD__CONTROL_FAMILY" for row in family_rows)
    unique_targets = int(residual_packet.get("proof_object_movement", {}).get("unique_route_target_count_current", 0))
    outcomes = [str(row.get("outcome_id", "")).strip() for row in policy_registry.get("outcomes", [])]
    rows = [
        {"dimension_id": "failure_containment", "status": "PASS_SIGNAL_PRESENT" if has_abstention else "NOT_YET_EARNED", "evidence": "Boundary abstention control remains lawful and live." if has_abstention else "No live abstention-control signal recorded."},
        {"dimension_id": "abstention_correctness", "status": "PASS_SIGNAL_PRESENT" if "ABSTAIN_FOR_REVIEW" in outcomes else "NOT_YET_EARNED", "evidence": "ABSTAIN_FOR_REVIEW preserved as a real policy outcome."},
        {"dimension_id": "traceability", "status": "PASS_SIGNAL_PRESENT" if unique_targets >= 3 else "PARTIAL_SIGNAL", "evidence": f"unique_route_target_count_current={unique_targets}"},
        {"dimension_id": "replayability", "status": "PASS_SIGNAL_PRESENT", "evidence": "Current branch remains bound through authoritative refs and tracked carrier surfaces."},
        {"dimension_id": "rollback_confidence", "status": "PARTIAL_SIGNAL", "evidence": "Promotion/merge followthrough was bound earlier, but current router branch still stops short of superiority."},
        {"dimension_id": "operator_burden_reduction", "status": "NOT_YET_EARNED", "evidence": "repo_state_executable_now=false; manual interpretation is still required before wider rollout."},
        {"dimension_id": "control_integrity", "status": "PASS_SIGNAL_PRESENT" if has_static_control else "NOT_YET_EARNED", "evidence": "STATIC_NO_ROUTE_CONTROL remains a rightful hold family." if has_static_control else "No explicit no-route hold family found."},
    ]
    return {
        "schema_id": "kt.operator.governance_roi_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This scorecard measures governance-derived value signals only. It does not claim router superiority or external comparative wins.",
        "repo_state_executable_now": bool(overlay.get("repo_state_executable_now")),
        "rows": rows,
    }


def _build_alpha_liability_registry(
    *,
    subject_head: str,
    current_head: str,
    alpha_manifest: Dict[str, Any],
    residual_wedge_spec: Dict[str, Any],
) -> Dict[str, Any]:
    alpha_rows = _index_rows(alpha_manifest.get("rows", []), key="family_id")
    wedge_rows = _index_rows(residual_wedge_spec.get("rows", []), key="family_id")
    rows: List[Dict[str, Any]] = []
    for family_id, alpha_row in sorted(alpha_rows.items()):
        wedge_row = wedge_rows.get(family_id, {})
        rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(alpha_row.get("target_lobe_id", "")).strip() or str(wedge_row.get("target_lobe_id", "")).strip(),
                "alpha_should_lose_here_because": str(alpha_row.get("alpha_should_lose_here_because", "")).strip(),
                "acceptance_metric": str(alpha_row.get("acceptance_metric", "")).strip(),
                "expected_route_outcome": str(alpha_row.get("expected_route_outcome", "")).strip(),
                "primary_pressure_axis": str(wedge_row.get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(wedge_row.get("secondary_pressure_axis", "")).strip(),
                "new_admissible_eval_family": str(wedge_row.get("new_admissible_eval_family", "")).strip(),
            }
        )
    return {
        "schema_id": "kt.operator.alpha_liability_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This registry records preregistered alpha liabilities only. It does not by itself earn superiority.",
        "rows": rows,
    }


def _build_transfer_guard(
    *,
    subject_head: str,
    current_head: str,
    crucible_packet: Dict[str, Any],
    residual_packet: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.lab_to_counted_transfer_guard.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This guard defines the only lawful crossing from lab crucible work into counted proof.",
        "transfer_rule": dict(crucible_packet.get("transfer_rule", {})),
        "preserved_controls": {
            "static_hold_family_ids": list(residual_packet.get("residual_alpha_dominance_summary", {}).get("static_hold_families", [])),
            "abstention_control_family_ids": list(residual_packet.get("residual_alpha_dominance_summary", {}).get("abstention_control_families", [])),
        },
        "prohibited_crossings": [
            "No composite-overload result may count before a single-axis wedge sharpening exists.",
            "No Kaggle or lab output may update counted claims directly.",
            "No family may count if its held-out rows were consumed during authoring.",
            "No transfer is valid if control families regress.",
        ],
        "counted_lane_stays_closed_until": [
            "a named wedge sharpening exists",
            "a named anti-alpha liability remains live",
            "a measurable route-delta hypothesis is satisfied",
            "a new admissible eval family is emitted",
            "rerun proof objects move under ordered proof",
        ],
    }


def _build_externalization_readiness_packet(
    *,
    subject_head: str,
    current_head: str,
    residual_packet: Dict[str, Any],
) -> Dict[str, Any]:
    specialist_count = len(residual_packet.get("residual_alpha_dominance_summary", {}).get("specialist_signal_families", []))
    return {
        "schema_id": "kt.operator.externalization_readiness_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This packet measures future externalization readiness only. It does not open Gate E/F or commercial surfaces.",
        "readiness_rows": [
            {"surface_id": "detached_verifier_portability", "status": "PARTIAL_READY", "reason": "Authoritative and tracked carrier surfaces exist, but superiority is not yet earned."},
            {"surface_id": "independent_replay", "status": "PARTIAL_READY", "reason": "The branch is replayable locally through authoritative refs, but external replay packets are not yet bound to a superiority win."},
            {"surface_id": "comparative_scorecard_publicability", "status": "BLOCKED", "reason": "Comparative external claims remain blocked while alpha still holds the canonical static comparator slot."},
            {"surface_id": "negative_row_preservation", "status": "READY", "reason": "Residual-alpha and prior negative-result surfaces are preserved explicitly instead of overwritten."},
            {"surface_id": "claim_ceiling_discipline", "status": "READY", "reason": "Current posture remains materially advanced but below superiority, with no Gate E/F opening."},
            {"surface_id": "public_verifier_bundle", "status": "BLOCKED", "reason": f"specialist_signal_family_count={specialist_count} is meaningful, but branch-level superiority is still unearned."},
        ],
    }


def _build_receipt(*, subject_head: str, current_head: str, emitted_refs: Dict[str, str]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_counted_lane_hardening_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "verdict_posture": VERDICT_POSTURE,
        "claim_boundary": "This receipt hardens interpretation and transfer law only. It does not change the counted-lane ceiling.",
        "emitted_surfaces": emitted_refs,
        "next_lawful_move": NEXT_MOVE,
    }


def run_counted_lane_hardening_tranche(
    *,
    residual_packet_path: Path,
    residual_wedge_spec_path: Path,
    r5_receipt_path: Path,
    ordered_receipt_path: Path,
    health_report_path: Path,
    crucible_packet_path: Path,
    alpha_manifest_path: Path,
    policy_registry_path: Path,
    oracle_scorecard_path: Path,
    current_overlay_path: Path,
    next_workstream_path: Path,
    resume_blockers_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_residual_packet_path, residual_packet = _resolve_authoritative(root, residual_packet_path.resolve(), "authoritative_cohort0_residual_alpha_dominance_packet_ref", "residual alpha dominance packet")
    authoritative_residual_wedge_spec_path, residual_wedge_spec = _resolve_authoritative(root, residual_wedge_spec_path.resolve(), "authoritative_cohort0_residual_alpha_dominance_wedge_spec_ref", "residual alpha dominance wedge spec")
    authoritative_r5_receipt_path, r5_receipt = _resolve_authoritative(root, r5_receipt_path.resolve(), "authoritative_recomposed_router_vs_best_adapter_proof_receipt_ref", "recomposed R5 receipt")
    authoritative_ordered_receipt_path, ordered_receipt = _resolve_authoritative(root, ordered_receipt_path.resolve(), "authoritative_recomposed_router_ordered_proof_receipt_ref", "recomposed ordered proof receipt")
    authoritative_health_path, health_report = _resolve_authoritative(root, health_report_path.resolve(), "authoritative_recomposed_route_distribution_health_ref", "recomposed route health")
    authoritative_crucible_packet_path, crucible_packet = _resolve_authoritative(root, crucible_packet_path.resolve(), "authoritative_crucible_escalation_packet_ref", "crucible escalation packet")
    authoritative_alpha_manifest_path, alpha_manifest = _resolve_authoritative(root, alpha_manifest_path.resolve(), "authoritative_alpha_should_lose_here_manifest_ref", "alpha manifest")
    authoritative_policy_registry_path, policy_registry = _resolve_authoritative(root, policy_registry_path.resolve(), "authoritative_route_policy_outcome_registry_ref", "route policy registry")
    authoritative_oracle_scorecard_path, oracle_scorecard = _resolve_authoritative(root, oracle_scorecard_path.resolve(), "authoritative_oracle_router_local_scorecard_ref", "oracle scorecard")
    authoritative_overlay_path, overlay = _resolve_authoritative(root, current_overlay_path.resolve(), "", "current campaign overlay")
    authoritative_next_workstream_path, next_workstream = _resolve_authoritative(root, next_workstream_path.resolve(), "", "next workstream contract")
    authoritative_resume_blockers_path, resume_blockers = _resolve_authoritative(root, resume_blockers_path.resolve(), "", "resume blockers receipt")

    _validate_inputs(
        residual_packet=residual_packet,
        residual_wedge_spec=residual_wedge_spec,
        r5_receipt=r5_receipt,
        ordered_receipt=ordered_receipt,
        health_report=health_report,
        crucible_packet=crucible_packet,
        alpha_manifest=alpha_manifest,
        policy_registry=policy_registry,
        oracle_scorecard=oracle_scorecard,
        overlay=overlay,
        next_workstream=next_workstream,
        resume_blockers=resume_blockers,
    )

    subject_head = _resolve_subject_head(
        packets=[residual_packet, residual_wedge_spec, r5_receipt, ordered_receipt, health_report, crucible_packet, alpha_manifest, policy_registry, oracle_scorecard]
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_counted_lane_hardening").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    payloads = {
        "counted_lane_verdict_grammar": _build_verdict_grammar(subject_head=subject_head, current_head=current_head, residual_packet=residual_packet),
        "pre_mortem_failure_map": _build_pre_mortem_failure_map(subject_head=subject_head, current_head=current_head),
        "governance_roi_scorecard": _build_governance_roi_scorecard(subject_head=subject_head, current_head=current_head, residual_packet=residual_packet, policy_registry=policy_registry, overlay=overlay),
        "alpha_liability_registry": _build_alpha_liability_registry(subject_head=subject_head, current_head=current_head, alpha_manifest=alpha_manifest, residual_wedge_spec=residual_wedge_spec),
        "lab_to_counted_transfer_guard": _build_transfer_guard(subject_head=subject_head, current_head=current_head, crucible_packet=crucible_packet, residual_packet=residual_packet),
        "externalization_readiness_packet": _build_externalization_readiness_packet(subject_head=subject_head, current_head=current_head, residual_packet=residual_packet),
    }

    emitted_refs: Dict[str, str] = {}
    for key, obj in payloads.items():
        out_path = (target_root / DEFAULT_REPORTS[key]).resolve()
        write_json_stable(out_path, obj)
        emitted_refs[f"{key}_ref"] = out_path.as_posix()

    receipt = _build_receipt(subject_head=subject_head, current_head=current_head, emitted_refs=emitted_refs)
    receipt_path = (target_root / DEFAULT_REPORTS["receipt"]).resolve()
    write_json_stable(receipt_path, receipt)
    emitted_refs["receipt_ref"] = receipt_path.as_posix()

    reports_root.mkdir(parents=True, exist_ok=True)
    for key, obj in payloads.items():
        tracked = dict(obj)
        tracked["carrier_surface_role"] = f"TRACKED_CARRIER_ONLY_{key.upper()}"
        tracked[f"authoritative_{key}_ref"] = emitted_refs[f"{key}_ref"]
        write_json_stable((reports_root / DEFAULT_REPORTS[key]).resolve(), tracked)

    tracked_receipt = dict(receipt)
    tracked_receipt["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_COHORT0_COUNTED_LANE_HARDENING_RECEIPT"
    tracked_receipt["authoritative_cohort0_counted_lane_hardening_receipt_ref"] = receipt_path.as_posix()
    write_json_stable((reports_root / DEFAULT_REPORTS["receipt"]).resolve(), tracked_receipt)

    payloads["receipt"] = receipt
    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Emit counted-lane hardening surfaces without changing the current counted-lane ceiling.")
    ap.add_argument("--residual-packet", default=DEFAULT_RESIDUAL_PACKET_REL)
    ap.add_argument("--residual-wedge-spec", default=DEFAULT_RESIDUAL_WEDGE_SPEC_REL)
    ap.add_argument("--r5-receipt", default=DEFAULT_R5_RECEIPT_REL)
    ap.add_argument("--ordered-receipt", default=DEFAULT_ORDERED_PROOF_REL)
    ap.add_argument("--health-report", default=DEFAULT_HEALTH_REL)
    ap.add_argument("--crucible-packet", default=DEFAULT_CRUCIBLE_PACKET_REL)
    ap.add_argument("--alpha-manifest", default=DEFAULT_ALPHA_MANIFEST_REL)
    ap.add_argument("--policy-registry", default=DEFAULT_POLICY_REGISTRY_REL)
    ap.add_argument("--oracle-scorecard", default=DEFAULT_ORACLE_SCORECARD_REL)
    ap.add_argument("--current-overlay", default=DEFAULT_CURRENT_OVERLAY_REL)
    ap.add_argument("--next-workstream", default=DEFAULT_NEXT_WORKSTREAM_REL)
    ap.add_argument("--resume-blockers", default=DEFAULT_RESUME_BLOCKERS_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_counted_lane_hardening_tranche(
        residual_packet_path=_resolve(root, str(args.residual_packet)),
        residual_wedge_spec_path=_resolve(root, str(args.residual_wedge_spec)),
        r5_receipt_path=_resolve(root, str(args.r5_receipt)),
        ordered_receipt_path=_resolve(root, str(args.ordered_receipt)),
        health_report_path=_resolve(root, str(args.health_report)),
        crucible_packet_path=_resolve(root, str(args.crucible_packet)),
        alpha_manifest_path=_resolve(root, str(args.alpha_manifest)),
        policy_registry_path=_resolve(root, str(args.policy_registry)),
        oracle_scorecard_path=_resolve(root, str(args.oracle_scorecard)),
        current_overlay_path=_resolve(root, str(args.current_overlay)),
        next_workstream_path=_resolve(root, str(args.next_workstream)),
        resume_blockers_path=_resolve(root, str(args.resume_blockers)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["receipt"]
    print(json.dumps({"status": receipt["status"], "verdict_posture": receipt["verdict_posture"], "next_lawful_move": receipt["next_lawful_move"]}, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
