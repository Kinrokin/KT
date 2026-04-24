from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_hardened_ceiling_verdict_packet.json"
DEFAULT_LIMITATIONS_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_current_substrate_limitations_report.json"
DEFAULT_REENTRY_BLOCK_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_reentry_block_contract.json"
DEFAULT_REDESIGN_WORK_ORDER_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_redesign_campaign_work_order.json"
DEFAULT_THEOREM_TARGET_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_next_theorem_target.json"
DEFAULT_CLOSEOUT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_hardened_ceiling_closeout_receipt.json"
DEFAULT_BLOCKER_BOARD_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_parallel_blocker_board.json"
DEFAULT_CURRENT_STATUS_REL = "KT_PROD_CLEANROOM/reports/cohort0_v11_current_status_section.json"
DEFAULT_STATUS_AUDIT_REL = "KT_PROD_CLEANROOM/reports/cohort0_v11_gate_d_status_audit_packet.json"
DEFAULT_REPORTS_ROOT_REL = "KT_PROD_CLEANROOM/reports"

EXPECTED_SUBJECT_HEAD = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"
EXPECTED_FINAL_VERDICT_ID = "GATE_D_NOT_CLEARED__CURRENT_SAME_HEAD_LANE_HARDENED_CEILING"
EXPECTED_THEOREM_CLASSIFICATION = "THEOREM_PARTIALLY_REAL__CURRENT_REALIZATION_CEILINGED_BY_RESIDUAL_ALPHA_DOMINANCE"
EXPECTED_PRIMARY_MOVE = "EXECUTE_REPORTABILITY_BRIDGE_REALIZATION_CAMPAIGN__PRIMARY"
EXPECTED_SECONDARY_MOVE = "EXECUTE_CAUSAL_ROUTE_CONSEQUENCE_HARNESS_CAMPAIGN__SECONDARY"
EXPECTED_PRIMARY_BLOCKER = "PRIMARY_THEOREM_BLOCKER__CURRENT_SUBSTRATE_CEILING_HARDENED__MISSING_MECHANISM_REDESIGN_REQUIRED"

OUTPUT_CHARTER = "cohort0_gate_d_successor_execution_charter.json"
OUTPUT_REPORT = "COHORT0_GATE_D_SUCCESSOR_COMPLETION_REPORT.md"
OUTPUT_SUCCESSOR_REENTRY_CONTRACT = "cohort0_successor_gate_d_reentry_contract.json"
OUTPUT_SCOPE_MANIFEST = "cohort0_mechanism_first_scope_manifest.json"
OUTPUT_EXECUTION_LOCK = "cohort0_execution_board_lock_receipt.json"
OUTPUT_TRUTH_SURFACE_LOCK = "cohort0_canonical_truth_surface_lock.json"
OUTPUT_RESCUE_VALIDATOR = "cohort0_redesign_versus_rescue_validator.json"
OUTPUT_REPORTABILITY_THEOREM_CONTRACT = "reportability_bridge_theorem_contract.json"
OUTPUT_REPORTABILITY_METRIC_CONTRACT = "reportability_bridge_metric_contract.json"
OUTPUT_REPORTABILITY_EVAL_COURT = "reportability_bridge_eval_court.json"
OUTPUT_REPORTABILITY_TRAINING_MANIFEST = "reportability_bridge_training_manifest.json"
OUTPUT_REPORTABILITY_MUTATION_PACK = "reportability_bridge_holdout_mutation_pack.json"
OUTPUT_REPORTABILITY_SUCCESS_RECEIPT = "reportability_bridge_success_verdict_receipt.json"
OUTPUT_CAUSAL_INTERVENTION_MATRIX = "causal_route_consequence_intervention_matrix.json"
OUTPUT_FORCED_WRONG_ROUTE = "forced_wrong_route_contract.json"
OUTPUT_RANDOM_ROUTE = "random_route_negative_control.json"
OUTPUT_ORACLE_UPPER_BOUND = "oracle_route_upper_bound_contract.json"
OUTPUT_ROUTE_ABLATION = "route_ablation_harness.json"
OUTPUT_ROUTE_CONSEQUENCE_RECEIPT = "route_consequence_verdict_receipt.json"
OUTPUT_MICRO_COURTS = "cohort0_successor_frozen_micro_courts_manifest.json"
OUTPUT_DOMINANCE_PACKET_CONTRACT = "cohort0_successor_dominance_packet_contract.json"
OUTPUT_READJUDICATION_MANIFEST = "cohort0_successor_gate_d_readjudication_manifest.json"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


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
        raise RuntimeError("FAIL_CLOSED: successor execution charter requires one same-head authority line")
    return next(iter(heads))


def _append_unique(items: List[str], value: str) -> None:
    text = str(value).strip()
    if text and text not in items:
        items.append(text)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _validate_live_state(
    *,
    verdict_packet: Dict[str, Any],
    limitations_report: Dict[str, Any],
    reentry_block: Dict[str, Any],
    redesign_work_order: Dict[str, Any],
    theorem_target: Dict[str, Any],
    closeout_receipt: Dict[str, Any],
    blocker_board: Dict[str, Any],
    current_status: Dict[str, Any],
    status_audit: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (limitations_report, "current substrate limitations report"),
        (reentry_block, "gate d reentry block contract"),
        (redesign_work_order, "gate d redesign campaign work order"),
        (theorem_target, "gate d next theorem target"),
        (closeout_receipt, "gate d hardened ceiling closeout receipt"),
        (blocker_board, "gate d parallel blocker board"),
        (current_status, "v11 current status section"),
        (status_audit, "v11 gate d status audit packet"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if str(verdict_packet.get("theorem_classification", "")).strip() != EXPECTED_THEOREM_CLASSIFICATION:
        raise RuntimeError("FAIL_CLOSED: verdict packet theorem classification mismatch")
    if str(verdict_packet.get("next_lawful_move", "")).strip() != EXPECTED_PRIMARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: verdict packet primary next move mismatch")
    if str(verdict_packet.get("secondary_parallel_move", "")).strip() != EXPECTED_SECONDARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: verdict packet secondary move mismatch")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: successor charter requires same-head reentry to remain blocked")

    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block contract must show hardened ceiling block")
    if str(closeout_receipt.get("current_primary_blocker", "")).strip() != EXPECTED_PRIMARY_BLOCKER:
        raise RuntimeError("FAIL_CLOSED: closeout receipt primary blocker mismatch")
    if str(blocker_board.get("gate_d_status", "")).strip() != "UNCLEARED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: blocker board gate_d_status mismatch")
    if str(current_status.get("next_lawful_move", "")).strip() != EXPECTED_PRIMARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: current status next move mismatch")
    if str(status_audit.get("audit_packet_posture", "")).strip() != "STATUS_ONLY__HARDENED_CEILING_VERDICT__REDESIGN_REQUIRED":
        raise RuntimeError("FAIL_CLOSED: status audit posture mismatch")


def _build_workstreams(subject_head: str, authority_refs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    return {
        "A_GOVERNANCE_LOCK_AND_SCOPE_HYGIENE": {
            "status": "ACTIVE__PARTIALLY_REALIZED__SUCCESSOR_GOVERNANCE_SURFACES_AUTHORED",
            "goal": "Make successor redesign work mechanically distinct from covert same-lane rescue.",
            "objectives": [
                "freeze successor scope and comparator order",
                "pin canonical truth surfaces",
                "reject rescue-shaped narration mechanically",
            ],
            "deliverables": [
                OUTPUT_SUCCESSOR_REENTRY_CONTRACT,
                OUTPUT_SCOPE_MANIFEST,
                OUTPUT_EXECUTION_LOCK,
                OUTPUT_TRUTH_SURFACE_LOCK,
                OUTPUT_RESCUE_VALIDATOR,
            ],
            "pass_criteria": [
                "same-lane rescue language is mechanically rejected",
                "alpha comparator remains pinned",
                "canonical/lab/archive boundaries stay explicit",
                "posture remains receipt-derived",
            ],
            "fail_criteria": [
                "successor artifacts silently inherit same-lane assumptions",
                "mixed-surface truth drift appears",
                "comparator order is relaxed or blurred",
            ],
            "source_refs": authority_refs,
        },
        "B_REPORTABILITY_BRIDGE_THEOREM_COURT": {
            "status": "AUTHORIZED__NOT_EXECUTED",
            "goal": "Realize typed admissible reportability without regressing current action/why-not strength.",
            "objectives": [
                "define admissible reportability precisely",
                "target the frozen fail families that mattered in the ceiling verdict",
                "prove held-out reason lift without action/why-not regression",
            ],
            "deliverables": [
                OUTPUT_REPORTABILITY_THEOREM_CONTRACT,
                OUTPUT_REPORTABILITY_METRIC_CONTRACT,
                OUTPUT_REPORTABILITY_EVAL_COURT,
                OUTPUT_REPORTABILITY_TRAINING_MANIFEST,
                OUTPUT_REPORTABILITY_MUTATION_PACK,
                OUTPUT_REPORTABILITY_SUCCESS_RECEIPT,
            ],
            "pass_criteria": [
                "typed held-out reason lift appears on the failure families that mattered",
                "action remains strong",
                "why-not remains strong",
                "the result survives mutation rather than formatting mimicry",
            ],
            "fail_criteria": [
                "prose quality rises without causal reportability lift",
                "action regresses",
                "why-not regresses",
                "reportability gains vanish under mutation",
            ],
            "source_refs": authority_refs,
        },
        "C_CAUSAL_ROUTE_CONSEQUENCE_HARNESS": {
            "status": "AUTHORIZED__NOT_EXECUTED",
            "goal": "Make route consequence comparator-legible through interventions rather than route texture.",
            "objectives": [
                "define the intervention matrix",
                "separate latent consequence from absent consequence",
                "price wrong routing and forced routing explicitly",
            ],
            "deliverables": [
                OUTPUT_CAUSAL_INTERVENTION_MATRIX,
                OUTPUT_FORCED_WRONG_ROUTE,
                OUTPUT_RANDOM_ROUTE,
                OUTPUT_ORACLE_UPPER_BOUND,
                OUTPUT_ROUTE_ABLATION,
                OUTPUT_ROUTE_CONSEQUENCE_RECEIPT,
            ],
            "pass_criteria": [
                "wrong-route penalty is visible",
                "correct-route advantage is visible",
                "route-vs-static economics are visible under intervention",
                "one fenced family shows admissible route consequence against the best static path",
            ],
            "fail_criteria": [
                "route distributions look different but outcomes do not move",
                "wrong-route penalties stay weak",
                "gains vanish against alpha",
                "wins are too family-concentrated to count",
            ],
            "source_refs": authority_refs,
        },
        "D_FROZEN_MICRO_COURTS": {
            "status": "AUTHORIZED__NOT_EXECUTED",
            "goal": "Learn quickly and honestly on frozen fail geometry before any major theorem run.",
            "objectives": [
                "freeze 3-5 micro-courts from the exact ceiling geometry",
                "test redesign variants without eval drift",
            ],
            "deliverables": [OUTPUT_MICRO_COURTS],
            "pass_criteria": [
                "reportability lift",
                "no action regression",
                "no why-not regression",
                "measurable proof-facing route delta under intervention",
            ],
            "fail_criteria": [
                "any of the four frozen micro-court conditions fail",
            ],
            "source_refs": authority_refs,
        },
        "E_DOMINANCE_MAPPING": {
            "status": "AUTHORIZED__NOT_EXECUTED",
            "goal": "Map exactly where the successor beats alpha and where alpha still dominates.",
            "objectives": [
                "emit alpha lose-zones and alpha still-dominates zones",
                "price abstain/static boundary correctness",
                "measure family concentration of wins",
            ],
            "deliverables": [OUTPUT_DOMINANCE_PACKET_CONTRACT],
            "pass_criteria": [
                "win geometry is explicit",
                "family concentration is measurable",
                "route-economics reduction zones are visible",
            ],
            "fail_criteria": [
                "big runs are authorized without a real dominance map",
            ],
            "source_refs": authority_refs,
        },
        "F_GATE_D_READJUDICATION_PACKAGE": {
            "status": "BLOCKED__UNTIL_PRIOR_WORKSTREAMS_PASS",
            "goal": "Reopen a lawful Gate D court only after the successor realization earns it.",
            "objectives": [
                "require micro-courts to pass",
                "require dominance packet movement",
                "require complete proof bundle under comparator lock",
            ],
            "deliverables": [OUTPUT_READJUDICATION_MANIFEST],
            "pass_criteria": [
                "controls preserved",
                "reportability and route consequence both rise enough to matter",
                "best static path is beaten or safely de-risked in one fenced family",
            ],
            "fail_criteria": [
                "movement stays narrow, brittle, or non-causal",
            ],
            "source_refs": authority_refs,
        },
    }


def _reportability_artifacts(subject_head: str, authority_refs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    common = {
        "status": "PASS",
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "subject_head": subject_head,
        "source_refs": authority_refs,
    }
    return {
        OUTPUT_REPORTABILITY_THEOREM_CONTRACT: {
            **common,
            "schema_id": "kt.operator.reportability_bridge_theorem_contract.v1",
            "claim_boundary": "This contract authorizes successor-realization reportability bridge work. It does not reopen the exhausted same-head lane.",
            "goal": "Realize typed admissible reportability on the frozen fail geometry.",
            "required_outputs": [
                "typed causal report object",
                "reason-faithfulness checks",
                "held-out reason lift",
                "no action regression",
                "no why-not regression",
            ],
            "non_moves": [
                "do not reward prettier prose as theorem movement",
                "do not reopen same-lane rescue under explanation language",
            ],
        },
        OUTPUT_REPORTABILITY_METRIC_CONTRACT: {
            **common,
            "schema_id": "kt.operator.reportability_bridge_metric_contract.v1",
            "claim_boundary": "These metrics separate reportability lift from policy quality.",
            "tracked_metrics": [
                "action_correctness",
                "why_not_correctness",
                "reason_correctness",
                "route_correctness",
                "calibration",
                "evidence_citation_fidelity",
            ],
            "pass_signature": [
                "reason_correctness rises materially above the current zero-holdout floor",
                "action_correctness remains preserved",
                "why_not_correctness remains preserved",
            ],
        },
        OUTPUT_REPORTABILITY_EVAL_COURT: {
            **common,
            "schema_id": "kt.operator.reportability_bridge_eval_court.v1",
            "claim_boundary": "This eval court freezes the failure families that matter to the closeout.",
            "court_shape": {
                "frozen_failure_geometry": True,
                "typed_outputs_only": True,
                "mutation_pressure_required": True,
            },
            "families_under_test": [
                "held_out_reason_failures_from_hardened_ceiling",
                "mutation_clones_of_the_same_fail_geometry",
            ],
        },
        OUTPUT_REPORTABILITY_TRAINING_MANIFEST: {
            **common,
            "schema_id": "kt.operator.reportability_bridge_training_manifest.v1",
            "claim_boundary": "This manifest authorizes bridge-specific training only as successor work.",
            "training_intents": [
                "typed causal schema emission",
                "bridge-specific objective heads",
                "low-confidence lawful refusal when no admissible reason object exists",
            ],
        },
        OUTPUT_REPORTABILITY_MUTATION_PACK: {
            **common,
            "schema_id": "kt.operator.reportability_bridge_holdout_mutation_pack.v1",
            "claim_boundary": "This mutation pack protects against formatting-memorization masquerading as reportability.",
            "mutation_dimensions": [
                "lexical_shell",
                "domain_label",
                "evidence_order",
                "distractor_structure",
                "ambiguity_framing",
            ],
        },
        OUTPUT_REPORTABILITY_SUCCESS_RECEIPT: {
            **common,
            "schema_id": "kt.operator.reportability_bridge_success_verdict_receipt.v1",
            "claim_boundary": "This receipt is only valid after execution. It is currently just the authorized verdict surface.",
            "future_pass_conditions": [
                "held-out typed reason lift",
                "no action regression",
                "no why-not regression",
                "mutation robustness",
            ],
        },
    }


def _causal_route_artifacts(subject_head: str, authority_refs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    common = {
        "status": "PASS",
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "subject_head": subject_head,
        "source_refs": authority_refs,
    }
    return {
        OUTPUT_CAUSAL_INTERVENTION_MATRIX: {
            **common,
            "schema_id": "kt.operator.causal_route_consequence_intervention_matrix.v1",
            "claim_boundary": "This matrix authorizes intervention-based route-consequence proof. It is not observational route texture.",
            "required_interventions": [
                "forced_wrong_route",
                "random_route",
                "forced_static_hold",
                "abstain_disabled",
                "witness_ablation",
                "oracle_route_upper_bound",
            ],
        },
        OUTPUT_FORCED_WRONG_ROUTE: {
            **common,
            "schema_id": "kt.operator.forced_wrong_route_contract.v1",
            "claim_boundary": "Wrong-route penalties must become visible before Gate D can reopen.",
            "future_pass_condition": "forced wrong-route produces measurable penalty against the routed baseline",
        },
        OUTPUT_RANDOM_ROUTE: {
            **common,
            "schema_id": "kt.operator.random_route_negative_control.v1",
            "claim_boundary": "Random-route serves as a negative control for ornamental routing.",
            "future_pass_condition": "routed behavior must outperform random-route under intervention",
        },
        OUTPUT_ORACLE_UPPER_BOUND: {
            **common,
            "schema_id": "kt.operator.oracle_route_upper_bound_contract.v1",
            "claim_boundary": "Oracle-route upper bound determines whether real route-bearing headroom exists.",
            "future_questions": [
                "is route-bearing headroom large enough to matter",
                "if headroom exists, is the substrate or the harness the blocker",
            ],
        },
        OUTPUT_ROUTE_ABLATION: {
            **common,
            "schema_id": "kt.operator.route_ablation_harness.v1",
            "claim_boundary": "Ablation must show whether route choice is causally load-bearing.",
            "required_ablation_types": [
                "witness_ablation",
                "route_assignment_ablation",
                "abstain_path_ablation",
            ],
        },
        OUTPUT_ROUTE_CONSEQUENCE_RECEIPT: {
            **common,
            "schema_id": "kt.operator.route_consequence_verdict_receipt.v1",
            "claim_boundary": "This receipt becomes real only after intervention execution; it is authored now as the verdict surface.",
            "future_pass_conditions": [
                "wrong-route penalty visible",
                "route-vs-static economics visible",
                "one fenced family shows admissible route consequence",
            ],
        },
    }


def _governance_artifacts(subject_head: str, authority_refs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    common = {
        "status": "PASS",
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "subject_head": subject_head,
        "source_refs": authority_refs,
    }
    return {
        OUTPUT_SUCCESSOR_REENTRY_CONTRACT: {
            **common,
            "schema_id": "kt.operator.cohort0_successor_gate_d_reentry_contract.v1",
            "claim_boundary": "This contract defines what must change before any successor Gate D reentry is lawful.",
            "reentry_requires": [
                "materially changed substrate",
                "reportability bridge or equivalent realized",
                "causal route consequence harness emits intervention proof objects",
                "fresh comparator-bound theorem target remains pinned",
            ],
        },
        OUTPUT_SCOPE_MANIFEST: {
            **common,
            "schema_id": "kt.operator.cohort0_mechanism_first_scope_manifest.v1",
            "claim_boundary": "This manifest keeps redesign work mechanism-first and rescue-free.",
            "allowed_scope": [
                "reportability bridge realization",
                "causal route consequence harness",
                "frozen micro-court measurement",
                "dominance mapping",
            ],
            "disallowed_scope": [
                "same-lane rescue",
                "mixed-axis relaunch under new language",
                "early Gate E narration",
            ],
        },
        OUTPUT_EXECUTION_LOCK: {
            **common,
            "schema_id": "kt.operator.cohort0_execution_board_lock_receipt.v1",
            "claim_boundary": "This receipt affirms that successor work does not alter current branch law.",
            "locked_live_state": {
                "gate_d_status": "UNCLEARED__CURRENT_LANE_HARDENED_CEILING",
                "gate_e_status": "BLOCKED_UNTIL_MATERIALLY_CHANGED_SUBSTRATE_EARNS_GATE_D",
                "same_head_counted_reentry_blocked": True,
            },
        },
        OUTPUT_TRUTH_SURFACE_LOCK: {
            **common,
            "schema_id": "kt.operator.cohort0_canonical_truth_surface_lock.v1",
            "claim_boundary": "Canonical truth remains receipt-first and mechanically derived.",
            "protected_surfaces": [
                "cohort0_gate_d_hardened_ceiling_verdict_packet.json",
                "cohort0_gate_d_parallel_blocker_board.json",
                "cohort0_v11_current_status_section.json",
                "cohort0_v11_gate_d_status_audit_packet.json",
            ],
        },
        OUTPUT_RESCUE_VALIDATOR: {
            **common,
            "schema_id": "kt.operator.cohort0_redesign_versus_rescue_validator.v1",
            "claim_boundary": "This validator distinguishes successor redesign from covert same-lane rescue.",
            "fail_closed_conditions": [
                "same-lane counted reentry language appears",
                "mixed-axis is described as pending or next",
                "Gate E narration appears before a new Gate D clear",
                "proposal language is written as established branch fact",
            ],
        },
    }


def _other_support_artifacts(subject_head: str, authority_refs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    common = {
        "status": "PASS",
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "subject_head": subject_head,
        "source_refs": authority_refs,
    }
    return {
        OUTPUT_MICRO_COURTS: {
            **common,
            "schema_id": "kt.operator.cohort0_successor_frozen_micro_courts_manifest.v1",
            "claim_boundary": "Frozen micro-courts guard against eval drift before any major successor theorem run.",
            "required_pass_conditions_per_micro_court": [
                "reportability_lift",
                "no_action_regression",
                "no_why_not_regression",
                "proof_facing_route_delta_under_intervention",
            ],
            "recommended_count": 5,
        },
        OUTPUT_DOMINANCE_PACKET_CONTRACT: {
            **common,
            "schema_id": "kt.operator.cohort0_successor_dominance_packet_contract.v1",
            "claim_boundary": "No major successor theorem run should proceed without explicit win geometry.",
            "required_sections": [
                "alpha_should_lose_here_manifest",
                "alpha_still_dominates_here_manifest",
                "abstain_static_boundary_correctness_map",
                "route_economics_reduction_map",
                "family_concentration_report",
            ],
        },
        OUTPUT_READJUDICATION_MANIFEST: {
            **common,
            "schema_id": "kt.operator.cohort0_successor_gate_d_readjudication_manifest.v1",
            "claim_boundary": "This manifest only becomes executable after the successor workstreams pass.",
            "preconditions": [
                "micro_courts_passed",
                "dominance_packet_shows_nontrivial_win_geometry",
                "controls_still_hold",
                "proof_bundle_is_complete",
            ],
        },
    }


def _build_markdown_report(charter: Dict[str, Any], outputs: Sequence[str]) -> str:
    lines: List[str] = []
    lines.append("# COHORT0 Gate D Successor Completion Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{charter['generated_utc']}`")
    lines.append(f"- Subject head: `{charter['subject_head']}`")
    lines.append(f"- Final verdict: `{charter['live_authority_snapshot']['final_verdict_id']}`")
    lines.append(f"- Theorem classification: `{charter['live_authority_snapshot']['theorem_classification']}`")
    lines.append("")
    lines.append("## Live Authority Summary")
    lines.append("")
    lines.append(f"- Gate D status: `{charter['live_authority_snapshot']['gate_d_status']}`")
    lines.append(f"- Gate E status: `{charter['live_authority_snapshot']['gate_e_status']}`")
    lines.append(f"- Current primary blocker: `{charter['live_authority_snapshot']['current_primary_blocker']}`")
    lines.append(f"- Primary next move: `{charter['live_authority_snapshot']['next_lawful_move']}`")
    lines.append(f"- Secondary parallel move: `{charter['live_authority_snapshot']['secondary_parallel_move']}`")
    lines.append(f"- Same-head counted reentry admissible now: `{charter['live_authority_snapshot']['same_head_counted_reentry_admissible_now']}`")
    lines.append("")
    lines.append("## What Was Completed")
    lines.append("")
    for item in charter["completion_summary"]["completed_now"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Immediate Non-Negotiables")
    lines.append("")
    for item in charter["hard_prohibitions"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Workstream Status")
    lines.append("")
    for key, payload in charter["workstreams"].items():
        lines.append(f"### {key}")
        lines.append("")
        lines.append(f"- Status: `{payload['status']}`")
        lines.append(f"- Goal: {payload['goal']}")
        lines.append("- Objectives:")
        for obj in payload["objectives"]:
            lines.append(f"  - {obj}")
        lines.append("- Deliverables:")
        for obj in payload["deliverables"]:
            lines.append(f"  - `{obj}`")
        lines.append("")
    lines.append("## Shortest Marching Order")
    lines.append("")
    for idx, step in enumerate(charter["shortest_marching_order"], start=1):
        lines.append(f"{idx}. {step}")
    lines.append("")
    lines.append("## Files Emitted By This Tranche")
    lines.append("")
    for rel in outputs:
        lines.append(f"- `{rel}`")
    lines.append("")
    lines.append("## Completion Boundary")
    lines.append("")
    lines.append("This report completes the planning/charter layer only. It does not claim that the successor campaigns have been executed or that Gate D has reopened.")
    lines.append("")
    return "\n".join(lines)


def run_gate_d_successor_execution_charter_tranche(
    *,
    verdict_packet_path: Path,
    limitations_report_path: Path,
    reentry_block_path: Path,
    redesign_work_order_path: Path,
    theorem_target_path: Path,
    closeout_receipt_path: Path,
    blocker_board_path: Path,
    current_status_path: Path,
    status_audit_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    root = repo_root().resolve()
    reports_root = reports_root.resolve()
    reports_root.mkdir(parents=True, exist_ok=True)

    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    limitations_report = _load_json_required(limitations_report_path, label="current substrate limitations report")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    redesign_work_order = _load_json_required(redesign_work_order_path, label="gate d redesign campaign work order")
    theorem_target = _load_json_required(theorem_target_path, label="gate d next theorem target")
    closeout_receipt = _load_json_required(closeout_receipt_path, label="gate d hardened ceiling closeout receipt")
    blocker_board = _load_json_required(blocker_board_path, label="gate d parallel blocker board")
    current_status = _load_json_required(current_status_path, label="v11 current status section")
    status_audit = _load_json_required(status_audit_path, label="v11 gate d status audit packet")

    _validate_live_state(
        verdict_packet=verdict_packet,
        limitations_report=limitations_report,
        reentry_block=reentry_block,
        redesign_work_order=redesign_work_order,
        theorem_target=theorem_target,
        closeout_receipt=closeout_receipt,
        blocker_board=blocker_board,
        current_status=current_status,
        status_audit=status_audit,
    )

    subject_head = _require_same_subject_head(
        [
            verdict_packet,
            limitations_report,
            reentry_block,
            redesign_work_order,
            theorem_target,
            closeout_receipt,
            blocker_board,
            current_status,
            status_audit,
        ]
    )
    if subject_head != EXPECTED_SUBJECT_HEAD:
        raise RuntimeError("FAIL_CLOSED: unexpected subject head for successor execution charter")

    authority_refs = {
        "verdict_packet_ref": verdict_packet_path.as_posix(),
        "limitations_report_ref": limitations_report_path.as_posix(),
        "reentry_block_ref": reentry_block_path.as_posix(),
        "redesign_work_order_ref": redesign_work_order_path.as_posix(),
        "theorem_target_ref": theorem_target_path.as_posix(),
        "closeout_receipt_ref": closeout_receipt_path.as_posix(),
        "blocker_board_ref": blocker_board_path.as_posix(),
        "current_status_ref": current_status_path.as_posix(),
        "status_audit_ref": status_audit_path.as_posix(),
    }

    workstreams = _build_workstreams(subject_head, authority_refs)

    charter = {
        "schema_id": "kt.operator.cohort0_gate_d_successor_execution_charter.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": verdict_packet.get("current_git_head", ""),
        "subject_head": subject_head,
        "claim_boundary": (
            "This charter derives the successor execution plan from the live hardened-ceiling authority stack. "
            "It does not reopen the exhausted same-head lane or claim any campaign execution that has not happened."
        ),
        "live_authority_snapshot": {
            "final_verdict_id": verdict_packet["final_verdict_id"],
            "theorem_classification": verdict_packet["theorem_classification"],
            "gate_d_status": blocker_board["gate_d_status"],
            "gate_e_status": blocker_board["gate_e_status"],
            "current_primary_blocker": closeout_receipt["current_primary_blocker"],
            "next_lawful_move": verdict_packet["next_lawful_move"],
            "secondary_parallel_move": verdict_packet["secondary_parallel_move"],
            "same_head_counted_reentry_admissible_now": verdict_packet["same_head_counted_reentry_admissible_now"],
            "current_same_head_lane_closed": verdict_packet["current_lane_closed"],
        },
        "governing_definition": {
            "gate_d_means_now": (
                "Design a successor realization that can lawfully reopen admissibility by proving the missing mechanism(s), "
                "then beat or safely displace the best static path under the same-head court."
            ),
            "branch_is_trying_to_prove": (
                "Can a successor realization add admissible explicit reportability and proof-usable causal route consequence "
                "strongly enough to reopen Gate D and then clear it against the best static comparator?"
            ),
        },
        "hard_prohibitions": [
            "No same-lane rescue under prettier language.",
            "No one-more-refinement-pass framing.",
            "No narrating mixed-axis as pending.",
            "No early E/F narration.",
            "No relaxing comparator order.",
            "No historical theory overruling live receipts.",
            "No archive/lab/commercial contamination of canonical truth.",
            "No treating route sensitivity as route consequence.",
            "No posture drift; truth must stay mechanically derived from live state.",
        ],
        "global_success_ladder": [
            {"level": 0, "id": "BRANCH_HONESTY", "definition": "The lane is closed, the ceiling is frozen, and same-lane rescue is blocked."},
            {"level": 1, "id": "REDESIGN_VIABILITY", "definition": "A successor mechanism moves frozen micro-courts on reportability and/or route consequence."},
            {"level": 2, "id": "GATE_D_REENTRY_ADMISSIBILITY", "definition": "The redesign is strong enough to justify a counted Gate D attempt on a successor realization."},
            {"level": 3, "id": "GATE_D_CLEAR", "definition": "The successor realization beats or safely de-risks the best static comparator while preserving controls, rightful static hold, and rightful abstention."},
            {"level": 4, "id": "GATE_E_ADMISSIBLE", "definition": "Only after a true Gate D clear."},
        ],
        "workstreams": workstreams,
        "methods": [
            "mechanism-first design",
            "frozen fail geometry",
            "typed objects over prose",
            "intervention over observation",
            "comparator discipline",
            "narrow theorem increments",
            "fail-closed advancement",
        ],
        "patterns_to_watch": {
            "good_trajectory": [
                "typed reportability rises first on exact fail families",
                "why-not stays stable",
                "action stays stable",
                "wrong-route penalties become clearer",
                "route ablations reveal explicit consequence",
                "alpha lose-zones expand",
            ],
            "weak_trajectory": [
                "explanations look better",
                "action gets a little worse",
                "route texture looks richer",
                "consequence remains weak",
                "wins stay narrow and brittle",
            ],
            "bad_trajectory": [
                "large prose improvements without causal lift",
                "calibration worsens",
                "abstain quality worsens",
                "wrong-route controls barely matter",
                "alpha still dominates under intervention",
            ],
        },
        "shortest_marching_order": [
            "Lock successor scope and reentry boundaries so same-lane rescue drift is impossible.",
            "Freeze the failure atlas from the hardened-ceiling closeout.",
            "Author the reportability bridge theorem contract, metric contract, and eval court.",
            "Author the causal route-consequence intervention matrix and controls.",
            "Build 3-5 frozen micro-courts from the exact fail geometry.",
            "Test bridge and harness variants only on those frozen courts first.",
            "Reject variants that improve prose without improving typed admissible reportability.",
            "Reject variants that show route texture without proof-facing consequence.",
            "Build the successor dominance packet.",
            "Only if the above passes, authorize a successor Gate D readjudication package.",
            "Readjudicate Gate D brutally.",
            "Only after a real Gate D pass, open Gate E.",
        ],
        "completion_summary": {
            "completed_now": [
                "Derived a successor execution charter from the live hardened-ceiling authority stack.",
                "Authored governance-lock support surfaces for redesign-versus-rescue separation.",
                "Authored the reportability bridge starter contract set.",
                "Authored the causal route-consequence harness starter contract set.",
                "Authored frozen micro-court, dominance-packet, and readjudication manifest surfaces.",
                "Emitted a comprehensive completion report grounded in live repo law.",
            ],
            "not_claimed": [
                "No successor campaign execution is claimed.",
                "No Gate D reentry is claimed.",
                "No Gate D clear is claimed.",
                "No Gate E opening is claimed.",
            ],
        },
        "source_refs": authority_refs,
    }

    artifact_payloads: Dict[str, Dict[str, Any]] = {
        OUTPUT_CHARTER: charter,
        **_governance_artifacts(subject_head, authority_refs),
        **_reportability_artifacts(subject_head, authority_refs),
        **_causal_route_artifacts(subject_head, authority_refs),
        **_other_support_artifacts(subject_head, authority_refs),
    }

    output_paths: List[str] = []
    for filename, payload in artifact_payloads.items():
        path = (reports_root / filename).resolve()
        write_json_stable(path, payload)
        output_paths.append(f"KT_PROD_CLEANROOM/reports/{filename}")

    report_markdown = _build_markdown_report(charter, output_paths)
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    _write_text(report_path, report_markdown)
    output_paths.append(f"KT_PROD_CLEANROOM/reports/{OUTPUT_REPORT}")

    return {
        "charter": charter,
        "outputs": output_paths,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Derive the successor Gate D execution charter and completion report from the live hardened-ceiling authority stack."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--limitations-report", default=DEFAULT_LIMITATIONS_REPORT_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--redesign-work-order", default=DEFAULT_REDESIGN_WORK_ORDER_REL)
    parser.add_argument("--theorem-target", default=DEFAULT_THEOREM_TARGET_REL)
    parser.add_argument("--closeout-receipt", default=DEFAULT_CLOSEOUT_RECEIPT_REL)
    parser.add_argument("--blocker-board", default=DEFAULT_BLOCKER_BOARD_REL)
    parser.add_argument("--current-status", default=DEFAULT_CURRENT_STATUS_REL)
    parser.add_argument("--status-audit", default=DEFAULT_STATUS_AUDIT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_gate_d_successor_execution_charter_tranche(
        verdict_packet_path=_resolve(root, str(args.verdict_packet)),
        limitations_report_path=_resolve(root, str(args.limitations_report)),
        reentry_block_path=_resolve(root, str(args.reentry_block)),
        redesign_work_order_path=_resolve(root, str(args.redesign_work_order)),
        theorem_target_path=_resolve(root, str(args.theorem_target)),
        closeout_receipt_path=_resolve(root, str(args.closeout_receipt)),
        blocker_board_path=_resolve(root, str(args.blocker_board)),
        current_status_path=_resolve(root, str(args.current_status)),
        status_audit_path=_resolve(root, str(args.status_audit)),
        reports_root=_resolve(root, str(args.reports_root)),
    )
    charter = payload["charter"]
    print(
        {
            "status": charter["status"],
            "final_verdict_id": charter["live_authority_snapshot"]["final_verdict_id"],
            "next_lawful_move": charter["live_authority_snapshot"]["next_lawful_move"],
            "secondary_parallel_move": charter["live_authority_snapshot"]["secondary_parallel_move"],
            "output_count": len(payload["outputs"]),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
