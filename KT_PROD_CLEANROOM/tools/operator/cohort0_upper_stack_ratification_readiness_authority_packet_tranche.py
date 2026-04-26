from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/upper-stack-ratification-readiness"
EXECUTION_STATUS = "PASS__UPPER_STACK_RATIFICATION_READINESS_AUTHORITY_BOUND"
OUTCOME = "UPPER_STACK_RATIFICATION_READINESS_AUTHORITY_PACKET_BOUND"
NEXT_MOVE_REVALIDATION_ASSET = "AUTHOR_B04_R1_R5_REVALIDATION_ASSET_SUPERSESSION_PACKET"
NEXT_LANE_REVALIDATION_ASSET = "b04_r1_r5_revalidation_asset_supersession"
NEXT_MOVE_R6 = "AUTHOR_B04_R6_LEARNED_ROUTER_SUPERIORITY_BLOCKER_RESOLUTION_PACKET"
NEXT_LANE_R6 = "b04_r6_learned_router_superiority_blocker_resolution"
NEXT_MOVE = NEXT_MOVE_REVALIDATION_ASSET
NEXT_LANE = NEXT_LANE_REVALIDATION_ASSET

POST_BOUNDARY_REGRADE = "post_boundary_canonical_regrade_audit_receipt.json"
NEXT_LANE_RECOMMENDATION = "next_authoritative_lane_recommendation.json"
UPPER_STACK_PREP_INVENTORY = "upper_stack_ratification_readiness_inventory.json"
REMAINING_A_PLUS_GAPS = "remaining_a_plus_gap_ledger.json"

R1_RECEIPT = "crucible_pressure_law_ratification_receipt.json"
R2_RECEIPT = "adapter_lifecycle_law_ratification_receipt.json"
R3_RECEIPT = "tournament_promotion_merge_law_ratification_receipt.json"
R4_RECEIPT = "router_shadow_evaluation_ratification_receipt.json"
R5_RECEIPT = "router_vs_best_adapter_proof_ratification_receipt.json"
ROUTER_SUPERIORITY_SCORECARD = "router_superiority_scorecard.json"
ROUTER_ORDERED_PROOF = "router_ordered_proof_receipt.json"
UNIVERSAL_ADAPTER_RECEIPT = "universal_adapter_receipt.json"
ROUTER_LOBE_GAP_MATRIX = "router_lobe_gap_matrix.json"
ADAPTER_CIVILIZATION_GAP_MATRIX = "adapter_civilization_gap_matrix.json"
CURRENT_CAMPAIGN_STATE_OVERLAY = "current_campaign_state_overlay.json"

OUTPUT_PACKET = "upper_stack_ratification_readiness_authority_packet.json"
OUTPUT_DOMAIN_INVENTORY = "upper_stack_domain_inventory.json"
OUTPUT_STATUS_MATRIX = "upper_stack_ratification_status_matrix.json"
OUTPUT_BLOCKER_LEDGER = "upper_stack_blocker_ledger.json"
OUTPUT_NEXT_RECOMMENDATION = "upper_stack_next_ratification_lane_recommendation.json"
OUTPUT_RECEIPT = "upper_stack_ratification_readiness_receipt.json"

STATUS_CLASSES = [
    "CANONICAL_AND_RATIFIED",
    "CANONICAL_BUT_BOUNDED",
    "LAB_PROVISIONAL",
    "HISTORICAL_ONLY",
    "INTENDED_NOT_PROMOTED",
    "REJECTED_OR_QUARANTINED",
    "NEEDS_HUMAN_REVIEW",
]

RATIFICATION_ORDER = [
    "crucibles_pressure_law",
    "policy_c_pressure_taxonomy",
    "adapter_lifecycle",
    "tournament_promotion_merge_law",
    "router_shadow_proof",
    "learned_router_authorization",
    "multi_lobe_orchestration",
    "broader_comparative_proof",
]


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    common.ensure_pass(payload, label=label)


def _ensure_true(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if payload.get(key) is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must set {key}=true")


def _ensure_int(payload: Dict[str, Any], key: str, expected: int, *, label: str) -> None:
    try:
        value = int(payload[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"FAIL_CLOSED: {label} must declare integer {key}") from exc
    if value != expected:
        raise RuntimeError(f"FAIL_CLOSED: {label} expected {key}={expected}, got {value}")


def _load_json(root: Path, raw: Path | str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _hash_ref(path: Path, *, root: Path) -> Dict[str, str]:
    resolved = path.resolve()
    return {"path": resolved.relative_to(root.resolve()).as_posix(), "sha256": canonical_file_sha256(resolved)}


def _optional_hash_ref(path: Path, *, root: Path) -> Dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file():
        return {"path": resolved.relative_to(root.resolve()).as_posix(), "exists": False, "sha256": None}
    payload = _hash_ref(resolved, root=root)
    payload["exists"] = True
    return payload


def _evidence_refs(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, Any]]:
    refs = {
        "post_boundary_regrade": reports_root / POST_BOUNDARY_REGRADE,
        "next_lane_recommendation": reports_root / NEXT_LANE_RECOMMENDATION,
        "upper_stack_prep_inventory": reports_root / UPPER_STACK_PREP_INVENTORY,
        "remaining_a_plus_gaps": reports_root / REMAINING_A_PLUS_GAPS,
        "r1_crucible_pressure_law_receipt": reports_root / R1_RECEIPT,
        "r2_adapter_lifecycle_receipt": reports_root / R2_RECEIPT,
        "r3_tournament_promotion_merge_receipt": reports_root / R3_RECEIPT,
        "r4_router_shadow_receipt": reports_root / R4_RECEIPT,
        "r5_router_vs_best_adapter_receipt": reports_root / R5_RECEIPT,
        "router_superiority_scorecard": reports_root / ROUTER_SUPERIORITY_SCORECARD,
        "router_ordered_proof": reports_root / ROUTER_ORDERED_PROOF,
        "universal_adapter_receipt": reports_root / UNIVERSAL_ADAPTER_RECEIPT,
        "router_lobe_gap_matrix": reports_root / ROUTER_LOBE_GAP_MATRIX,
        "adapter_civilization_gap_matrix": reports_root / ADAPTER_CIVILIZATION_GAP_MATRIX,
        "current_campaign_state_overlay": reports_root / CURRENT_CAMPAIGN_STATE_OVERLAY,
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
        "readiness_scope_manifest": governance_root / "readiness_scope_manifest.json",
        "trust_zone_registry": governance_root / "trust_zone_registry.json",
        "r1_terminal_state": governance_root / "b04_r1_crucible_pressure_terminal_state.json",
        "r2_terminal_state": governance_root / "b04_r2_adapter_lifecycle_terminal_state.json",
        "r3_terminal_state": governance_root / "b04_r3_tournament_promotion_merge_terminal_state.json",
        "r4_terminal_state": governance_root / "b04_r4_router_shadow_terminal_state.json",
        "r5_terminal_state": governance_root / "b04_r5_router_vs_best_adapter_terminal_state.json",
        "crucible_lifecycle_law": governance_root / "crucible_lifecycle_law.json",
        "crucible_registry": governance_root / "crucible_registry.json",
        "pressure_response_taxonomy": governance_root / "pressure_response_taxonomy.json",
        "adapter_lifecycle_law": governance_root / "adapter_lifecycle_law.json",
        "adapter_registry": governance_root / "adapter_registry.json",
        "tournament_law": governance_root / "tournament_law.json",
        "promotion_engine_law": governance_root / "promotion_engine_law.json",
        "merge_law": governance_root / "merge_law.json",
        "router_policy_registry": governance_root / "router_policy_registry.json",
        "router_promotion_law": governance_root / "router_promotion_law.json",
        "lobe_role_registry": governance_root / "lobe_role_registry.json",
        "lobe_promotion_law": governance_root / "lobe_promotion_law.json",
    }
    return {
        key: (_optional_hash_ref(path, root=root) if key == "current_campaign_state_overlay" else _hash_ref(path, root=root))
        for key, path in refs.items()
    }


def _load_payloads(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, Any]]:
    names = {
        "post_boundary_regrade": reports_root / POST_BOUNDARY_REGRADE,
        "next_lane_recommendation": reports_root / NEXT_LANE_RECOMMENDATION,
        "upper_stack_prep_inventory": reports_root / UPPER_STACK_PREP_INVENTORY,
        "remaining_a_plus_gaps": reports_root / REMAINING_A_PLUS_GAPS,
        "r1_receipt": reports_root / R1_RECEIPT,
        "r2_receipt": reports_root / R2_RECEIPT,
        "r3_receipt": reports_root / R3_RECEIPT,
        "r4_receipt": reports_root / R4_RECEIPT,
        "r5_receipt": reports_root / R5_RECEIPT,
        "router_superiority_scorecard": reports_root / ROUTER_SUPERIORITY_SCORECARD,
        "router_ordered_proof": reports_root / ROUTER_ORDERED_PROOF,
        "universal_adapter_receipt": reports_root / UNIVERSAL_ADAPTER_RECEIPT,
        "router_lobe_gap_matrix": reports_root / ROUTER_LOBE_GAP_MATRIX,
        "adapter_civilization_gap_matrix": reports_root / ADAPTER_CIVILIZATION_GAP_MATRIX,
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
        "readiness_scope_manifest": governance_root / "readiness_scope_manifest.json",
        "trust_zone_registry": governance_root / "trust_zone_registry.json",
        "r1_terminal_state": governance_root / "b04_r1_crucible_pressure_terminal_state.json",
        "r2_terminal_state": governance_root / "b04_r2_adapter_lifecycle_terminal_state.json",
        "r3_terminal_state": governance_root / "b04_r3_tournament_promotion_merge_terminal_state.json",
        "r4_terminal_state": governance_root / "b04_r4_router_shadow_terminal_state.json",
        "r5_terminal_state": governance_root / "b04_r5_router_vs_best_adapter_terminal_state.json",
        "router_policy_registry": governance_root / "router_policy_registry.json",
        "lobe_role_registry": governance_root / "lobe_role_registry.json",
        "lobe_promotion_law": governance_root / "lobe_promotion_law.json",
    }
    return {key: _load_json(root, path, label=key) for key, path in names.items()}


def validate_inputs(*, payloads: Dict[str, Dict[str, Any]], live_validation: Dict[str, Any]) -> None:
    for key in [
        "post_boundary_regrade",
        "next_lane_recommendation",
        "upper_stack_prep_inventory",
        "remaining_a_plus_gaps",
        "r1_receipt",
        "r2_receipt",
        "r3_receipt",
        "r4_receipt",
        "r5_receipt",
        "router_superiority_scorecard",
        "router_ordered_proof",
        "universal_adapter_receipt",
        "router_lobe_gap_matrix",
        "adapter_civilization_gap_matrix",
    ]:
        _ensure_pass(payloads[key], label=key)

    regrade = payloads["post_boundary_regrade"]
    if str(regrade.get("next_lawful_move", "")).strip() != "AUTHOR_UPPER_STACK_RATIFICATION_READINESS_AUTHORITY_PACKET":
        raise RuntimeError("FAIL_CLOSED: post-boundary regrade must authorize upper-stack readiness")
    _ensure_int(regrade, "truth_engine_blocking_contradictions", 0, label="post-boundary regrade")
    _ensure_int(regrade, "truth_engine_advisory_contradictions", 0, label="post-boundary regrade")
    _ensure_int(regrade, "unknown_zone_queue_count", 0, label="post-boundary regrade")
    _ensure_int(regrade, "live_blocker_count", 0, label="post-boundary regrade")
    _ensure_true(regrade, "package_promotion_remains_deferred", label="post-boundary regrade")
    _ensure_true(regrade, "truth_engine_derivation_law_unchanged", label="post-boundary regrade")

    recommendation = payloads["next_lane_recommendation"]
    if str(recommendation.get("recommended_next_authoritative_lane", "")).strip() != "upper_stack_ratification_readiness":
        raise RuntimeError("FAIL_CLOSED: next-lane recommendation must name upper_stack_ratification_readiness")

    for key in ["router_lobe_gap_matrix", "adapter_civilization_gap_matrix"]:
        _ensure_true(payloads[key], "package_promotion_remains_deferred", label=key)
        _ensure_true(payloads[key], "truth_engine_derivation_law_unchanged", label=key)

    expected_chain = [
        ("r1_receipt", "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION"),
        ("r2_receipt", "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"),
        ("r3_receipt", "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"),
        ("r4_receipt", "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"),
        ("r5_receipt", "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"),
    ]
    for key, expected_next in expected_chain:
        if str(payloads[key].get("next_lawful_move", "")).strip() != expected_next:
            raise RuntimeError(f"FAIL_CLOSED: {key} must route to {expected_next}")

    r5_terminal = payloads["r5_terminal_state"]
    if r5_terminal.get("router_vs_best_adapter_proof_ratified") is not True:
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must ratify router-vs-best-adapter proof")
    if r5_terminal.get("learned_router_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must not authorize learned router")
    if str(r5_terminal.get("next_lawful_move", "")).strip() != "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF":
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must hold before B04_R6")

    scorecard = payloads["router_superiority_scorecard"]
    if scorecard.get("superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: current readiness court expects router superiority not yet earned")
    if str(scorecard.get("multi_lobe_promotion_status", "")).strip() != "BLOCKED_PENDING_LEARNED_ROUTER_WIN":
        raise RuntimeError("FAIL_CLOSED: multi-lobe promotion must remain blocked pending learned-router win")

    router_policy = payloads["router_policy_registry"]
    multi_lobe = router_policy.get("multi_lobe_orchestration_policy", {}) or {}
    if str(multi_lobe.get("current_status", "")).strip() != "BLOCKED_PENDING_LEARNED_ROUTER_WIN":
        raise RuntimeError("FAIL_CLOSED: router policy must block multi-lobe orchestration before learned-router win")

    if str(payloads["readiness_scope_manifest"].get("current_authority_mode", "")).strip() != "SETTLED_AUTHORITATIVE":
        raise RuntimeError("FAIL_CLOSED: readiness scope must remain settled authoritative")
    if str(live_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: live trust-zone validation must pass")
    if len(live_validation.get("checks", [])) != 24 or len(live_validation.get("failures", [])) != 0:
        raise RuntimeError("FAIL_CLOSED: live trust-zone validation must remain 24 checks / 0 failures")


def _prep_counts(prep: Dict[str, Any]) -> Dict[str, int]:
    classes = prep.get("classes", {}) if isinstance(prep.get("classes", {}), dict) else {}
    return {key: int(value.get("tracked_path_count", 0)) for key, value in classes.items() if isinstance(value, dict)}


def build_outputs(
    *,
    root: Path,
    reports_root: Path,
    governance_root: Path,
    branch_head: str,
    payloads: Dict[str, Dict[str, Any]],
    live_validation: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    generated_utc = utc_now_iso_z()
    evidence = _evidence_refs(root, reports_root, governance_root)
    prep_counts = _prep_counts(payloads["upper_stack_prep_inventory"])
    checks = live_validation.get("checks", [])
    failures = live_validation.get("failures", [])
    overlay_available = (reports_root / CURRENT_CAMPAIGN_STATE_OVERLAY).resolve().is_file()
    next_move = NEXT_MOVE_R6 if overlay_available else NEXT_MOVE_REVALIDATION_ASSET
    next_lane = NEXT_LANE_R6 if overlay_available else NEXT_LANE_REVALIDATION_ASSET
    r1_r5_revalidation_replay_status = "READY_FOR_ACTIVE_REPLAY" if overlay_available else "BLOCKED_MISSING_CURRENT_CAMPAIGN_STATE_OVERLAY"
    r1_r5_status_class = "CANONICAL_AND_RATIFIED" if overlay_available else "CANONICAL_BUT_BOUNDED"
    r1_r5_stage_suffix = "REPLAY_READY" if overlay_available else "RECEIPT_PASS_REVALIDATION_BLOCKED"

    common_header = {
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
    }

    domain_rows: List[Dict[str, Any]] = [
        {
            "domain_id": "crucibles_pressure_law",
            "display_name": "Crucibles / pressure law",
            "status_class": r1_r5_status_class,
            "ratification_stage": f"B04_R1_{r1_r5_stage_suffix}",
            "source_refs": ["r1_crucible_pressure_law_receipt", "crucible_lifecycle_law", "crucible_registry"],
            "readiness_summary": "R1 pressure-law receipt is PASS; active validator replay is bounded by the current overlay asset status.",
            "tracked_path_count_hint": prep_counts.get("crucibles_policy_c", 0),
            "may_drive_live_posture": True,
        },
        {
            "domain_id": "policy_c_pressure_taxonomy",
            "display_name": "Policy C / pressure taxonomy",
            "status_class": "CANONICAL_BUT_BOUNDED",
            "ratification_stage": "FOUNDATION_READY",
            "source_refs": ["pressure_response_taxonomy", "r1_crucible_pressure_law_receipt"],
            "readiness_summary": "Canonical pressure taxonomy exists, but upper-stack readiness may not imply full adaptive-stack capability.",
            "tracked_path_count_hint": prep_counts.get("crucibles_policy_c", 0),
            "may_drive_live_posture": False,
        },
        {
            "domain_id": "epochs",
            "display_name": "Epochs / ordered cycles",
            "status_class": "LAB_PROVISIONAL",
            "ratification_stage": "NOT_YET_PROMOTED",
            "source_refs": ["upper_stack_prep_inventory"],
            "readiness_summary": "Epoch/orchestrator surfaces exist as lab/proving machinery, not as live upper-stack authority.",
            "tracked_path_count_hint": 0,
            "may_drive_live_posture": False,
        },
        {
            "domain_id": "adapter_lifecycle",
            "display_name": "Adapters / lifecycle law",
            "status_class": r1_r5_status_class,
            "ratification_stage": f"B04_R2_{r1_r5_stage_suffix}",
            "source_refs": ["r2_adapter_lifecycle_receipt", "adapter_lifecycle_law", "adapter_registry"],
            "readiness_summary": "R2 adapter lifecycle law is PASS; broad adapter civilization remains bounded by promotion law.",
            "tracked_path_count_hint": prep_counts.get("adapters", 0),
            "may_drive_live_posture": True,
        },
        {
            "domain_id": "adapter_forge_training",
            "display_name": "Adapter forge / learning loops / hypertraining",
            "status_class": "LAB_PROVISIONAL",
            "ratification_stage": "NOT_YET_PROMOTED",
            "source_refs": ["adapter_civilization_gap_matrix", "upper_stack_prep_inventory"],
            "readiness_summary": "Forge/training surfaces are useful prep but do not authorize product, router, or lobe claims.",
            "tracked_path_count_hint": prep_counts.get("forge_training", 0),
            "may_drive_live_posture": False,
        },
        {
            "domain_id": "tournament_promotion_merge_law",
            "display_name": "Tournament / promotion / merge law",
            "status_class": r1_r5_status_class,
            "ratification_stage": f"B04_R3_{r1_r5_stage_suffix}",
            "source_refs": ["r3_tournament_promotion_merge_receipt"],
            "readiness_summary": "R3 law is PASS and can govern future promotion, but does not itself authorize learned-router or lobe promotion.",
            "tracked_path_count_hint": prep_counts.get("tournaments_promotion_merge", 0),
            "may_drive_live_posture": True,
        },
        {
            "domain_id": "router_shadow_proof",
            "display_name": "Router shadow proof / static router boundary",
            "status_class": "CANONICAL_BUT_BOUNDED",
            "ratification_stage": f"B04_R4_R5_STATIC_HOLD_{r1_r5_stage_suffix}",
            "source_refs": ["r4_router_shadow_receipt", "r5_router_vs_best_adapter_receipt", "router_ordered_proof"],
            "readiness_summary": "R4/R5 are PASS, but the router remains bounded; R6 is held until learned-router superiority is earned.",
            "tracked_path_count_hint": prep_counts.get("router_lobes", 0),
            "may_drive_live_posture": True,
        },
        {
            "domain_id": "learned_router_authorization",
            "display_name": "Learned router authorization",
            "status_class": "INTENDED_NOT_PROMOTED",
            "ratification_stage": "B04_R6_BLOCKED",
            "source_refs": ["router_superiority_scorecard", "r5_terminal_state", "router_policy_registry"],
            "readiness_summary": "B04_R6 remains blocked; resolve active R1-R5 revalidation asset status before attempting superiority-blocker resolution.",
            "tracked_path_count_hint": prep_counts.get("router_lobes", 0),
            "may_drive_live_posture": False,
        },
        {
            "domain_id": "multi_lobe_orchestration",
            "display_name": "Lobes / multi-lobe orchestration",
            "status_class": "INTENDED_NOT_PROMOTED",
            "ratification_stage": "B04_R7_BLOCKED_AFTER_R6",
            "source_refs": ["lobe_role_registry", "lobe_promotion_law", "router_lobe_gap_matrix"],
            "readiness_summary": "Lobe law and role registry exist, but multi-lobe promotion is blocked pending learned-router win.",
            "tracked_path_count_hint": prep_counts.get("router_lobes", 0),
            "may_drive_live_posture": False,
        },
        {
            "domain_id": "universal_adapter",
            "display_name": "Universal adapter",
            "status_class": "CANONICAL_BUT_BOUNDED",
            "ratification_stage": "BOUNDED_VALIDATION_PRESENT",
            "source_refs": ["universal_adapter_receipt", "adapter_civilization_gap_matrix"],
            "readiness_summary": "Universal-adapter validation exists, but not broad plug-any-model civilization authority.",
            "tracked_path_count_hint": prep_counts.get("adapters", 0),
            "may_drive_live_posture": False,
        },
        {
            "domain_id": "chaos_adversarial_pressure",
            "display_name": "Chaos / adversarial pressure",
            "status_class": "LAB_PROVISIONAL",
            "ratification_stage": "PREP_ONLY",
            "source_refs": ["upper_stack_prep_inventory"],
            "readiness_summary": "Adversarial pressure surfaces support future ratification but do not currently promote upper-stack authority.",
            "tracked_path_count_hint": prep_counts.get("crucibles_policy_c", 0),
            "may_drive_live_posture": False,
        },
        {
            "domain_id": "broader_comparative_proof",
            "display_name": "Broader comparative proof",
            "status_class": "INTENDED_NOT_PROMOTED",
            "ratification_stage": "TRACK_01_BOUNDED_ONLY",
            "source_refs": ["remaining_a_plus_gaps"],
            "readiness_summary": "Track 01 bounded proof remains real; broader comparative proof is still an open A+ gap.",
            "tracked_path_count_hint": 0,
            "may_drive_live_posture": False,
        },
    ]

    status_matrix = [
        {
            "domain_id": row["domain_id"],
            "status_class": row["status_class"],
            "ratification_stage": row["ratification_stage"],
            "may_become_authoritative_now": row["domain_id"] == "learned_router_authorization" and overlay_available,
            "authority_condition": (
                (
                    "Only a blocker-resolution lane may open now; B04_R6 authorization remains unavailable until superiority_earned=true."
                    if overlay_available
                    else "Repair or supersede the R1-R5 active revalidation overlay asset before any B04_R6 blocker-resolution lane may open."
                )
                if row["domain_id"] == "learned_router_authorization"
                else "No new authority promotion from this readiness packet."
            ),
            "source_refs": row["source_refs"],
        }
        for row in domain_rows
    ]

    blocker_entries: List[Dict[str, Any]] = []
    if not overlay_available:
        blocker_entries.append(
            {
                "blocker_id": "B04_R1_R5_ACTIVE_REVALIDATION_OVERLAY_MISSING",
                "severity": "BLOCKS_NEXT_RATIFICATION",
                "blocked_domain": "learned_router_authorization",
                "evidence": [
                    "current_campaign_state_overlay",
                    "r1_crucible_pressure_law_receipt",
                    "r5_router_vs_best_adapter_receipt",
                ],
                "resolution_path": NEXT_MOVE_REVALIDATION_ASSET,
            }
        )
    blocker_entries.extend(
        [
            {
                "blocker_id": "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED",
                "severity": "BLOCKS_NEXT_RATIFICATION" if overlay_available else "BLOCKS_AFTER_REVALIDATION_ASSET",
                "blocked_domain": "learned_router_authorization",
                "evidence": ["router_superiority_scorecard", "r5_router_vs_best_adapter_receipt", "r5_terminal_state"],
                "resolution_path": NEXT_MOVE_R6,
            },
            {
                "blocker_id": "B04_R7_MULTI_LOBE_ORCHESTRATION_BLOCKED_PENDING_LEARNED_ROUTER_WIN",
                "severity": "BLOCKS_DOWNSTREAM_RATIFICATION",
                "blocked_domain": "multi_lobe_orchestration",
                "evidence": ["router_policy_registry", "lobe_promotion_law"],
                "resolution_path": "Do not open lobe ratification until B04_R6 is earned and authorized.",
            },
            {
                "blocker_id": "BROAD_COMPARATIVE_PROOF_REMAINS_OPEN_A_PLUS_GAP",
                "severity": "BLOCKS_BROAD_CLAIMS",
                "blocked_domain": "broader_comparative_proof",
                "evidence": ["remaining_a_plus_gaps"],
                "resolution_path": "Open only after ordered router/lobe status is settled or explicitly bounded.",
            },
        ]
    )

    packet = {
        **common_header,
        "schema_id": "kt.operator.upper_stack_ratification_readiness_authority_packet.v1",
        "outcome": OUTCOME,
        "authoritative_lane": REQUIRED_BRANCH,
        "branch_head": branch_head,
        "allowed_status_classes": STATUS_CLASSES,
        "required_ratification_order": RATIFICATION_ORDER,
        "non_claim_boundaries": [
            "does_not_ratify_full_civilization_stack",
            "does_not_claim_router_or_lobe_superiority",
            "does_not_open_broad_product_truth",
            "does_not_promote_lab_artifacts",
            "does_not_change_package_promotion",
            "does_not_supersede_truth_engine_or_trust_zone_law",
        ],
        "evidence_refs": evidence,
        "required_outputs": [
            OUTPUT_PACKET,
            OUTPUT_DOMAIN_INVENTORY,
            OUTPUT_STATUS_MATRIX,
            OUTPUT_BLOCKER_LEDGER,
            OUTPUT_NEXT_RECOMMENDATION,
            OUTPUT_RECEIPT,
        ],
        "active_revalidation_asset_status": r1_r5_revalidation_replay_status,
        "next_lawful_move": next_move,
    }
    domain_inventory = {
        **common_header,
        "schema_id": "kt.operator.upper_stack_domain_inventory.v1",
        "outcome": "UPPER_STACK_DOMAIN_INVENTORY_BOUND",
        "domain_count": len(domain_rows),
        "domains": domain_rows,
        "active_revalidation_asset_status": r1_r5_revalidation_replay_status,
        "next_lawful_move": next_move,
    }
    matrix = {
        **common_header,
        "schema_id": "kt.operator.upper_stack_ratification_status_matrix.v1",
        "outcome": "UPPER_STACK_RATIFICATION_STATUS_MATRIX_BOUND",
        "status_classes": STATUS_CLASSES,
        "ratification_order": RATIFICATION_ORDER,
        "rows": status_matrix,
        "active_revalidation_asset_status": r1_r5_revalidation_replay_status,
        "next_lawful_move": next_move,
    }
    blocker_ledger = {
        **common_header,
        "schema_id": "kt.operator.upper_stack_blocker_ledger.v1",
        "outcome": "UPPER_STACK_BLOCKERS_BOUND",
        "live_blocker_count": 0,
        "ratification_blocker_count": len(blocker_entries),
        "entries": blocker_entries,
        "active_revalidation_asset_status": r1_r5_revalidation_replay_status,
        "next_lawful_move": next_move,
    }
    recommendation = {
        **common_header,
        "schema_id": "kt.operator.upper_stack_next_ratification_lane_recommendation.v1",
        "outcome": "B04_REVALIDATION_ASSET_SUPERSESSION_RECOMMENDED" if not overlay_available else "B04_R6_BLOCKER_RESOLUTION_RECOMMENDED",
        "recommended_next_authoritative_lane": next_lane,
        "recommended_next_move": next_move,
        "why": [
            "R1 through R5 are already PASS in the active evidence chain.",
            "Active R1-R5 validator replay currently depends on current_campaign_state_overlay.json.",
            "R5 terminal state explicitly blocks learned-router authorization.",
            "router_superiority_scorecard.superiority_earned is false.",
            "multi-lobe orchestration remains blocked pending learned-router win.",
        ],
        "forbidden_next_lanes": [
            "multi_lobe_orchestration_ratification",
            "broad_comparative_superiority",
            "commercial_product_expansion",
            "package_promotion",
        ],
        "active_revalidation_asset_status": r1_r5_revalidation_replay_status,
        "next_lawful_move": next_move,
    }
    receipt = {
        **common_header,
        "schema_id": "kt.operator.upper_stack_ratification_readiness_receipt.v1",
        "outcome": OUTCOME,
        "branch_head": branch_head,
        "domain_count": len(domain_rows),
        "status_class_count": len(STATUS_CLASSES),
        "ratification_order_count": len(RATIFICATION_ORDER),
        "r1_through_r5_receipt_chain_pass": True,
        "r1_through_r5_active_revalidation_replay_status": r1_r5_revalidation_replay_status,
        "r6_authorization_status": "BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF",
        "live_blocker_count": 0,
        "ratification_blocker_count": len(blocker_entries),
        "trust_zone_validation_status": live_validation["status"],
        "trust_zone_validation_check_count": len(checks),
        "trust_zone_validation_failure_count": len(failures),
        "recommended_next_authoritative_lane": next_lane,
        "next_lawful_move": next_move,
    }
    return {
        "packet": packet,
        "domain_inventory": domain_inventory,
        "status_matrix": matrix,
        "blocker_ledger": blocker_ledger,
        "recommendation": recommendation,
        "receipt": receipt,
    }


def run(*, reports_root: Path, governance_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before upper-stack readiness run")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: upper-stack readiness must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: upper-stack readiness must read canonical governance root only")

    payloads = _load_payloads(root, reports_root.resolve(), governance_root.resolve())
    live_validation = validate_trust_zones(root=root)
    validate_inputs(payloads=payloads, live_validation=live_validation)
    outputs = build_outputs(
        root=root,
        reports_root=reports_root.resolve(),
        governance_root=governance_root.resolve(),
        branch_head=common.git_rev_parse(root, "HEAD"),
        payloads=payloads,
        live_validation=live_validation,
    )
    for filename, key in [
        (OUTPUT_PACKET, "packet"),
        (OUTPUT_DOMAIN_INVENTORY, "domain_inventory"),
        (OUTPUT_STATUS_MATRIX, "status_matrix"),
        (OUTPUT_BLOCKER_LEDGER, "blocker_ledger"),
        (OUTPUT_NEXT_RECOMMENDATION, "recommendation"),
        (OUTPUT_RECEIPT, "receipt"),
    ]:
        write_json_stable((reports_root / filename).resolve(), outputs[key])
    return {"outcome": OUTCOME, "next_lawful_move": outputs["receipt"]["next_lawful_move"]}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Author the upper-stack ratification readiness authority packet.")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
