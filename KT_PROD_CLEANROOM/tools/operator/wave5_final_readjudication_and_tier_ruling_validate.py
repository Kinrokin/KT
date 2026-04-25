from __future__ import annotations

import argparse
import json
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.observability import emit_toolchain_telemetry, telemetry_now_ms
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WAVE_ID = "WAVE_5_FINAL_READJUDICATION_AND_TIER_RULING"
WORK_ORDER_ID = "KT_UNIFIED_CONVERGENCE_MAX_POWER_CAMPAIGN_V2_1_1_FINAL"
CANONICAL_KERNEL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py"

STATE_CORE_REL = f"{REPORT_ROOT_REL}/kt_wave5_state_core.json"
BLOCKER_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave5_blocker_matrix.json"
RUNTIME_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_runtime_truth_surface.json"
VERIFIER_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_verifier_truth_surface.json"
RELEASE_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_release_truth_surface.json"
PRODUCT_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_product_truth_surface.json"
CLAIM_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave5_final_claim_class_matrix.json"
TIER_RULING_REL = f"{REPORT_ROOT_REL}/kt_wave5_final_tier_ruling.json"
GAP_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_wave5_remaining_gap_register.json"
DISPOSITION_REL = f"{REPORT_ROOT_REL}/kt_wave5_updated_surface_disposition_register.json"
MAIN_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave5_final_readjudication_receipt.json"
TELEMETRY_REL = f"{REPORT_ROOT_REL}/kt_wave5_readjudication_telemetry.jsonl"

EXECUTION_REPORT_REL = f"{REPORT_ROOT_REL}/kt_unified_convergence_execution_report_v2_1_1.json"
PASS_FAIL_REL = f"{REPORT_ROOT_REL}/kt_unified_convergence_pass_fail_gate_matrix.json"
TRUTH_MAP_REL = f"{REPORT_ROOT_REL}/kt_unified_convergence_current_truth_map.json"
RUNTIME_MAP_REL = f"{REPORT_ROOT_REL}/kt_unified_convergence_runtime_reality_map.json"
CONTRADICTION_TABLE_REL = f"{REPORT_ROOT_REL}/kt_unified_convergence_contradiction_table.json"
LIVE_VALIDATION_WAVE4_REL = f"{REPORT_ROOT_REL}/live_validation_index.wave4.json"
LIVE_VALIDATION_WAVE5_REL = f"{REPORT_ROOT_REL}/live_validation_index.wave5.json"

WAVE3_RUN_REL = f"{REPORT_ROOT_REL}/kt_wave3_minimum_viable_civilization_run_pack.json"
WAVE3_DETACHED_REL = f"{REPORT_ROOT_REL}/kt_wave3_detached_verifier_receipt.json"
WAVE3_CLAIM_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave3_claim_class_matrix.json"
WAVE4_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave4_chaos_and_external_challenge_receipt.json"
WAVE4_PUBLIC_REL = f"{REPORT_ROOT_REL}/kt_wave4_public_challenge_receipt.json"
WAVE4_EXTERNALITY_REL = f"{REPORT_ROOT_REL}/kt_wave4_externality_class_matrix.json"
WAVE2C_DISPOSITION_REL = f"{REPORT_ROOT_REL}/kt_wave2c_organ_disposition_register.json"
RELEASE_ACTIVATION_REL = f"{REPORT_ROOT_REL}/kt_release_activation_receipt.json"
PRODUCT_WEDGE_REL = f"{REPORT_ROOT_REL}/kt_product_wedge_activation_receipt.json"
C007_CANON_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave0_5_package_import_canon_receipt.json"
C016A_SUCCESS_REL = f"{REPORT_ROOT_REL}/post_wave5_c016a_success_matrix.json"
C016B_RESILIENCE_REL = f"{REPORT_ROOT_REL}/post_wave5_c016b_resilience_pack.json"
C005_ROUTER_SELECTION_REL = f"{REPORT_ROOT_REL}/kt_wave2b_router_selection_receipt.json"
C005_ROUTER_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave2b_router_shadow_eval_matrix.json"
C005_ROUTER_HEALTH_REL = f"{REPORT_ROOT_REL}/kt_wave2b_route_distribution_health.json"
POST_WAVE5_C005_RATIFICATION_REL = f"{REPORT_ROOT_REL}/post_wave5_c005_router_ratification_receipt.json"
POST_WAVE5_C006_PREP_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_trust_prep_receipt.json"

C005_ID = "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION"
C006_ID = "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
C007_ID = "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED"
C016_ID = "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE"


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _open_contradiction_rows(contradiction_table: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for row in contradiction_table.get("rows", []):
        if str(row.get("state", "")).strip().upper().startswith("OPEN"):
            rows.append(dict(row))
    return rows


def _open_contradiction_ids(contradiction_table: Dict[str, Any]) -> List[str]:
    return [str(row.get("contradiction_id", "")).strip() for row in _open_contradiction_rows(contradiction_table)]


def _is_pass(payload: Dict[str, Any]) -> bool:
    return str(payload.get("status", "")).strip().upper() == "PASS"


def _c016a_closed(payload: Dict[str, Any]) -> bool:
    if not _is_pass(payload):
        return False
    if str(payload.get("c016a_delta", "")).strip() != "C016A_CLOSED_FOR_CANONICAL_LIVE_HASHED_LANE":
        return False
    rows = payload.get("provider_rows", [])
    return bool(rows) and all(
        isinstance(row, dict)
        and str(row.get("status", "")).strip() == "OK"
        and bool(row.get("receipt_exists"))
        for row in rows
    )


def _c016b_closed(payload: Dict[str, Any]) -> bool:
    return (
        _is_pass(payload)
        and str(payload.get("c016b_delta", "")).strip() == "C016B_CLOSED_FOR_CANONICAL_LIVE_HASHED_RESILIENCE_PATH"
        and str(payload.get("repeatability_status", "")).strip().upper() == "PASS"
    )


def _c005_router_refreshed(selection: Dict[str, Any], matrix: Dict[str, Any], health: Dict[str, Any]) -> bool:
    provider_context = selection.get("provider_underlay_context", {})
    return (
        _is_pass(selection)
        and _is_pass(matrix)
        and _is_pass(health)
        and str(selection.get("ratification_scope", "")).strip() == "STATIC_ROUTER_BASELINE_ONLY"
        and str(provider_context.get("provider_report_ref", "")).strip() == C016A_SUCCESS_REL
        and bool(provider_context.get("same_host_live_hashed_success_proven"))
        and bool(provider_context.get("same_host_live_hashed_resilience_proven"))
        and bool(matrix.get("promotion_decision", {}).get("canonical_router_unchanged"))
        and not bool(matrix.get("promotion_decision", {}).get("learned_router_cutover_allowed"))
        and float(health.get("shadow_match_rate", 0.0)) == 1.0
        and int(health.get("route_distribution_delta_count", -1)) == 0
    )


def _c005_ratified_hold(payload: Dict[str, Any]) -> bool:
    return (
        _is_pass(payload)
        and str(payload.get("c005_delta", "")).strip() == "C005_CLOSED_BY_HONEST_STATIC_ROUTER_RATIFICATION_HOLD"
        and str(payload.get("ratification_decision", "")).strip() == "HOLD_STATIC_CANONICAL_BASELINE"
        and str(payload.get("exact_superiority_outcome", "")).strip() == "NOT_EARNED_SHADOW_MATCHES_STATIC_BASELINE"
        and float(payload.get("comparison_metrics", {}).get("shadow_match_rate", 0.0)) == 1.0
        and int(payload.get("comparison_metrics", {}).get("route_distribution_delta_count", -1)) == 0
    )


def _c006_prep_ready(payload: Dict[str, Any]) -> bool:
    return (
        _is_pass(payload)
        and str(payload.get("c006_status", "")).strip() == "OPEN_PREPARED_NOT_PROMOTED"
        and str(payload.get("current_externality_ceiling", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
        and str(payload.get("blocker_delta", "")).strip() == "C006_PREPARED_FOR_FRIENDLY_CROSS_HOST_PROOF_PATH_BUT_NOT_PROMOTED"
    )


def _rebind_current_head_contradiction_table(
    *,
    base_table: Dict[str, Any],
    head: str,
    c007_receipt: Dict[str, Any],
    c016a_receipt: Dict[str, Any],
    c016b_receipt: Dict[str, Any],
    c005_selection: Dict[str, Any],
    c005_matrix: Dict[str, Any],
    c005_health: Dict[str, Any],
    c005_ratification: Dict[str, Any],
    c006_prep: Dict[str, Any],
) -> Dict[str, Any]:
    table = deepcopy(base_table)
    table["generated_utc"] = utc_now_iso_z()
    table["current_git_head"] = head

    for raw_row in table.get("rows", []):
        if not isinstance(raw_row, dict):
            continue
        contradiction_id = str(raw_row.get("contradiction_id", "")).strip()
        if contradiction_id == C007_ID and _is_pass(c007_receipt):
            raw_row.pop("evidence_ref", None)
            raw_row.pop("evidence_refs", None)
            raw_row["resolution_receipt"] = C007_CANON_RECEIPT_REL
            raw_row["state"] = "RESOLVED_POST_WAVE5_CANONICAL_RUNTIME_INSTALL_LANE"
            raw_row["summary"] = (
                "Canonical runtime package/import parity is now proven for repo-root, cleanroom-root, "
                "and isolated editable-install execution. Stronger wheel/sdist, hermetic, and detached "
                "source-independent packaging claims remain unearned."
            )
        elif contradiction_id == C016_ID and _c016a_closed(c016a_receipt) and _c016b_closed(c016b_receipt):
            raw_row.pop("evidence_ref", None)
            raw_row.pop("evidence_refs", None)
            raw_row["resolution_receipts"] = [C016A_SUCCESS_REL, C016B_RESILIENCE_REL]
            raw_row["state"] = "RESOLVED_POST_WAVE5_CANONICAL_SAME_HOST_LIVE_HASHED"
            raw_row["summary"] = (
                "Successful authenticated live-provider execution and same-host resilience are proven for the "
                "canonical LIVE_HASHED OpenAI/OpenRouter lane with signed receipts. This does not raise "
                "externality above E1 or prove broader provider coverage."
            )
        elif contradiction_id == C005_ID and _c005_ratified_hold(c005_ratification):
            raw_row.pop("evidence_ref", None)
            raw_row["evidence_refs"] = [
                POST_WAVE5_C005_RATIFICATION_REL,
                C005_ROUTER_SELECTION_REL,
                C005_ROUTER_MATRIX_REL,
                C005_ROUTER_HEALTH_REL,
                C016A_SUCCESS_REL,
                C016B_RESILIENCE_REL,
            ]
            raw_row["state"] = "RESOLVED_POST_WAVE5_STATIC_BASELINE_RATIFIED_HOLD"
            raw_row["summary"] = (
                "C005 is closed by honest router ratification: the audited static router is now explicitly "
                "ratified as canonical current-head control, shadow evidence reproduces the fenced static "
                "baseline exactly, fallback evidence is preserved, best-static comparator control remains "
                "explicit, and learned routing plus multi-lobe promotion stay blocked until new superiority "
                "evidence is earned."
            )
        elif contradiction_id == C005_ID and _c005_router_refreshed(c005_selection, c005_matrix, c005_health):
            raw_row.pop("evidence_ref", None)
            raw_row["evidence_refs"] = [
                C005_ROUTER_SELECTION_REL,
                C005_ROUTER_MATRIX_REL,
                C005_ROUTER_HEALTH_REL,
                C016A_SUCCESS_REL,
                C016B_RESILIENCE_REL,
            ]
            raw_row["state"] = "OPEN_CURRENT_HEAD_STATIC_CONTROL_REFRESHED_POST_WAVE5"
            raw_row["summary"] = (
                "Router ratification is refreshed against the current-head same-host LIVE_HASHED provider lane: "
                "the audited static router remains canonical, shadow routing exactly matches the fenced static "
                "baseline, fallback evidence is preserved, and best-static comparator control is explicit. "
                "Learned routing and multi-lobe promotion remain unearned."
            )
        elif contradiction_id == C006_ID and _c006_prep_ready(c006_prep):
            raw_row.pop("evidence_ref", None)
            raw_row["evidence_refs"] = [
                POST_WAVE5_C006_PREP_REL,
                WAVE3_DETACHED_REL,
                f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json",
                f"{REPORT_ROOT_REL}/kt_external_reproduction_receipt.json",
                f"{REPORT_ROOT_REL}/kt_outsider_path_receipt.json",
                WAVE4_EXTERNALITY_REL,
                VERIFIER_TRUTH_REL,
            ]
            raw_row["state"] = "OPEN_PREPARED_POST_WAVE5_E1_CEILING_ONLY"
            raw_row["summary"] = (
                "C006 is now prep-ready but not promoted: same-host detached verifier parity, same-host "
                "independent clean-environment replay, secret-free outsider verifier tooling, trust-zone "
                "boundaries, and the Wave 5 verifier truth surface are all present, while externality remains "
                "bounded at E1 until fresh cross-host proof is earned."
            )
    return table


def _state_core_open_gates(contradiction_table: Dict[str, Any]) -> List[str]:
    open_ids = set(_open_contradiction_ids(contradiction_table))
    gates = [
        "current_head_external_capability_not_confirmed",
        "externality_above_E1_not_confirmed",
    ]
    if C005_ID in open_ids:
        gates.append("learned_router_cutover_not_earned")
    if C007_ID in open_ids:
        gates.append("repo_root_import_fragility_visible_and_unfixed")
    if C016_ID in open_ids:
        gates.append("successful_authenticated_remote_provider_inference_not_confirmed")
    return gates


def _missing_proof_map() -> Dict[str, str]:
    return {
        C005_ID: "To raise above the static-router bounded class, KT must complete the learned-router ratification order on current head with shadow-to-cutover promotion evidence, best-static comparison, canonical cutover receipts, and no-regression proof.",
        C006_ID: "To rise above E1, KT must earn the higher externality class directly: E2 cross-host friendly replay, E3 independent hostile replay, or E4 public challenge survival.",
        C007_ID: "To close repo-root import fragility, KT must prove canonical package/import behavior across the declared repo-root surfaces and remove or lawfully bind the remaining ambiguous repo-root resolution paths.",
        C016_ID: "To narrow the live-provider contradiction, KT must produce successful authenticated current-head live provider inference receipts on the canonical ABI-bound lane without widening externality or router claims.",
    }


def _build_state_core(
    *,
    head: str,
    contradiction_table: Dict[str, Any],
    wave3_run: Dict[str, Any],
    wave3_detached: Dict[str, Any],
    wave4_receipt: Dict[str, Any],
    wave4_public: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.wave5.state_core.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "current_head_truth_id": f"kt.wave5.state_core::{head}",
        "status": "PASS",
        "highest_lawful_wave_reached": WAVE_ID,
        "canonical_kernel": CANONICAL_KERNEL,
        "canonical_router_status": "STATIC_CANONICAL_BASELINE_ONLY",
        "minimum_viable_organism_status": str(wave3_run.get("status", "")).strip(),
        "detached_verifier_status": str(wave3_detached.get("status", "")).strip(),
        "challenge_lane_status": str(wave4_receipt.get("status", "")).strip(),
        "externality_ceiling": str(wave4_public.get("externality_ceiling_after_wave4", "E1_SAME_HOST_DETACHED_REPLAY")).strip(),
        "current_head_posture": "SCOPED_BOUNDED_CURRENT_HEAD_ORGANISM_E1_FINAL_READJUDICATED",
        "open_stop_gates": _state_core_open_gates(contradiction_table),
        "remaining_open_contradictions": _open_contradiction_ids(contradiction_table),
        "source_refs": {
            "wave3_run": WAVE3_RUN_REL,
            "wave3_detached_verifier": WAVE3_DETACHED_REL,
            "wave4_receipt": WAVE4_RECEIPT_REL,
            "wave4_public_challenge": WAVE4_PUBLIC_REL,
            "contradiction_table": CONTRADICTION_TABLE_REL,
        },
        "supersedes_refs": [
            f"{REPORT_ROOT_REL}/kt_state_vector_v2.json",
            f"{REPORT_ROOT_REL}/kt_final_current_head_readjudication_receipt.json",
        ],
        "stronger_claim_not_made": [
            "broad_current_head_external_capability_confirmed",
            "learned_router_cutover_occurred",
            "broad_live_provider_capability_beyond_canonical_same_host_lane_claimed",
            "externality_class_above_E1_claimed",
            "product_or_commercial_language_widened",
        ],
    }


def _build_blocker_matrix(*, head: str, contradiction_table: Dict[str, Any]) -> Dict[str, Any]:
    proof_map = _missing_proof_map()
    open_blockers = []
    for row in _open_contradiction_rows(contradiction_table):
        contradiction_id = str(row.get("contradiction_id", "")).strip()
        open_blockers.append(
            {
                "blocker_id": contradiction_id,
                "severity": str(row.get("severity", "")).strip(),
                "state": str(row.get("state", "")).strip(),
                "summary": str(row.get("summary", "")).strip(),
                "missing_proof_to_close": proof_map.get(contradiction_id, "Explicit closure proof not yet defined."),
            }
        )
    return {
        "schema_id": "kt.wave5.blocker_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "status": "PASS",
        "matrix_status": "OPEN_BLOCKERS_PRESENT",
        "open_blocker_count": len(open_blockers),
        "open_blockers": open_blockers,
        "blocked_promotions": [
            "learned_router_cutover",
            "externality_class_above_E1",
            "broad_live_provider_or_externality_claims",
            "commercial_or_enterprise_readiness_claims",
            "comparative_or_superiority_claims",
        ],
        "supersedes_refs": [
            f"{REPORT_ROOT_REL}/kt_blocker_matrix_v2.json",
            f"{REPORT_ROOT_REL}/kt_final_blocker_matrix.json",
        ],
    }


def _build_runtime_truth_surface(
    *,
    head: str,
    wave3_run: Dict[str, Any],
    contradiction_table: Dict[str, Any],
    c016a_receipt: Dict[str, Any],
    c016b_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    open_ids = _open_contradiction_ids(contradiction_table)
    provider_boundary = str(wave3_run.get("canonical_run", {}).get("adapter_provider_boundary", "")).strip()
    if _c016a_closed(c016a_receipt) and _c016b_closed(c016b_receipt):
        provider_boundary = (
            "Canonical run proves adapter invocation through the static DRY_RUN council execute lane, and "
            "Post-Wave5 now proves successful authenticated same-host LIVE_HASHED execution plus resilience "
            "for the canonical OpenAI/OpenRouter lane. This does not prove cross-host replay, outsider "
            "verification, or learned-router superiority."
        )
    return {
        "schema_id": "kt.wave5.runtime_truth_surface.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "status": "PASS",
        "runtime_truth_class": "CURRENT_HEAD_PARTIALLY_PROVEN_MINIMUM_VIABLE_ORGANISM_RUN",
        "minimum_viable_organism_run_status": str(wave3_run.get("status", "")).strip(),
        "exact_end_to_end_path_exercised": list(wave3_run.get("exact_end_to_end_path_exercised", [])),
        "canonical_router_status": "STATIC_CANONICAL_BASELINE_ONLY",
        "adapter_provider_boundary": provider_boundary,
        "organ_realization_boundary": "Council, cognition, paradox, temporal, and multiverse are realized as bounded current-head organs. Wave 3 proves one canonical organism lane; it does not prove universal live-provider success or learned-router superiority.",
        "open_runtime_contradictions": [
            row
            for row in open_ids
            if row
            in {
                C005_ID,
                C007_ID,
                C016_ID,
            }
        ],
        "source_refs": [WAVE3_RUN_REL, WAVE2C_DISPOSITION_REL, CONTRADICTION_TABLE_REL],
        "stronger_claim_not_made": [
            "learned_router_cutover_occurred",
            "cross_host_or_outsider_live_provider_confirmation_claimed",
            "broad_current_head_external_runtime_capability_confirmed",
            "multi_lobe_or_router_superiority_claimed",
        ],
    }


def _build_verifier_truth_surface(
    *,
    head: str,
    wave3_detached: Dict[str, Any],
    wave4_externality: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.wave5.verifier_truth_surface.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "status": "PASS",
        "verifier_truth_class": "CURRENT_HEAD_PROVEN_DETACHED_SAME_HOST_PACKAGED",
        "externality_class": str(wave3_detached.get("externality_class", "E1_SAME_HOST_DETACHED_REPLAY")).strip(),
        "verifier_boundary": str(wave3_detached.get("verifier_boundary", "")).strip(),
        "earned_externality_refs": list(wave4_externality.get("earned_classes", [])),
        "source_refs": [WAVE3_DETACHED_REL, WAVE4_EXTERNALITY_REL],
        "stronger_claim_not_made": [
            "cross_host_friendly_replay_confirmed",
            "independent_hostile_replay_confirmed",
            "public_challenge_survival_confirmed",
            "externality_class_above_E1_claimed",
        ],
    }


def _build_release_truth_surface(*, head: str, release_activation: Dict[str, Any]) -> Dict[str, Any]:
    subject_head = str(release_activation.get("subject_head_commit", "")).strip()
    return {
        "schema_id": "kt.wave5.release_truth_surface.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "status": "PASS",
        "release_truth_class": "CARRIED_FORWARD_BOUNDED_RELEASE_SURFACE_PRESENT_ON_CURRENT_HEAD",
        "source_surface_status": str(release_activation.get("status", "")).strip(),
        "fresh_current_head_runtime_proof": subject_head == head,
        "carry_forward_boundary": "Wave 5 preserves the bounded release surface as present on current head without upgrading the older release receipt into fresh current-head runtime or externality proof.",
        "source_refs": [RELEASE_ACTIVATION_REL],
        "stronger_claim_not_made": [
            "fresh_current_head_release_runtime_proven",
            "commercial_or_enterprise_readiness_proven",
            "broad_current_head_external_capability_confirmed",
        ],
    }


def _build_product_truth_surface(*, head: str, product_wedge: Dict[str, Any]) -> Dict[str, Any]:
    subject_head = str(product_wedge.get("subject_head_commit", "")).strip()
    return {
        "schema_id": "kt.wave5.product_truth_surface.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "status": "PASS",
        "product_truth_class": "CARRIED_FORWARD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_PRESENT_ON_CURRENT_HEAD",
        "source_surface_status": str(product_wedge.get("status", "")).strip(),
        "fresh_current_head_runtime_proof": subject_head == head,
        "carry_forward_boundary": "Wave 5 preserves the bounded noncommercial evaluation wedge as present on current head without upgrading it into commercial, enterprise, or broad external runtime proof.",
        "source_refs": [PRODUCT_WEDGE_REL],
        "stronger_claim_not_made": [
            "commercial_product_surface_active",
            "enterprise_readiness_proven",
            "product_language_widened_beyond_noncommercial_wedge",
        ],
    }


def _build_final_claim_class_matrix(*, head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.wave5.final_claim_class_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "status": "PASS",
        "dimensions": [
            {"dimension": "control_plane_truth", "claim_class": "CURRENT_HEAD_PROVEN"},
            {"dimension": "runtime_truth", "claim_class": "CURRENT_HEAD_PARTIALLY_PROVEN_MINIMUM_VIABLE_ORGANISM_RUN"},
            {"dimension": "verifier_truth", "claim_class": "CURRENT_HEAD_PROVEN_DETACHED_SAME_HOST_PACKAGED"},
            {"dimension": "challenge_survival", "claim_class": "BOUNDED_INTERNAL_HOSTILE_PROBES_AND_TYPED_CHALLENGE_CHANNEL_ONLY"},
            {"dimension": "replayability", "claim_class": "E1_SAME_HOST_DETACHED_REPLAY"},
            {"dimension": "release_truth", "claim_class": "CARRIED_FORWARD_BOUNDED_RELEASE_SURFACE_PRESENT_ON_CURRENT_HEAD"},
            {"dimension": "product_truth", "claim_class": "CARRIED_FORWARD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_PRESENT_ON_CURRENT_HEAD"},
            {"dimension": "external_confirmation", "claim_class": "E1_SAME_HOST_DETACHED_REPLAY"},
        ],
        "forbidden_escalations": [
            "Do not narrate same-host detached replay as E2, E3, or E4 externality.",
            "Do not narrate live-provider success beyond the canonical same-host LIVE_HASHED OpenAI/OpenRouter lane.",
            "Do not narrate learned-router cutover or superiority.",
            "Do not narrate commercial or enterprise readiness.",
            "Do not narrate SOTA, frontier, or beyond-SOTA status.",
        ],
        "source_refs": [WAVE3_CLAIM_MATRIX_REL, WAVE4_EXTERNALITY_REL, RELEASE_TRUTH_REL, PRODUCT_TRUTH_REL],
    }


def _build_remaining_gap_register(*, contradiction_table: Dict[str, Any]) -> Dict[str, Any]:
    proof_map = _missing_proof_map()
    rows = []
    for row in _open_contradiction_rows(contradiction_table):
        contradiction_id = str(row.get("contradiction_id", "")).strip()
        rows.append(
            {
                "gap_id": contradiction_id,
                "severity": str(row.get("severity", "")).strip(),
                "summary": str(row.get("summary", "")).strip(),
                "missing_proof": proof_map.get(contradiction_id, "Explicit closure proof not yet defined."),
            }
        )
    return {
        "schema_id": "kt.wave5.remaining_gap_register.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "remaining_gap_count": len(rows),
        "rows": rows,
    }


def _build_updated_disposition_register(
    *,
    head: str,
    c016a_receipt: Dict[str, Any],
    c016b_receipt: Dict[str, Any],
    c005_ratification: Dict[str, Any],
) -> Dict[str, Any]:
    adapter_disposition = "REALIZED_BOUNDED_AUTH_ONLY"
    adapter_summary = "Two ABI-bound live adapters are active, but successful authenticated current-head provider inference remains unproven because current probes are 401 fail-closed."
    adapter_evidence = f"{REPORT_ROOT_REL}/kt_wave2a_adapter_activation_receipt.json"
    if _c016a_closed(c016a_receipt) and _c016b_closed(c016b_receipt):
        adapter_disposition = "REALIZED_BOUNDED_CANONICAL_SAME_HOST_LIVE_HASHED"
        adapter_summary = (
            "The canonical same-host LIVE_HASHED OpenAI/OpenRouter adapter lane now has successful authenticated "
            "execution and bounded resilience proof. This remains same-host only and does not upgrade C006."
        )
        adapter_evidence = C016B_RESILIENCE_REL
    router_disposition = "KEEP_STATIC_CANONICAL_BASELINE"
    router_status = "UNCHANGED"
    router_evidence_ref = C005_ROUTER_SELECTION_REL
    router_summary = "Static router remains canonical. Post-Wave5 shadow evidence now binds to the current-head same-host LIVE_HASHED provider underlay, but learned-router cutover and multi-lobe promotion remain unearned."
    router_objective_status = "ACTIVE_GOVERNED_ADVANCEMENT_OBJECTIVE"
    router_objective_summary = "Learned-router superiority and multi-lobe promotion remain active governed advancement objectives and are not abandoned; they are simply not yet earned for canonical promotion on current head."
    if _c005_ratified_hold(c005_ratification):
        router_disposition = "RATIFIED_STATIC_CANONICAL_BASELINE"
        router_status = "UPDATED_POST_WAVE5"
        router_evidence_ref = POST_WAVE5_C005_RATIFICATION_REL
        router_summary = (
            "Static router is now explicitly ratified as canonical current-head control. Shadow evidence "
            "matches the fenced static baseline exactly, best-static comparator control remains explicit, "
            "and learned-router cutover plus multi-lobe promotion remain blocked until new superiority is earned. "
            "This current-head hold does not abandon router ambition."
        )

    rows = [
        {
            "organ_id": "router",
            "disposition": router_disposition,
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": router_status,
            "evidence_ref": router_evidence_ref,
            "bounded_summary": router_summary,
            "continuing_governed_objective_id": "ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION",
            "continuing_governed_objective_status": router_objective_status,
            "continuing_governed_objective_summary": router_objective_summary,
        },
        {
            "organ_id": "council",
            "disposition": "REALIZED_BOUNDED_KEEP_CANONICAL",
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UPDATED_WAVE_5",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_council_kernel_binding_pack.json",
            "bounded_summary": "Council is realized and participates in the bounded canonical organism path. Its same-host LIVE_HASHED provider seam is now proven for the canonical OpenAI/OpenRouter lane without widening externality or router claims.",
        },
        {
            "organ_id": "cognition",
            "disposition": "REALIZED_BOUNDED_KEEP_CANONICAL",
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UPDATED_WAVE_5",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_cognitive_provenance_pack.json",
            "bounded_summary": "Cognition is realized as a bounded planner/executor and is exercised on the minimum viable organism path.",
        },
        {
            "organ_id": "paradox",
            "disposition": "REALIZED_BOUNDED_KEEP_CANONICAL",
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
            "status": "UPDATED_WAVE_5",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_paradox_engine_pack.json",
            "bounded_summary": "Paradox is realized as a bounded contradiction surface. It remains current-head real without being promoted into broader superiority claims.",
        },
        {
            "organ_id": "temporal",
            "disposition": "REALIZED_BOUNDED_KEEP_CANONICAL",
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UPDATED_WAVE_5",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_temporal_engine_pack.json",
            "bounded_summary": "Temporal is realized as a bounded fork-and-replay surface with deterministic refusal behavior.",
        },
        {
            "organ_id": "multiverse",
            "disposition": "REALIZED_BOUNDED_KEEP_CANONICAL",
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UPDATED_WAVE_5",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_multiverse_engine_pack.json",
            "bounded_summary": "Multiverse is realized as a bounded deterministic candidate-ranking surface and remains current-head bounded only.",
        },
        {
            "organ_id": "adapter_layer",
            "disposition": adapter_disposition,
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UPDATED_POST_WAVE5",
            "evidence_ref": adapter_evidence,
            "bounded_summary": adapter_summary,
        },
        {
            "organ_id": "tournament_promotion",
            "disposition": "LAB_ONLY_UNTIL_RUNTIME_REAL",
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UNCHANGED",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_tournament_readiness_receipt.json",
            "bounded_summary": "Tournament/promotion remains lab-only and is not promoted by Wave 5.",
        },
        {
            "organ_id": "teacher_growth_surfaces",
            "disposition": "LAB_ONLY_UNLESS_PROMOTED",
            "reality_class": "SCAFFOLDED",
            "maturity_class": "UNRATED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UNCHANGED",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave0_quarantine_receipts.json",
            "bounded_summary": "Teacher/growth surfaces remain lab-only and outside canonical runtime truth.",
        },
        {
            "organ_id": "toolchain_only_orchestrators",
            "disposition": "TOOLCHAIN_PROVING_ONLY",
            "reality_class": "TOOLCHAIN_PROVING",
            "maturity_class": "UNRATED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UNCHANGED",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave0_5_toolchain_runtime_firewall_receipt.json",
            "bounded_summary": "Toolchain-only orchestrators remain non-runtime and are firewalled from canonical authority.",
        },
        {
            "organ_id": "detached_verifier",
            "disposition": "REALIZED_BOUNDED_E1_SAME_HOST_PACKAGED",
            "reality_class": "CURRENT_HEAD_PROVEN",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
            "status": "UPDATED_WAVE_5",
            "evidence_ref": WAVE3_DETACHED_REL,
            "bounded_summary": "Detached verifier is realized and proven only as same-host packaged detached replay. It is not independent hostile confirmation.",
        },
        {
            "organ_id": "claim_compiler",
            "disposition": "REALIZED_BOUNDED_VOCABULARY_GATE",
            "reality_class": "CURRENT_HEAD_PROVEN",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "status": "UPDATED_WAVE_5",
            "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave3_claim_compiler_receipt.json",
            "bounded_summary": "Claim compiler is active as a bounded vocabulary gate and remains physically blocked from widening externality, product, or superiority language.",
        },
    ]
    return {
        "schema_id": "kt.wave5.updated_surface_disposition_register.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": "PASS",
        "rows": rows,
        "stronger_claim_not_made": [
            "learned_router_cutover_occurred",
            "tournament_promoted_to_canonical_runtime",
            "product_language_widened",
            "broad_live_runtime_or_externality_success_claimed",
        ],
    }


def _build_tier_ruling(*, head: str, contradiction_table: Dict[str, Any]) -> Dict[str, Any]:
    proof_map = _missing_proof_map()
    open_ids = _open_contradiction_ids(contradiction_table)
    return {
        "schema_id": "kt.wave5.final_tier_ruling.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": head,
        "status": "PASS",
        "tier_id": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
        "tier_summary": "Current head proves one bounded canonical organism run, one bounded same-host packaged detached verifier path, one bounded internal hostile-probe plus typed challenge lane, one canonical runtime import/install lane, and one canonical same-host LIVE_HASHED provider success/resilience lane. This tier does not prove cross-host friendly replay, independent hostile replay, public challenge survival, learned-router superiority, or broad live-provider portability.",
        "earned_truths": [
            "One bounded minimum viable organism run on the canonical runtime path.",
            "One detached verifier path bounded at E1 same-host packaged replay.",
            "One bounded internal hostile-probe and typed challenge lane with no successful findings.",
            "One bounded claim compiler output that stayed within the earned ceiling.",
            "One canonical runtime import/install lane proven across repo-root, cleanroom-root, and isolated editable install.",
            "One canonical same-host LIVE_HASHED OpenAI/OpenRouter provider lane with success and resilience proof.",
        ],
        "bounded_truths": [
            "Router remains static-canonical and learned-router cutover is unearned.",
            "Externality remains bounded at E1 same-host detached replay.",
            "Release and product surfaces remain carried-forward bounded surfaces only.",
            "Live-provider proof remains bounded to the canonical same-host LIVE_HASHED OpenAI/OpenRouter lane only.",
        ],
        "continuing_governed_advancement_objectives": [
            {
                "objective_id": "ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION",
                "status": "ACTIVE_GOVERNED_ADVANCEMENT_OBJECTIVE",
                "boundary": "Closed on current-head canonical truth does not mean abandoned. Learned-router superiority and multi-lobe promotion remain active governed objectives until either superiority is earned or an explicit retirement decision is signed.",
            }
        ],
        "unearned_truths": [
            "E2 cross-host friendly replay",
            "E3 independent hostile replay",
            "E4 public challenge survival",
            "learned-router superiority or cutover",
            "cross-host or outsider-verified live-provider capability",
            "commercial or enterprise readiness",
            "SOTA, frontier, or beyond-SOTA standing",
        ],
        "exact_proof_required_to_raise": [{"target": key, "required_proof": proof_map[key]} for key in open_ids if key in proof_map],
        "remaining_open_contradictions": open_ids,
        "replayable_from": [MAIN_RECEIPT_REL, CLAIM_MATRIX_REL, GAP_REGISTER_REL],
        "forbidden_rulings": [
            "single_prestige_brand_label",
            "independent_hostile_confirmation_claim",
            "broad_external_runtime_capability_confirmed",
            "commercial_or_enterprise_readiness_confirmed",
        ],
    }


def build_wave5_outputs(*, root: Path, telemetry_path: Path) -> Dict[str, Dict[str, Any]]:
    started = telemetry_now_ms()
    head = _git_head(root)

    contradiction_table = load_json((root / CONTRADICTION_TABLE_REL).resolve())
    wave3_run = load_json((root / WAVE3_RUN_REL).resolve())
    wave3_detached = load_json((root / WAVE3_DETACHED_REL).resolve())
    wave4_receipt = load_json((root / WAVE4_RECEIPT_REL).resolve())
    wave4_public = load_json((root / WAVE4_PUBLIC_REL).resolve())
    wave4_externality = load_json((root / WAVE4_EXTERNALITY_REL).resolve())
    release_activation = load_json((root / RELEASE_ACTIVATION_REL).resolve())
    product_wedge = load_json((root / PRODUCT_WEDGE_REL).resolve())
    wave4_validation = load_json((root / LIVE_VALIDATION_WAVE4_REL).resolve())
    c007_receipt = load_json((root / C007_CANON_RECEIPT_REL).resolve())
    c016a_receipt = load_json((root / C016A_SUCCESS_REL).resolve())
    c016b_receipt = load_json((root / C016B_RESILIENCE_REL).resolve())
    c005_selection = load_json((root / C005_ROUTER_SELECTION_REL).resolve())
    c005_matrix = load_json((root / C005_ROUTER_MATRIX_REL).resolve())
    c005_health = load_json((root / C005_ROUTER_HEALTH_REL).resolve())
    c005_ratification = load_json((root / POST_WAVE5_C005_RATIFICATION_REL).resolve())
    c006_prep = load_json((root / POST_WAVE5_C006_PREP_REL).resolve())

    contradiction_table = _rebind_current_head_contradiction_table(
        base_table=contradiction_table,
        head=head,
        c007_receipt=c007_receipt,
        c016a_receipt=c016a_receipt,
        c016b_receipt=c016b_receipt,
        c005_selection=c005_selection,
        c005_matrix=c005_matrix,
        c005_health=c005_health,
        c005_ratification=c005_ratification,
        c006_prep=c006_prep,
    )

    critical_failures = [
        row
        for row in wave4_validation.get("checks", [])
        if isinstance(row, dict) and bool(row.get("critical")) and str(row.get("status", "")).strip().upper() == "FAIL"
    ]
    inputs_ok = all(
        str(obj.get("status", "")).strip() == "PASS"
        for obj in (wave3_run, wave3_detached, wave4_receipt, wave4_public, wave4_externality)
    ) and not critical_failures

    state_core = _build_state_core(
        head=head,
        contradiction_table=contradiction_table,
        wave3_run=wave3_run,
        wave3_detached=wave3_detached,
        wave4_receipt=wave4_receipt,
        wave4_public=wave4_public,
    )
    blocker_matrix = _build_blocker_matrix(head=head, contradiction_table=contradiction_table)
    runtime_truth = _build_runtime_truth_surface(
        head=head,
        wave3_run=wave3_run,
        contradiction_table=contradiction_table,
        c016a_receipt=c016a_receipt,
        c016b_receipt=c016b_receipt,
    )
    verifier_truth = _build_verifier_truth_surface(head=head, wave3_detached=wave3_detached, wave4_externality=wave4_externality)
    release_truth = _build_release_truth_surface(head=head, release_activation=release_activation)
    product_truth = _build_product_truth_surface(head=head, product_wedge=product_wedge)
    claim_matrix = _build_final_claim_class_matrix(head=head)
    gap_register = _build_remaining_gap_register(contradiction_table=contradiction_table)
    disposition_register = _build_updated_disposition_register(
        head=head,
        c016a_receipt=c016a_receipt,
        c016b_receipt=c016b_receipt,
        c005_ratification=c005_ratification,
    )
    tier_ruling = _build_tier_ruling(head=head, contradiction_table=contradiction_table)

    status = "PASS" if inputs_ok else "FAIL"
    completed = telemetry_now_ms()
    main_receipt = {
        "schema_id": "kt.wave5.final_readjudication_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": WORK_ORDER_ID,
        "wave_id": WAVE_ID,
        "status": status,
        "compiled_head_commit": head,
        "scope_boundary": "Wave 5 only: recompute current-head truth surfaces, emit one scoped final claim-class matrix, one scoped tier ruling, one remaining gap register, one updated surface disposition register, and fold in earned Post-Wave5 router ratification hold evidence when present.",
        "state_core_ref": STATE_CORE_REL,
        "blocker_matrix_ref": BLOCKER_MATRIX_REL,
        "runtime_truth_surface_ref": RUNTIME_TRUTH_REL,
        "verifier_truth_surface_ref": VERIFIER_TRUTH_REL,
        "release_truth_surface_ref": RELEASE_TRUTH_REL,
        "product_truth_surface_ref": PRODUCT_TRUTH_REL,
        "final_claim_class_matrix_ref": CLAIM_MATRIX_REL,
        "final_tier_ruling_ref": TIER_RULING_REL,
        "remaining_gap_register_ref": GAP_REGISTER_REL,
        "updated_surface_disposition_register_ref": DISPOSITION_REL,
        "remaining_open_contradictions": _open_contradiction_ids(contradiction_table),
        "wave4_board_critical_failures": len(critical_failures),
        "stronger_claim_not_made": [
            "same_host_detached_replay_narrated_as_E2_or_E3",
            "live_provider_claims_widened_beyond_canonical_same_host_lane",
            "learned_router_cutover_claimed",
            "commercial_or_enterprise_readiness_claimed",
            "SOTA_or_frontier_claimed",
        ],
        "timing_ms": {
            "start_ts": started,
            "end_ts": completed,
            "latency_ms": max(0, completed - started),
        },
    }
    emit_toolchain_telemetry(
        surface_id="tools.operator.wave5_final_readjudication_and_tier_ruling_validate",
        zone="TOOLCHAIN_PROVING",
        event_type="wave5.final_readjudication",
        start_ts=started,
        end_ts=completed,
        result_status=status,
        policy_applied="wave5.final_readjudication_and_tier_ruling",
        receipt_ref=MAIN_RECEIPT_REL,
        trace_id="wave5-final-readjudication",
        request_id="wave5.final_readjudication_and_tier_ruling_validate",
        path=telemetry_path,
    )
    return {
        "main_receipt": main_receipt,
        "state_core": state_core,
        "blocker_matrix": blocker_matrix,
        "runtime_truth": runtime_truth,
        "verifier_truth": verifier_truth,
        "release_truth": release_truth,
        "product_truth": product_truth,
        "claim_matrix": claim_matrix,
        "gap_register": gap_register,
        "disposition_register": disposition_register,
        "tier_ruling": tier_ruling,
        "current_head_contradiction_table": contradiction_table,
    }


def _append_unique(items: List[str], additions: Sequence[str]) -> List[str]:
    out = list(items)
    for item in additions:
        if item not in out:
            out.append(item)
    return out


def update_convergence_surfaces(*, root: Path, outputs: Dict[str, Dict[str, Any]]) -> None:
    if outputs["main_receipt"]["status"] != "PASS":
        return

    execution = load_json((root / EXECUTION_REPORT_REL).resolve())
    gate = load_json((root / PASS_FAIL_REL).resolve())
    truth_map = load_json((root / TRUTH_MAP_REL).resolve())
    runtime_map = load_json((root / RUNTIME_MAP_REL).resolve())
    contradiction_table = load_json((root / CONTRADICTION_TABLE_REL).resolve())
    head = _git_head(root)
    remaining_open = list(outputs["main_receipt"]["remaining_open_contradictions"])

    execution["generated_utc"] = utc_now_iso_z()
    execution["current_git_head"] = head
    execution["highest_lawful_wave_reached"] = WAVE_ID
    execution["scope_executed"] = "WAVE_0_THROUGH_WAVE_5_ONLY"
    execution["blocked_by"] = list(remaining_open)
    execution["overall_status"] = "WAVE_5_FINAL_READJUDICATION_COMPLETE_SCOPED_TIER_RULING_EMITTED"
    execution["repo_status"] = "WAVE_5_WORKTREE_DIRTY_UNCOMMITTED"
    execution["non_blocking_holds"] = [
        "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
        "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
        "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
        "LIVE_PROVIDER_PROOF_REMAINS_BOUNDED_TO_CANONICAL_SAME_HOST_LIVE_HASHED_OPENAI_OPENROUTER_LANE",
        "PUBLIC_CHALLENGE_SURVIVAL_NOT_EARNED",
        "COMMERCIAL_AND_ENTERPRISE_LANGUAGE_REMAINS_UNEARNED",
    ]
    execution["executed_findings"] = _append_unique(
        execution.get("executed_findings", []),
        [
            "Wave 5 recomputes the current-head state core, blocker matrix, runtime truth, verifier truth, release truth, and product truth from the live convergence surfaces rather than inheriting stale phase verdicts.",
            "Wave 5 now freezes the canonical package/import canon plus the canonical same-host LIVE_HASHED provider success/resilience lane into the current-head truth surfaces without widening C006.",
            "Wave 5 emits one scoped final claim-class matrix and one scoped tier ruling that preserve E1 same-host packaged detached replay as the externality ceiling and keep only the contradictions still open on current head.",
            "Wave 5 updates the surface disposition register so current-head organ status matches the actual bounded organism path, detached verifier boundary, claim compiler boundary, and same-host-bounded adapter reality.",
        ],
    )
    execution["next_lawful_actions"] = [
        "Hold after Wave 5; no comparative, commercial, or externality widening is lawful without new proof.",
        "To rise above E1, earn E2, E3, or E4 directly rather than narratively.",
        "To narrow runtime claims further, continue exact current-head proof for any remaining open blocker without widening learned routing, externality, or product claims.",
    ]
    execution["outputs_produced"] = _append_unique(
        execution.get("outputs_produced", []),
        [
            STATE_CORE_REL,
            BLOCKER_MATRIX_REL,
            RUNTIME_TRUTH_REL,
            VERIFIER_TRUTH_REL,
            RELEASE_TRUTH_REL,
            PRODUCT_TRUTH_REL,
            CLAIM_MATRIX_REL,
            TIER_RULING_REL,
            GAP_REGISTER_REL,
            DISPOSITION_REL,
            MAIN_RECEIPT_REL,
            TELEMETRY_REL,
        ],
    )
    execution["remaining_open_contradictions"] = remaining_open
    execution["stronger_claim_not_made"] = _append_unique(
        execution.get("stronger_claim_not_made", []),
        [
            "same_host_detached_replay_narrated_as_independent_hostile_confirmation",
            "live_provider_claims_widened_beyond_canonical_same_host_openai_openrouter_lane",
            "commercial_or_enterprise_readiness_claimed",
            "SOTA_or_frontier_claimed",
        ],
    )
    write_json_stable((root / EXECUTION_REPORT_REL).resolve(), execution)

    gate["generated_utc"] = utc_now_iso_z()
    gate["current_git_head"] = head
    gate["highest_lawful_wave_reached"] = WAVE_ID
    gate["scope_executed"] = "WAVE_0_THROUGH_WAVE_5_ONLY"
    found = False
    for row in gate.get("wave_statuses", []):
        if row.get("wave_id") == WAVE_ID:
            row.clear()
            row.update(
                {
                    "wave_id": WAVE_ID,
                    "status": "PASS",
                    "boundary_holds": [
                        "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
                        "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
                        "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
                        "LIVE_PROVIDER_PROOF_REMAINS_BOUNDED_TO_CANONICAL_SAME_HOST_LIVE_HASHED_OPENAI_OPENROUTER_LANE",
                    ],
                    "cleared_blockers": [
                        "wave5_final_readjudication_locked_by_scope_boundary",
                        "stale_phase_level_readjudication_surfaces_not_superseded",
                    ],
                    "completed_outputs": [
                        "kt_wave5_state_core",
                        "kt_wave5_blocker_matrix",
                        "kt_wave5_runtime_truth_surface",
                        "kt_wave5_verifier_truth_surface",
                        "kt_wave5_release_truth_surface",
                        "kt_wave5_product_truth_surface",
                        "kt_wave5_final_claim_class_matrix",
                        "kt_wave5_final_tier_ruling",
                        "kt_wave5_remaining_gap_register",
                        "kt_wave5_updated_surface_disposition_register",
                        "kt_wave5_final_readjudication_receipt",
                    ],
                    "remaining_open_contradictions": remaining_open,
                }
            )
            found = True
            break
    if not found:
        gate.setdefault("wave_statuses", []).append({"wave_id": WAVE_ID, "status": "PASS", "remaining_open_contradictions": remaining_open})
    write_json_stable((root / PASS_FAIL_REL).resolve(), gate)

    truth_map["generated_utc"] = utc_now_iso_z()
    truth_map["current_git_head"] = head
    truth_map["source_surfaces"]["current_head_state_vector"] = STATE_CORE_REL
    truth_map["source_surfaces"]["current_head_blocker_matrix"] = BLOCKER_MATRIX_REL
    truth_map["source_surfaces"]["current_head_runtime_truth_surface"] = RUNTIME_TRUTH_REL
    truth_map["source_surfaces"]["current_head_verifier_truth_surface"] = VERIFIER_TRUTH_REL
    truth_map["source_surfaces"]["current_head_release_truth_surface"] = RELEASE_TRUTH_REL
    truth_map["source_surfaces"]["current_head_product_truth_surface"] = PRODUCT_TRUTH_REL
    truth_map["source_surfaces"]["current_head_final_claim_class_surface"] = CLAIM_MATRIX_REL
    truth_map["source_surfaces"]["current_head_final_tier_surface"] = TIER_RULING_REL
    truth_map["source_surfaces"]["current_head_remaining_gap_surface"] = GAP_REGISTER_REL
    truth_map["source_surfaces"]["current_head_organ_disposition_surface"] = DISPOSITION_REL
    truth_map["source_surfaces"]["current_head_live_validation_index"] = LIVE_VALIDATION_WAVE5_REL
    truth_map["source_surfaces"]["current_head_router_ratification_surface"] = POST_WAVE5_C005_RATIFICATION_REL
    truth_map["source_surfaces"]["current_head_c006_prep_surface"] = POST_WAVE5_C006_PREP_REL
    truth_map["open_stop_gates"] = [
        "current_head_external_capability_not_confirmed",
        "externality_above_E1_not_confirmed",
    ]
    truth_map["truth_partitions"]["current_head_control_plane_truth"]["summary"] = "Current-head control-plane truth is proven through the Wave 0-5 convergence lane: one canonical kernel, one truth core, one package/import canon, one toolchain/runtime firewall, one frozen interface surface, and one scoped final readjudication."
    truth_map["truth_partitions"]["current_head_runtime_truth"]["summary"] = "Current-head runtime truth remains partially proven: KT proves one bounded minimum viable organism run on the canonical path, one canonical runtime import/install lane, one canonical same-host LIVE_HASHED provider success/resilience lane, and one ratified static-router control surface bound to current-head best-static comparison. Learned-router cutover remains unearned and externality above E1 remains unearned."
    truth_map["truth_partitions"]["current_head_runtime_truth"]["advancement_boundary"] = "Router hold on current head is not abandonment. Learned-router superiority and multi-lobe promotion remain active governed advancement objectives and require fenced-task superiority plus no-regression proof before canonical cutover."
    truth_map["truth_partitions"]["current_head_trust_and_provenance_truth"]["summary"] = "Trust and provenance truth are current-head partially proven: machine-bound trust surfaces, bounded detached verifier replay at E1, same-host independent clean-environment replay, secret-free bounded outsider verifier tooling, typed challenge protocol, and final readjudication are all present without widening externality above E1."
    truth_map["truth_partitions"]["product_and_commercial_truth"]["summary"] = "Product and commercial truth remain bounded: a carried-forward noncommercial evaluation wedge is present on current head, but no commercial or enterprise readiness claim is earned."
    truth_map["truth_partitions"]["integrated_overall_truth"]["summary"] = "Integrated current-head truth is now scoped and final-readjudicated: one bounded canonical organism run, one bounded same-host detached verifier path, one bounded internal hostile-probe layer, one canonical runtime import/install lane, one canonical same-host LIVE_HASHED provider success/resilience lane, one ratified static-router control surface, and one scoped tier ruling. Overall truth remains bounded only by contradictions still open on current head."
    write_json_stable((root / TRUTH_MAP_REL).resolve(), truth_map)

    runtime_map["generated_utc"] = utc_now_iso_z()
    runtime_map["current_git_head"] = head
    runtime_map["runtime_roots"]["wave5_final_readjudication_status"] = "PASS_SCOPED_FINAL_TIER_RULING"
    runtime_map["critical_organs"] = list(outputs["disposition_register"]["rows"])
    runtime_map["wave5_final_readjudication_lane"] = {
        "status": "PASS",
        "boundary_holds": [
            "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
            "BEST_STATIC_COMPARATOR_REMAINS_CONTROL",
            "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
            "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
            "LIVE_PROVIDER_PROOF_REMAINS_BOUNDED_TO_CANONICAL_SAME_HOST_LIVE_HASHED_OPENAI_OPENROUTER_LANE",
        ],
        "evidence_refs": [
            STATE_CORE_REL,
            BLOCKER_MATRIX_REL,
            RUNTIME_TRUTH_REL,
            VERIFIER_TRUTH_REL,
            RELEASE_TRUTH_REL,
            PRODUCT_TRUTH_REL,
            CLAIM_MATRIX_REL,
            TIER_RULING_REL,
            GAP_REGISTER_REL,
            DISPOSITION_REL,
            MAIN_RECEIPT_REL,
            POST_WAVE5_C005_RATIFICATION_REL,
            C005_ROUTER_SELECTION_REL,
            POST_WAVE5_C006_PREP_REL,
        ],
        "tier_id": outputs["tier_ruling"]["tier_id"],
        "externality_ceiling": "E1_SAME_HOST_DETACHED_REPLAY",
        "remaining_open_contradictions": remaining_open,
        "continuing_governed_advancement_objectives": [
            "ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION",
        ],
    }
    write_json_stable((root / RUNTIME_MAP_REL).resolve(), runtime_map)

    write_json_stable((root / CONTRADICTION_TABLE_REL).resolve(), outputs["current_head_contradiction_table"])


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Wave 5 final readjudication and tier ruling on the bounded current-head convergence stack.")
    parser.add_argument("--state-core-output", default=STATE_CORE_REL)
    parser.add_argument("--blocker-matrix-output", default=BLOCKER_MATRIX_REL)
    parser.add_argument("--runtime-truth-output", default=RUNTIME_TRUTH_REL)
    parser.add_argument("--verifier-truth-output", default=VERIFIER_TRUTH_REL)
    parser.add_argument("--release-truth-output", default=RELEASE_TRUTH_REL)
    parser.add_argument("--product-truth-output", default=PRODUCT_TRUTH_REL)
    parser.add_argument("--claim-matrix-output", default=CLAIM_MATRIX_REL)
    parser.add_argument("--tier-ruling-output", default=TIER_RULING_REL)
    parser.add_argument("--gap-register-output", default=GAP_REGISTER_REL)
    parser.add_argument("--disposition-output", default=DISPOSITION_REL)
    parser.add_argument("--receipt-output", default=MAIN_RECEIPT_REL)
    parser.add_argument("--telemetry-output", default=TELEMETRY_REL)
    parser.add_argument("--update-convergence-surfaces", action="store_true")
    return parser.parse_args(argv)


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    telemetry_path = _resolve(root, str(args.telemetry_output))
    outputs = build_wave5_outputs(root=root, telemetry_path=telemetry_path)

    write_json_stable(_resolve(root, str(args.state_core_output)), outputs["state_core"])
    write_json_stable(_resolve(root, str(args.blocker_matrix_output)), outputs["blocker_matrix"])
    write_json_stable(_resolve(root, str(args.runtime_truth_output)), outputs["runtime_truth"])
    write_json_stable(_resolve(root, str(args.verifier_truth_output)), outputs["verifier_truth"])
    write_json_stable(_resolve(root, str(args.release_truth_output)), outputs["release_truth"])
    write_json_stable(_resolve(root, str(args.product_truth_output)), outputs["product_truth"])
    write_json_stable(_resolve(root, str(args.claim_matrix_output)), outputs["claim_matrix"])
    write_json_stable(_resolve(root, str(args.tier_ruling_output)), outputs["tier_ruling"])
    write_json_stable(_resolve(root, str(args.gap_register_output)), outputs["gap_register"])
    write_json_stable(_resolve(root, str(args.disposition_output)), outputs["disposition_register"])
    write_json_stable(_resolve(root, str(args.receipt_output)), outputs["main_receipt"])

    if args.update_convergence_surfaces:
        update_convergence_surfaces(root=root, outputs=outputs)

    print(
        json.dumps(
            {
                "externality_ceiling": "E1_SAME_HOST_DETACHED_REPLAY",
                "remaining_open_contradictions": outputs["main_receipt"]["remaining_open_contradictions"],
                "status": outputs["main_receipt"]["status"],
                "tier_id": outputs["tier_ruling"]["tier_id"],
            },
            sort_keys=True,
        )
    )
    return 0 if outputs["main_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
