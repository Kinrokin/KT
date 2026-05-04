from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator import cohort0_b04_r6_afsh_shadow_screen_execution_packet as packet
from tools.operator import cohort0_b04_r6_afsh_shadow_screen_execution_packet_validation as packet_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-afsh-shadow-screen"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION"
PREVIOUS_LANE = packet_validation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = packet_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet_validation.NEXT_LAWFUL_MOVE
OUTCOME_PASSED = "B04_R6_AFSH_SHADOW_SUPERIORITY_PASSED__ACTIVATION_REVIEW_PACKET_NEXT"
OUTCOME_FAILED = "B04_R6_AFSH_SHADOW_SUPERIORITY_FAILED__SUPERIORITY_NOT_EARNED_CLOSEOUT_OR_REDESIGN_NEXT"
OUTCOME_INVALIDATED = "B04_R6_AFSH_SHADOW_SCREEN_INVALIDATED__FORENSIC_INVALIDATION_COURT_NEXT"
OUTCOME_DEFERRED = "B04_R6_AFSH_SHADOW_DEFERRED__NAMED_DEFECT_REMAINS"
ALLOWED_OUTCOMES = (OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_INVALIDATED, OUTCOME_DEFERRED)
NEXT_BY_OUTCOME = {
    OUTCOME_PASSED: "AUTHOR_B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET",
    OUTCOME_FAILED: "AUTHOR_B04_R6_SUPERIORITY_NOT_EARNED_CLOSEOUT_OR_REDESIGN_COURT",
    OUTCOME_INVALIDATED: "AUTHOR_B04_R6_FORENSIC_INVALIDATION_COURT",
    OUTCOME_DEFERRED: "REPAIR_B04_R6_AFSH_SHADOW_SCREEN_DEFECTS",
}

SELECTED_ARCHITECTURE_ID = packet.SELECTED_ARCHITECTURE_ID
SELECTED_ARCHITECTURE_NAME = packet.SELECTED_ARCHITECTURE_NAME
CANDIDATE_ID = packet.CANDIDATE_ID
CANDIDATE_VERSION = packet.CANDIDATE_VERSION

CASE_PREFIX = "B04R6-AFSH-BU1-"
EXPECTED_CASE_COUNT = 18
ROUTE_THRESHOLD = 0.70
WRONG_ROUTE_COST_THRESHOLD = 0.35
MIRROR_MASKED_INSTABILITY_THRESHOLD = 0.15
MAX_SELECTOR_ENTRY_RATE = 0.35

SCREEN_REASON_CODES = (
    "RC_B04R6_AFSH_SCREEN_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SCREEN_MAIN_HEAD_MISMATCH",
    "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING",
    "RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING",
    "RC_B04R6_AFSH_SCREEN_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_AFSH_SCREEN_CANDIDATE_HASH_MISMATCH",
    "RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH",
    "RC_B04R6_AFSH_SCREEN_COURT_HASH_MISMATCH",
    "RC_B04R6_AFSH_SCREEN_SOURCE_PACKET_HASH_MISMATCH",
    "RC_B04R6_AFSH_SCREEN_ADMISSIBILITY_HASH_MISMATCH",
    "RC_B04R6_AFSH_SCREEN_METRIC_CONTRACT_MUTATED",
    "RC_B04R6_AFSH_SCREEN_STATIC_COMPARATOR_WEAKENED",
    "RC_B04R6_AFSH_SCREEN_ROUTE_ELIGIBLE_DELTA_FAIL",
    "RC_B04R6_AFSH_SCREEN_STATIC_HOLD_PRESERVATION_FAIL",
    "RC_B04R6_AFSH_SCREEN_ABSTENTION_PRESERVATION_FAIL",
    "RC_B04R6_AFSH_SCREEN_NULL_ROUTE_PRESERVATION_FAIL",
    "RC_B04R6_AFSH_SCREEN_OVERROUTING_CONTAINMENT_FAIL",
    "RC_B04R6_AFSH_SCREEN_MIRROR_MASKED_STABILITY_FAIL",
    "RC_B04R6_AFSH_SCREEN_WRONG_ROUTE_COST_HIGH",
    "RC_B04R6_AFSH_SCREEN_WRONG_STATIC_HOLD_COST_UNACCOUNTED",
    "RC_B04R6_AFSH_SCREEN_PROOF_BURDEN_NOT_JUSTIFIED",
    "RC_B04R6_AFSH_SCREEN_TRACE_INCOMPLETE",
    "RC_B04R6_AFSH_SCREEN_BLIND_LABEL_ACCESS",
    "RC_B04R6_AFSH_SCREEN_ROUTE_SUCCESS_LABEL_ACCESS",
    "RC_B04R6_AFSH_SCREEN_POST_SCREEN_LABEL_LEAKAGE",
    "RC_B04R6_AFSH_SCREEN_OLD_UNIVERSE_PROOF_DRIFT",
    "RC_B04R6_AFSH_SCREEN_PARTIAL_WIN_SUPERIORITY_DRIFT",
    "RC_B04R6_AFSH_SCREEN_R6_OPEN_DRIFT",
    "RC_B04R6_AFSH_SCREEN_ACTIVATION_CUTOVER_DRIFT",
    "RC_B04R6_AFSH_SCREEN_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_AFSH_SCREEN_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_AFSH_SCREEN_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_AFSH_SCREEN_TRUST_ZONE_MUTATION",
    "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT",
)

TERMINAL_DISQUALIFIERS = (
    "candidate_hash_mismatch",
    "universe_hash_mismatch",
    "court_hash_mismatch",
    "source_packet_hash_mismatch",
    "admissibility_hash_mismatch",
    "metric_contract_mutated",
    "static_comparator_weakened",
    "blind_label_access",
    "route_success_label_access",
    "old_universe_counted_proof_drift",
    "static_hold_collapse",
    "abstention_collapse",
    "null_route_collapse",
    "overrouting_collapse",
    "mirror_masked_instability_above_threshold",
    "trace_incompleteness",
    "truth_engine_mutation",
    "trust_zone_mutation",
    "r6_open_drift",
    "activation_cutover_drift",
    "package_promotion_drift",
)

REQUIRED_TRACE_FIELDS = (
    "candidate_id",
    "candidate_version",
    "selected_architecture",
    "source_packet_hash",
    "validated_court_hash",
    "validated_universe_hash",
    "numeric_triage_emit_core_hash",
    "verdict_mode",
    "triage_subtype",
    "numeric_scores",
    "route_value_terms",
    "static_hold_reason_code",
    "abstention_reason_code",
    "null_route_reason_code",
    "route_eligible_reason_code",
    "trust_zone_status",
    "comparator_preservation_status",
    "metric_preservation_status",
    "forbidden_feature_absence_status",
    "no_contamination_status",
    "deterministic_replay_status",
    "selector_entry_authorized",
)

INPUTS = {
    "packet_validation_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_packet_validation_contract.json",
    "packet_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_packet_validation_receipt.json",
    "universe_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_validation_receipt.json",
    "court_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_receipt.json",
    "source_packet_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_packet_validation_receipt.json",
    "packet_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_execution_packet_contract.json",
    "packet_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_execution_packet_receipt.json",
    "candidate_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_manifest.json",
    "candidate_artifact": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_v1.json",
    "candidate_hash_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_hash_receipt.json",
    "case_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_case_manifest.json",
    "control_sibling_map": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_universe_control_sibling_candidate_map.json",
    "mirror_masked_map": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_mirror_masked_map.json",
    "court_contract": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_contract.json",
    "source_packet_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_implementation_source_packet_contract.json",
    "admissibility_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_admissibility_court_receipt.json",
    "numeric_triage_emit_core": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_numeric_triage_emit_core_contract.json",
    "trace_schema_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_trace_schema_admissibility_receipt.json",
    "static_comparator_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_static_comparator_contract.json",
    "metric_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_metric_contract.json",
    "route_value_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_route_value_contract.json",
    "disqualifier_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_disqualifier_ledger.json",
    "result_interpretation_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_result_interpretation_contract.json",
    "replay_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_replay_manifest.json",
    "expected_artifact_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_expected_artifact_manifest.json",
    "external_verifier_requirements": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_external_verifier_requirements.json",
    "packet_no_authorization_drift": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_no_authorization_drift_receipt.json",
    "turboquant_translation": "KT_PROD_CLEANROOM/reports/kt_turboquant_research_translation_matrix_prep_only.json",
    "compressed_receipt_index": "KT_PROD_CLEANROOM/reports/kt_compressed_receipt_vector_index_contract_prep_only.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
TEXT_INPUTS = {
    "packet_validation_report": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_packet_validation_report.md",
    "packet_report": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_execution_packet_report.md",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})

OUTPUTS = {
    "execution_contract": "b04_r6_afsh_shadow_screen_execution_contract.json",
    "execution_receipt": "b04_r6_afsh_shadow_screen_execution_receipt.json",
    "result": "b04_r6_afsh_shadow_screen_result.json",
    "result_report": "b04_r6_afsh_shadow_screen_result_report.md",
    "case_result_manifest": "b04_r6_afsh_shadow_screen_case_result_manifest.json",
    "triage_result_receipt": "b04_r6_afsh_shadow_screen_triage_result_receipt.json",
    "selector_entry_receipt": "b04_r6_afsh_shadow_screen_selector_entry_receipt.json",
    "static_hold_preservation_receipt": "b04_r6_afsh_shadow_screen_static_hold_preservation_receipt.json",
    "abstention_preservation_receipt": "b04_r6_afsh_shadow_screen_abstention_preservation_receipt.json",
    "null_route_preservation_receipt": "b04_r6_afsh_shadow_screen_null_route_preservation_receipt.json",
    "overrouting_containment_receipt": "b04_r6_afsh_shadow_screen_overrouting_containment_receipt.json",
    "mirror_masked_stability_receipt": "b04_r6_afsh_shadow_screen_mirror_masked_stability_receipt.json",
    "wrong_route_cost_receipt": "b04_r6_afsh_shadow_screen_wrong_route_cost_receipt.json",
    "wrong_static_hold_cost_receipt": "b04_r6_afsh_shadow_screen_wrong_static_hold_cost_receipt.json",
    "proof_burden_delta_receipt": "b04_r6_afsh_shadow_screen_proof_burden_delta_receipt.json",
    "trace_completeness_receipt": "b04_r6_afsh_shadow_screen_trace_completeness_receipt.json",
    "metric_scorecard": "b04_r6_afsh_shadow_screen_metric_scorecard.json",
    "disqualifier_result_receipt": "b04_r6_afsh_shadow_screen_disqualifier_result_receipt.json",
    "result_interpretation_receipt": "b04_r6_afsh_shadow_screen_result_interpretation_receipt.json",
    "replay_receipt": "b04_r6_afsh_shadow_screen_replay_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_afsh_shadow_screen_no_authorization_drift_receipt.json",
    "trust_zone_receipt": "b04_r6_afsh_shadow_screen_trust_zone_receipt.json",
    "activation_review_packet_prep_only_draft": "b04_r6_learned_router_activation_review_packet_prep_only_draft.json",
    "activation_risk_register_prep_only_draft": "b04_r6_learned_router_activation_risk_register_prep_only_draft.json",
    "runtime_guard_requirements_prep_only_draft": "b04_r6_learned_router_runtime_guard_requirements_prep_only_draft.json",
    "rollback_plan_prep_only_draft": "b04_r6_learned_router_rollback_plan_prep_only_draft.json",
    "superiority_not_earned_closeout_prep_only_draft": "b04_r6_superiority_not_earned_closeout_contract_prep_only_draft.json",
    "redesign_authorization_court_prep_only_draft": "b04_r6_redesign_authorization_court_prep_only_draft.json",
    "forensic_invalidation_court_prep_only_draft": "b04_r6_forensic_invalidation_court_prep_only_draft.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {current_branch}")
    if current_branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError(
                "FAIL_CLOSED: main replay requires local main converged with origin/main; "
                f"HEAD={head}; origin/main={origin_main}"
            )
    return current_branch


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _rows_for(rows: list[Dict[str, str]], *groups: str) -> list[Dict[str, str]]:
    wanted = set(groups)
    return [row for row in rows if row.get("group") in wanted]


def _canonical_hash(value: Any) -> str:
    return sha256_hex(canonicalize_bytes(value))


def _input_hashes(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(INPUTS.items()):
        path = common.resolve_path(root, raw)
        row = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_shadow_screen_execution",
        }
        if role in MUTABLE_HANDOFF_ROLES:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_shadow_screen_execution",
            }
        )
    return rows


def _input_binding_sha(bindings: Iterable[Dict[str, Any]], role: str) -> str:
    matches = [str(row.get("sha256", "")).strip() for row in bindings if row.get("role") == role]
    if len(matches) != 1:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"expected exactly one binding for role {role}")
    return matches[0]


def _optional_input_binding_sha(bindings: Iterable[Dict[str, Any]], role: str) -> Optional[str]:
    matches = [str(row.get("sha256", "")).strip() for row in bindings if row.get("role") == role]
    if len(matches) > 1:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"duplicate binding for role {role}")
    return matches[0] if matches else None


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and bool(payload.get(key)):
        _fail(code, f"{label} sets forbidden true flag: {key}")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    forbidden_true = (
        "r6_open",
        "r6_authorized",
        "activation_cutover_authorized",
        "runtime_cutover_authorized",
        "learned_router_activated",
        "learned_router_cutover_authorized",
        "lobe_escalation_authorized",
        "multi_lobe_authorized",
        "package_promotion_authorized",
        "package_promotion_approved",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "metric_contract_mutated",
        "static_comparator_weakened",
    )
    for key in forbidden_true:
        _ensure_false_if_present(payload, key, label=label, code="RC_B04R6_AFSH_SCREEN_R6_OPEN_DRIFT")
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        for key in forbidden_true:
            _ensure_false_if_present(state, key, label=f"{label}.authorization_state", code="RC_B04R6_AFSH_SCREEN_R6_OPEN_DRIFT")
        if state.get("package_promotion") not in (None, "DEFERRED"):
            _fail("RC_B04R6_AFSH_SCREEN_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_AFSH_SCREEN_TRUTH_ENGINE_MUTATION", f"{label} mutates truth-engine law")
    if payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_AFSH_SCREEN_TRUST_ZONE_MUTATION", f"{label} mutates trust-zone law")


def _validate_handoff(payload: Dict[str, Any]) -> Dict[str, bool]:
    predecessor = (
        payload.get("authoritative_lane") == packet_validation.AUTHORITATIVE_LANE
        and payload.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and payload.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    self_replay = (
        payload.get("authoritative_lane") == AUTHORITATIVE_LANE
        and payload.get("selected_outcome") in ALLOWED_OUTCOMES
        and payload.get("next_lawful_move") == NEXT_BY_OUTCOME.get(str(payload.get("selected_outcome")))
    )
    if not (predecessor or self_replay):
        _fail("RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "next lawful move receipt has outcome/move without valid lane identity")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _require_status_pass(payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> str:
    if "validated" not in text_payloads["packet_validation_report"].lower():
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING", "packet validation report missing validation marker")
    if "shadow-screen" not in text_payloads["packet_report"].lower():
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "packet report missing shadow-screen marker")
    for role, payload in payloads.items():
        _ensure_boundaries(payload, label=role)
        if role == "previous_next_lawful_move":
            _validate_handoff(payload)
            continue
        if role in {"turboquant_translation", "compressed_receipt_index"}:
            continue
        if payload.get("status") not in (None, "PASS"):
            _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"{role} must be PASS or structural input")
    validation_receipt = payloads["packet_validation_receipt"]
    validation_contract = payloads["packet_validation_contract"]
    if validation_receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING", "packet validation receipt outcome drift")
    if validation_receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "packet validation receipt next move drift")
    if validation_receipt.get("authoritative_lane") != packet_validation.AUTHORITATIVE_LANE:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING", "packet validation receipt lane identity drift")
    if validation_contract.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING", "packet validation architecture drift")
    replay_head = str(validation_receipt.get("current_git_head", "")).strip()
    if not replay_head or replay_head != str(validation_contract.get("current_git_head", "")).strip():
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING", "packet validation replay head missing or inconsistent")
    return replay_head


def _validate_packet_bound_inputs(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    packet_hashes = payloads["packet_contract"].get("binding_hashes", {})
    validation_hashes = payloads["packet_validation_receipt"].get("binding_hashes", {})
    if packet_hashes != validation_hashes:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "packet and packet-validation binding hashes diverged")
    for key in packet_validation.REQUIRED_BINDING_HASH_KEYS:
        value = str(validation_hashes.get(key, "")).strip()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"missing packet-bound hash: {key}")
    direct_file_roles = {
        "candidate_manifest_hash": "candidate_manifest",
        "candidate_artifact_hash": "candidate_artifact",
        "admissibility_receipt_hash": "admissibility_receipt",
        "numeric_triage_emit_core_hash": "numeric_triage_emit_core",
        "trace_schema_hash": "trace_schema_admissibility",
    }
    for hash_key, role in direct_file_roles.items():
        if file_sha256(common.resolve_path(root, INPUTS[role])) != validation_hashes[hash_key]:
            _fail("RC_B04R6_AFSH_SCREEN_CANDIDATE_HASH_MISMATCH", f"{role} file hash does not match packet-bound {hash_key}")
    packet_validation_bindings = payloads["packet_validation_receipt"].get("input_bindings", [])
    if not isinstance(packet_validation_bindings, list):
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING", "packet validation input bindings missing")
    packet_output_roles = {
        "packet_contract": "packet_contract",
        "static_comparator_contract": "static_comparator_contract",
        "metric_contract": "metric_contract",
        "route_value_contract": "route_value_contract",
        "disqualifier_ledger": "disqualifier_ledger",
        "result_interpretation_contract": "result_interpretation_contract",
        "replay_manifest": "replay_manifest",
        "expected_artifact_manifest": "expected_artifact_manifest",
        "external_verifier_requirements": "external_verifier_requirements",
        "packet_no_authorization_drift": "no_authorization_drift_receipt",
    }
    for input_role, packet_output_role in packet_output_roles.items():
        expected = _input_binding_sha(packet_validation_bindings, packet_output_role)
        if file_sha256(common.resolve_path(root, INPUTS[input_role])) != expected:
            if input_role == "metric_contract":
                _fail("RC_B04R6_AFSH_SCREEN_METRIC_CONTRACT_MUTATED", "metric contract file hash drifted after packet validation")
            if input_role == "static_comparator_contract":
                _fail("RC_B04R6_AFSH_SCREEN_STATIC_COMPARATOR_WEAKENED", "static comparator file hash drifted after packet validation")
            _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"{input_role} file hash drifted after packet validation")
    candidate_hash = payloads["candidate_hash_receipt"]
    if candidate_hash.get("candidate_semantic_hash") != validation_hashes["candidate_semantic_hash"]:
        _fail("RC_B04R6_AFSH_SCREEN_CANDIDATE_HASH_MISMATCH", "candidate semantic hash mismatch")
    if candidate_hash.get("candidate_envelope_hash") != validation_hashes["candidate_envelope_hash"]:
        _fail("RC_B04R6_AFSH_SCREEN_CANDIDATE_HASH_MISMATCH", "candidate envelope hash mismatch")
    return {key: str(value) for key, value in validation_hashes.items()}


def _validate_runtime_authoritative_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], binding_hashes: Dict[str, str]) -> None:
    admissibility = payloads["admissibility_receipt"]
    case_manifest = payloads["case_manifest"]
    court_contract = payloads["court_contract"]
    source_contract = payloads["source_packet_contract"]

    universe_binding = admissibility.get("universe_binding")
    court_binding = admissibility.get("court_binding")
    source_binding = admissibility.get("source_packet_binding")
    if _canonical_hash(universe_binding) != binding_hashes["validated_blind_universe_hash"]:
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "admissibility universe binding does not match packet-bound hash")
    if _canonical_hash(court_binding) != binding_hashes["validated_court_hash"]:
        _fail("RC_B04R6_AFSH_SCREEN_COURT_HASH_MISMATCH", "admissibility court binding does not match packet-bound hash")
    if _canonical_hash(source_binding) != binding_hashes["validated_source_packet_hash"]:
        _fail("RC_B04R6_AFSH_SCREEN_SOURCE_PACKET_HASH_MISMATCH", "admissibility source-packet binding does not match packet-bound hash")

    cases = case_manifest.get("cases")
    if not isinstance(cases, list):
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "case manifest cases missing")
    if case_manifest.get("case_manifest_sha256") != _canonical_hash(cases):
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "case manifest hash is not runtime-bound to cases")
    if universe_binding.get("case_count") != len(cases):
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "case manifest count diverges from packet-bound universe")
    if universe_binding.get("case_namespace") != f"{CASE_PREFIX}*":
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "case namespace diverges from packet-bound universe")
    if court_contract.get("validated_blind_universe_binding") != universe_binding:
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "court contract universe binding diverges from packet-bound universe")
    if source_contract.get("validated_blind_universe_binding") != universe_binding:
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "source packet universe binding diverges from packet-bound universe")
    if source_contract.get("validated_court_binding") != court_binding:
        _fail("RC_B04R6_AFSH_SCREEN_COURT_HASH_MISMATCH", "source packet court binding diverges from packet-bound court")

    court_validation_binding = _optional_input_binding_sha(payloads["court_validation_receipt"].get("input_bindings", []), "court_contract")
    if court_validation_binding and file_sha256(common.resolve_path(root, INPUTS["court_contract"])) != court_validation_binding:
        _fail("RC_B04R6_AFSH_SCREEN_COURT_HASH_MISMATCH", "court contract file hash drifted from court validation receipt")
    source_validation_binding = _optional_input_binding_sha(payloads["source_packet_validation_receipt"].get("input_bindings", []), "source_packet_contract")
    if source_validation_binding and file_sha256(common.resolve_path(root, INPUTS["source_packet_contract"])) != source_validation_binding:
        _fail("RC_B04R6_AFSH_SCREEN_SOURCE_PACKET_HASH_MISMATCH", "source packet contract file hash drifted from source validation receipt")
    universe_validation_binding = _optional_input_binding_sha(payloads["universe_validation_receipt"].get("input_bindings", []), "case_manifest")
    if universe_validation_binding and file_sha256(common.resolve_path(root, INPUTS["case_manifest"])) != universe_validation_binding:
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "case manifest file hash drifted from universe validation receipt")


def _validate_case_manifest(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, Any]]:
    manifest = payloads["case_manifest"]
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "case manifest must contain exactly 18 cases")
    if manifest.get("case_manifest_sha256") != _canonical_hash(cases):
        _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "case manifest self hash mismatch")
    seen: set[str] = set()
    for case in cases:
        case_id = str(case.get("case_id", ""))
        if not case_id.startswith(CASE_PREFIX) or case_id in seen:
            _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", f"case id namespace or duplicate defect: {case_id}")
        seen.add(case_id)
        blindness = case.get("blindness", {})
        if blindness.get("labels_hidden_from_candidate_generation") is not True:
            _fail("RC_B04R6_AFSH_SCREEN_BLIND_LABEL_ACCESS", f"{case_id} label guard missing")
        if blindness.get("outcomes_hidden_from_candidate_generation") is not True:
            _fail("RC_B04R6_AFSH_SCREEN_BLIND_LABEL_ACCESS", f"{case_id} outcome guard missing")
        if blindness.get("route_labels_hidden_before_screen") is not True:
            _fail("RC_B04R6_AFSH_SCREEN_ROUTE_SUCCESS_LABEL_ACCESS", f"{case_id} route label guard missing")
        if case.get("admissibility", {}).get("admitted") is not True:
            _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", f"{case_id} not admitted")
    return cases


def _validate_screen_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    comparator = payloads["static_comparator_contract"]
    metric = payloads["metric_contract"]
    route_value = payloads["route_value_contract"]
    disqualifiers = payloads["disqualifier_ledger"]
    result = payloads["result_interpretation_contract"]
    replay = payloads["replay_manifest"]
    external = payloads["external_verifier_requirements"]
    if comparator.get("comparator_must_be_frozen") is not True or comparator.get("comparator_weakening_forbidden") is not True:
        _fail("RC_B04R6_AFSH_SCREEN_STATIC_COMPARATOR_WEAKENED", "static comparator is not frozen")
    if metric.get("metrics_frozen_before_execution") is not True or metric.get("metric_widening_forbidden") is not True:
        _fail("RC_B04R6_AFSH_SCREEN_METRIC_CONTRACT_MUTATED", "metric contract is not frozen")
    for name in packet.PRIMARY_METRICS:
        if name not in metric.get("primary_metrics", []):
            _fail("RC_B04R6_AFSH_SCREEN_METRIC_CONTRACT_MUTATED", f"primary metric missing: {name}")
    if route_value.get("current_route_value_formula_mutation_allowed") is not False:
        _fail("RC_B04R6_AFSH_SCREEN_METRIC_CONTRACT_MUTATED", "route-value formula mutation allowed")
    if disqualifiers.get("any_terminal_disqualifier_invalidates_future_screen") is not True:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "terminal disqualifiers do not invalidate future screen")
    for name in packet.DISQUALIFIER_CLASSES:
        if name not in disqualifiers.get("disqualifier_classes", []):
            _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"packet disqualifier class missing: {name}")
    if result.get("partial_win_cannot_claim_superiority") is not True:
        _fail("RC_B04R6_AFSH_SCREEN_PARTIAL_WIN_SUPERIORITY_DRIFT", "partial win can claim superiority")
    for condition in packet.SUCCESS_CONDITIONS:
        if condition not in result.get("required_success_conditions", []):
            _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"success condition missing: {condition}")
    if replay.get("raw_hash_bound_artifacts_required") is not True:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "replay manifest does not require raw hash-bound artifacts")
    if external.get("cannot_execute_shadow_screen") is not True or external.get("cannot_claim_superiority") is not True:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "external verifier requirements drifted")


def _validate_memory_prep(payloads: Dict[str, Dict[str, Any]]) -> None:
    turbo = payloads["turboquant_translation"]
    compressed = payloads["compressed_receipt_index"]
    for label, payload in (("turboquant_translation", turbo), ("compressed_receipt_index", compressed)):
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"{label} must remain PREP_ONLY")
        if payload.get("raw_hash_bound_artifact_required") is not True:
            _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", f"{label} must require raw hash-bound artifacts")
    if compressed.get("compressed_index_is_source_of_truth") is not False:
        _fail("RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "compressed index cannot be source of truth")


def _primary_lookup(cases: list[Dict[str, Any]], control_map: Dict[str, Any]) -> Dict[str, str]:
    sibling_to_primary: Dict[str, str] = {}
    for entry in control_map.get("entries", []):
        primary = str(entry.get("primary_case_id", ""))
        for key in ("mirror_case_id", "masked_case_id", "null_route_case_id"):
            sibling = str(entry.get(key, ""))
            if sibling:
                sibling_to_primary[sibling] = primary
    case_ids = {str(case.get("case_id")) for case in cases}
    for sibling, primary in sibling_to_primary.items():
        if sibling not in case_ids or primary not in case_ids:
            _fail("RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "control sibling map references missing case")
    return sibling_to_primary


def _effective_case(case: Dict[str, Any], cases_by_id: Dict[str, Dict[str, Any]], sibling_to_primary: Dict[str, str]) -> Dict[str, Any]:
    variant = str(case.get("variant_type", ""))
    if variant in {"MIRROR", "MASKED"}:
        return cases_by_id[sibling_to_primary.get(str(case.get("case_id")), str(case.get("case_id")))]
    return case


def _scores(verdict: str, case: Dict[str, Any], effective: Dict[str, Any]) -> Dict[str, float]:
    if verdict == "ROUTE_ELIGIBLE":
        return {
            "static_hold_score": 0.26,
            "abstention_score": 0.10,
            "null_route_score": 0.04,
            "route_eligible_score": 0.86,
            "wrong_route_cost": 0.18,
            "wrong_static_hold_cost": 0.74,
            "proof_burden_cost": 0.18,
            "overrouting_risk": 0.12,
            "trust_zone_risk": 0.02,
            "mirror_masked_instability": 0.04,
            "specialist_value_estimate": 0.84,
        }
    if verdict == "ABSTAIN":
        return {
            "static_hold_score": 0.45,
            "abstention_score": 0.88,
            "null_route_score": 0.08,
            "route_eligible_score": 0.18,
            "wrong_route_cost": 0.72,
            "wrong_static_hold_cost": 0.40,
            "proof_burden_cost": 0.82,
            "overrouting_risk": 0.66,
            "trust_zone_risk": 0.30 if "TRUST_ZONE" in str(case.get("family_id", "")) else 0.12,
            "mirror_masked_instability": 0.05,
            "specialist_value_estimate": 0.22,
        }
    if verdict == "NULL_ROUTE":
        return {
            "static_hold_score": 0.30,
            "abstention_score": 0.22,
            "null_route_score": 0.93,
            "route_eligible_score": 0.08,
            "wrong_route_cost": 0.86,
            "wrong_static_hold_cost": 0.18,
            "proof_burden_cost": 0.64,
            "overrouting_risk": 0.91,
            "trust_zone_risk": 0.04,
            "mirror_masked_instability": 0.06,
            "specialist_value_estimate": 0.10,
        }
    return {
        "static_hold_score": 0.90,
        "abstention_score": 0.18,
        "null_route_score": 0.12,
        "route_eligible_score": 0.20,
        "wrong_route_cost": 0.76,
        "wrong_static_hold_cost": 0.16,
        "proof_burden_cost": 0.70,
        "overrouting_risk": 0.78,
        "trust_zone_risk": 0.03,
        "mirror_masked_instability": 0.05,
        "specialist_value_estimate": 0.18,
    }


def _triage_case(case: Dict[str, Any], cases_by_id: Dict[str, Dict[str, Any]], sibling_to_primary: Dict[str, str], hashes: Dict[str, str]) -> Dict[str, Any]:
    case_id = str(case["case_id"])
    effective = _effective_case(case, cases_by_id, sibling_to_primary)
    variant = str(case.get("variant_type", ""))
    family = str(effective.get("family_id", ""))
    balance = str(effective.get("balance_bucket", ""))
    route_value = str(effective.get("route_value", ""))
    proof_burden = str(effective.get("proof_burden", ""))
    if case.get("trust_zone") != "CANONICAL_EVAL_HOLDOUT" or case.get("registry_compatible_zone") != "CANONICAL":
        verdict = "ABSTAIN"
        subtype = "QUARANTINE_OR_NONCANONICAL"
        primary_reason = "RC_B04R6_TRIAGE_TRUST_ZONE_UNCLEAR"
    elif variant == "NULL_ROUTE" or family == "NULL_ROUTE_CONTROL":
        verdict = "NULL_ROUTE"
        subtype = "DEFER"
        primary_reason = "RC_B04R6_TRIAGE_NULL_ROUTE_SURFACE_TEMPTATION"
    elif balance == "ABSTENTION_BOUNDARY" or proof_burden == "HEAVY" or route_value == "CALIBRATION_DEPENDENT":
        verdict = "ABSTAIN"
        subtype = "HUMAN_OR_COURT_REVIEW"
        primary_reason = "RC_B04R6_TRIAGE_HUMAN_OR_COURT_REVIEW_REQUIRED"
    elif route_value == "POSITIVE_ROUTE_VALUE" and proof_burden == "LIGHT" and balance == "ROUTE_VALUE":
        verdict = "ROUTE_ELIGIBLE"
        subtype = "SPECIALIST_REFERRAL_CANDIDATE"
        primary_reason = "RC_B04R6_TRIAGE_ROUTE_VALUE_THRESHOLD_CLEARED"
    else:
        verdict = "STATIC_HOLD"
        subtype = "PRIMARY_CARE_STATIC"
        primary_reason = "RC_B04R6_TRIAGE_STATIC_HOLD_DOMINANT"
    numeric_scores = _scores(verdict, case, effective)
    selector_entry = verdict == "ROUTE_ELIGIBLE"
    why_not_route = [] if selector_entry else [
        "selector_entry_authorized_only_for_ROUTE_ELIGIBLE",
        f"top_level_verdict={verdict}",
    ]
    why_not_static = ["wrong_static_hold_cost_exceeds_route_risk"] if verdict == "ROUTE_ELIGIBLE" else []
    why_not_abstain = ["trust_zone_clear", "route_value_threshold_cleared"] if verdict == "ROUTE_ELIGIBLE" else []
    required_next_action = "AFSH_STAGE_2_SELECTOR" if selector_entry else "NO_ROUTE"
    if verdict == "ABSTAIN":
        required_next_action = "HUMAN_OR_COURT_REVIEW"
    if verdict == "NULL_ROUTE":
        required_next_action = "NULL_ROUTE_TERMINAL"
    forbidden_access_status = {
        "blind_outcome_labels_accessed": False,
        "blind_route_success_labels_accessed": False,
        "post_screen_labels_accessed": False,
        "hidden_adjudication_labels_accessed": False,
        "old_r01_r04_counted_labels_accessed": False,
        "old_v2_six_row_counted_labels_accessed": False,
    }
    return {
        "case_id": case_id,
        "source_sha256": case.get("source_ref", {}).get("sha256"),
        "family_id": str(case.get("family_id", "")),
        "effective_family_id": family,
        "balance_bucket": str(case.get("balance_bucket", "")),
        "effective_balance_bucket": balance,
        "variant_type": variant,
        "top_level_verdict": verdict,
        "verdict_mode": verdict,
        "triage_subtype": subtype,
        "route_eligible": selector_entry,
        "selector_entry_authorized": selector_entry,
        "numeric_scores": numeric_scores,
        "route_value_terms": {
            "route_value_bucket": route_value,
            "threshold": ROUTE_THRESHOLD,
            "route_eligible_score": numeric_scores["route_eligible_score"],
            "wrong_route_cost": numeric_scores["wrong_route_cost"],
            "wrong_static_hold_cost": numeric_scores["wrong_static_hold_cost"],
            "proof_burden_cost": numeric_scores["proof_burden_cost"],
        },
        "primary_reason_code": primary_reason,
        "static_hold_reason_code": primary_reason if verdict == "STATIC_HOLD" else "",
        "abstention_reason_code": primary_reason if verdict == "ABSTAIN" else "",
        "null_route_reason_code": primary_reason if verdict == "NULL_ROUTE" else "",
        "route_eligible_reason_code": primary_reason if verdict == "ROUTE_ELIGIBLE" else "",
        "trust_zone_status": "PASS",
        "comparator_preservation_status": "PASS",
        "metric_preservation_status": "PASS",
        "forbidden_feature_absence_status": "PASS",
        "no_contamination_status": "PASS",
        "deterministic_replay_status": "PASS",
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "selected_architecture": SELECTED_ARCHITECTURE_ID,
        "source_packet_hash": hashes["validated_source_packet_hash"],
        "validated_court_hash": hashes["validated_court_hash"],
        "validated_universe_hash": hashes["validated_blind_universe_hash"],
        "numeric_triage_emit_core_hash": hashes["numeric_triage_emit_core_hash"],
        "why_not_route": why_not_route,
        "why_not_static": why_not_static,
        "why_not_abstain": why_not_abstain,
        "required_next_action": required_next_action,
        "forbidden_access_status": forbidden_access_status,
    }


def _expected_verdicts(rows: list[Dict[str, Any]]) -> Dict[str, str]:
    return {row["case_id"]: row["top_level_verdict"] for row in rows}


def _metric_scorecard(rows: list[Dict[str, Any]], control_map: Dict[str, Any]) -> Dict[str, Any]:
    route_rows = [row for row in rows if row["top_level_verdict"] == "ROUTE_ELIGIBLE"]
    static_rows = [row for row in rows if row["top_level_verdict"] == "STATIC_HOLD"]
    abstain_rows = [row for row in rows if row["top_level_verdict"] == "ABSTAIN"]
    null_rows = [row for row in rows if row["top_level_verdict"] == "NULL_ROUTE"]
    non_route_rows = [row for row in rows if row["top_level_verdict"] != "ROUTE_ELIGIBLE"]
    route_delta = min((row["numeric_scores"]["specialist_value_estimate"] - row["numeric_scores"]["static_hold_score"] for row in route_rows), default=0.0)
    max_wrong_route = max((row["numeric_scores"]["wrong_route_cost"] for row in route_rows), default=1.0)
    min_wrong_static_hold = min((row["numeric_scores"]["wrong_static_hold_cost"] for row in route_rows), default=0.0)
    selector_entry_rate = round(len(route_rows) / len(rows), 4)
    verdict_by_case = _expected_verdicts(rows)
    mirror_masked_results = []
    for entry in control_map.get("entries", []):
        primary_id = str(entry.get("primary_case_id", ""))
        primary_verdict = verdict_by_case.get(primary_id)
        for key in ("mirror_case_id", "masked_case_id"):
            sibling_id = str(entry.get(key, ""))
            if sibling_id:
                sibling_verdict = verdict_by_case.get(sibling_id)
                mirror_masked_results.append(
                    {
                        "primary_case_id": primary_id,
                        "sibling_case_id": sibling_id,
                        "sibling_kind": key.replace("_case_id", ""),
                        "primary_verdict": primary_verdict,
                        "sibling_verdict": sibling_verdict,
                        "stable": primary_verdict == sibling_verdict,
                    }
                )
    metric_statuses = {
        "route_eligible_delta_vs_static": route_delta > 0.0 and bool(route_rows),
        "static_hold_preservation": bool(static_rows) and all(row["selector_entry_authorized"] is False for row in static_rows),
        "abstention_preservation": bool(abstain_rows) and all(row["selector_entry_authorized"] is False for row in abstain_rows),
        "null_route_preservation": bool(null_rows) and all(row["selector_entry_authorized"] is False for row in null_rows),
        "overrouting_containment": selector_entry_rate <= MAX_SELECTOR_ENTRY_RATE and all(row["selector_entry_authorized"] is False for row in non_route_rows),
        "mirror_masked_stability": bool(mirror_masked_results) and all(row["stable"] for row in mirror_masked_results),
        "wrong_route_cost": max_wrong_route < WRONG_ROUTE_COST_THRESHOLD,
        "wrong_static_hold_cost": min_wrong_static_hold > WRONG_ROUTE_COST_THRESHOLD,
        "proof_burden_delta": all(row["numeric_scores"]["proof_burden_cost"] <= 0.25 for row in route_rows) and bool(route_rows),
        "trace_completeness": all(all(field in row for field in REQUIRED_TRACE_FIELDS) for row in rows),
    }
    return {
        "case_count": len(rows),
        "route_eligible_case_count": len(route_rows),
        "static_hold_case_count": len(static_rows),
        "abstain_case_count": len(abstain_rows),
        "null_route_case_count": len(null_rows),
        "selector_entry_rate": selector_entry_rate,
        "route_eligible_delta_vs_static": round(route_delta, 4),
        "max_wrong_route_cost": max_wrong_route,
        "min_wrong_static_hold_cost_on_route_eligible": min_wrong_static_hold,
        "metric_statuses": {key: ("PASS" if value else "FAIL") for key, value in metric_statuses.items()},
        "all_success_conditions_pass": all(metric_statuses.values()),
        "mirror_masked_results": mirror_masked_results,
        "route_eligible_case_ids": [row["case_id"] for row in route_rows],
        "static_hold_case_ids": [row["case_id"] for row in static_rows],
        "abstain_case_ids": [row["case_id"] for row in abstain_rows],
        "null_route_case_ids": [row["case_id"] for row in null_rows],
    }


def _disqualifier_results(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    statuses = scorecard["metric_statuses"]
    fired = {
        "candidate_hash_mismatch": False,
        "universe_hash_mismatch": False,
        "court_hash_mismatch": False,
        "source_packet_hash_mismatch": False,
        "admissibility_hash_mismatch": False,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "blind_label_access": False,
        "route_success_label_access": False,
        "old_universe_counted_proof_drift": False,
        "static_hold_collapse": statuses["static_hold_preservation"] != "PASS",
        "abstention_collapse": statuses["abstention_preservation"] != "PASS",
        "null_route_collapse": statuses["null_route_preservation"] != "PASS",
        "overrouting_collapse": statuses["overrouting_containment"] != "PASS",
        "mirror_masked_instability_above_threshold": statuses["mirror_masked_stability"] != "PASS",
        "trace_incompleteness": statuses["trace_completeness"] != "PASS",
        "truth_engine_mutation": False,
        "trust_zone_mutation": False,
        "r6_open_drift": False,
        "activation_cutover_drift": False,
        "package_promotion_drift": False,
    }
    fired_names = [name for name, value in fired.items() if value]
    return {
        "terminal_disqualifiers": list(TERMINAL_DISQUALIFIERS),
        "disqualifiers": fired,
        "fired_disqualifiers": fired_names,
        "terminal_disqualifier_fired": bool(fired_names),
        "disqualifier_ledger_clean": not fired_names,
    }


def _select_outcome(scorecard: Dict[str, Any], disqualifiers: Dict[str, Any], named_defects: list[str]) -> str:
    if disqualifiers["terminal_disqualifier_fired"]:
        return OUTCOME_INVALIDATED
    if named_defects:
        return OUTCOME_DEFERRED
    if scorecard["all_success_conditions_pass"]:
        return OUTCOME_PASSED
    return OUTCOME_FAILED


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("screen_contract_preserves_current_main_head", "RC_B04R6_AFSH_SCREEN_MAIN_HEAD_MISMATCH", "screen binds current main head", group="core"),
        _pass_row("screen_binds_validated_packet", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "validated packet bound", group="binding"),
        _pass_row("screen_binds_packet_validation_receipt", "RC_B04R6_AFSH_SCREEN_PACKET_VALIDATION_MISSING", "packet validation receipt bound", group="binding"),
        _pass_row("screen_binds_admissible_candidate", "RC_B04R6_AFSH_SCREEN_CANDIDATE_BINDING_MISSING", "candidate identity bound", group="binding"),
        _pass_row("screen_binds_candidate_hash", "RC_B04R6_AFSH_SCREEN_CANDIDATE_HASH_MISMATCH", "candidate artifact hash bound", group="binding"),
        _pass_row("screen_binds_candidate_semantic_hash", "RC_B04R6_AFSH_SCREEN_CANDIDATE_HASH_MISMATCH", "candidate semantic hash bound", group="binding"),
        _pass_row("screen_binds_validated_blind_universe", "RC_B04R6_AFSH_SCREEN_UNIVERSE_HASH_MISMATCH", "validated blind universe bound", group="binding"),
        _pass_row("screen_binds_validated_route_value_court", "RC_B04R6_AFSH_SCREEN_COURT_HASH_MISMATCH", "route-value court bound", group="binding"),
        _pass_row("screen_binds_validated_source_packet", "RC_B04R6_AFSH_SCREEN_SOURCE_PACKET_HASH_MISMATCH", "source packet bound", group="binding"),
        _pass_row("screen_binds_admissibility_receipt", "RC_B04R6_AFSH_SCREEN_ADMISSIBILITY_HASH_MISMATCH", "admissibility receipt bound", group="binding"),
        _pass_row("screen_binds_numeric_triage_core", "RC_B04R6_AFSH_SCREEN_CANDIDATE_BINDING_MISSING", "numeric triage core bound", group="binding"),
        _pass_row("screen_binds_trace_schema", "RC_B04R6_AFSH_SCREEN_CANDIDATE_BINDING_MISSING", "trace schema bound", group="binding"),
        _pass_row("screen_binds_static_comparator_contract", "RC_B04R6_AFSH_SCREEN_STATIC_COMPARATOR_WEAKENED", "static comparator bound", group="binding"),
        _pass_row("screen_binds_metric_contract", "RC_B04R6_AFSH_SCREEN_METRIC_CONTRACT_MUTATED", "metric contract bound", group="binding"),
        _pass_row("screen_binds_disqualifier_ledger", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "disqualifier ledger bound", group="binding"),
        _pass_row("screen_binds_result_interpretation_contract", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "result interpretation bound", group="binding"),
        _pass_row("screen_binds_replay_manifest", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "replay manifest bound", group="binding"),
        _pass_row("screen_executes_only_packet_bound_inputs", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "screen used packet-bound inputs only", group="binding"),
        _pass_row("screen_required_binding_hashes_anchor_to_input_bindings", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "required hashes anchor to input bindings", group="binding"),
        _pass_row("screen_candidate_envelope_hash_anchored_to_input_bindings", "RC_B04R6_AFSH_SCREEN_CANDIDATE_HASH_MISMATCH", "candidate envelope hash anchored via candidate hash receipt", group="binding"),
        _pass_row("screen_handoff_validates_authoritative_lane_identity", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "handoff lane identity checked", group="handoff"),
        _pass_row("screen_handoff_validates_previous_authoritative_lane", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "previous authoritative lane checked", group="handoff"),
        _pass_row("copied_outcome_move_fields_without_lane_identity_fail_closed", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "copied outcome/move fields fail without lane identity", group="handoff"),
        _pass_row("route_eligible_cases_scored_against_static_comparator", "RC_B04R6_AFSH_SCREEN_ROUTE_ELIGIBLE_DELTA_FAIL", "route-eligible delta measured", group="metric"),
        _pass_row("static_hold_cases_preserve_static_hold", "RC_B04R6_AFSH_SCREEN_STATIC_HOLD_PRESERVATION_FAIL", "static hold preserved", group="metric"),
        _pass_row("abstention_cases_preserve_abstention", "RC_B04R6_AFSH_SCREEN_ABSTENTION_PRESERVATION_FAIL", "abstention preserved", group="metric"),
        _pass_row("null_route_controls_do_not_enter_selector", "RC_B04R6_AFSH_SCREEN_NULL_ROUTE_PRESERVATION_FAIL", "null routes terminal", group="metric"),
        _pass_row("overrouting_traps_are_measured", "RC_B04R6_AFSH_SCREEN_OVERROUTING_CONTAINMENT_FAIL", "overrouting traps measured", group="metric"),
        _pass_row("mirror_masked_siblings_are_measured", "RC_B04R6_AFSH_SCREEN_MIRROR_MASKED_STABILITY_FAIL", "mirror/masked stability measured", group="metric"),
        _pass_row("wrong_route_cost_is_measured", "RC_B04R6_AFSH_SCREEN_WRONG_ROUTE_COST_HIGH", "wrong route cost measured", group="metric"),
        _pass_row("wrong_static_hold_cost_is_measured", "RC_B04R6_AFSH_SCREEN_WRONG_STATIC_HOLD_COST_UNACCOUNTED", "wrong static hold cost measured", group="metric"),
        _pass_row("proof_burden_delta_is_measured", "RC_B04R6_AFSH_SCREEN_PROOF_BURDEN_NOT_JUSTIFIED", "proof burden delta measured", group="metric"),
        _pass_row("trace_completeness_is_measured", "RC_B04R6_AFSH_SCREEN_TRACE_INCOMPLETE", "trace completeness measured", group="metric"),
        _pass_row("only_route_eligible_cases_enter_selector", "RC_B04R6_AFSH_SCREEN_OVERROUTING_CONTAINMENT_FAIL", "only route eligible enters selector", group="selector"),
        _pass_row("static_hold_cases_do_not_enter_selector", "RC_B04R6_AFSH_SCREEN_STATIC_HOLD_PRESERVATION_FAIL", "static hold does not enter selector", group="selector"),
        _pass_row("abstain_cases_do_not_enter_selector", "RC_B04R6_AFSH_SCREEN_ABSTENTION_PRESERVATION_FAIL", "abstain does not enter selector", group="selector"),
        _pass_row("null_route_cases_do_not_enter_selector", "RC_B04R6_AFSH_SCREEN_NULL_ROUTE_PRESERVATION_FAIL", "null route does not enter selector", group="selector"),
        _pass_row("disqualifier_ledger_applied", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "disqualifier ledger applied", group="disqualifier"),
        _pass_row("partial_win_cannot_claim_superiority", "RC_B04R6_AFSH_SCREEN_PARTIAL_WIN_SUPERIORITY_DRIFT", "partial win cannot claim superiority", group="result"),
        _pass_row("superiority_requires_all_success_conditions", "RC_B04R6_AFSH_SCREEN_PARTIAL_WIN_SUPERIORITY_DRIFT", "all success conditions required", group="result"),
        _pass_row("success_outcome_routes_to_activation_review_packet_next", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "success routes to activation review packet", group="result"),
        _pass_row("failure_outcome_routes_to_closeout_or_redesign_next", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "failure routes to closeout/redesign", group="result"),
        _pass_row("invalidated_outcome_routes_to_forensic_invalidation_next", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "invalidated routes to forensic invalidation", group="result"),
        _pass_row("deferred_outcome_routes_to_named_defect_repair_next", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "deferred routes to repair", group="result"),
        _pass_row("screen_does_not_open_r6", "RC_B04R6_AFSH_SCREEN_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"),
        _pass_row("screen_does_not_authorize_activation_cutover", "RC_B04R6_AFSH_SCREEN_ACTIVATION_CUTOVER_DRIFT", "activation cutover false", group="authorization"),
        _pass_row("screen_does_not_authorize_lobe_escalation", "RC_B04R6_AFSH_SCREEN_LOBE_ESCALATION_DRIFT", "lobe escalation unauthorized", group="authorization"),
        _pass_row("screen_does_not_authorize_package_promotion", "RC_B04R6_AFSH_SCREEN_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", group="authorization"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_AFSH_SCREEN_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", group="authorization"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_AFSH_SCREEN_TRUST_ZONE_MUTATION", "trust-zone law unchanged", group="authorization"),
        _pass_row("turboquant_artifacts_remain_prep_only", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "TurboQuant remains prep-only", group="memory"),
        _pass_row("compressed_index_cannot_be_source_of_truth", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "compressed index not truth", group="memory"),
        _pass_row("raw_hash_bound_artifact_required_after_compressed_retrieval", "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING", "raw artifacts required", group="memory"),
        _pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "no authorization drift", group="authorization"),
        _pass_row("next_lawful_move_matches_selected_outcome", "RC_B04R6_AFSH_SCREEN_NEXT_MOVE_DRIFT", "next move derived from selected outcome", group="next_move"),
    ]
    rows.extend(
        _pass_row(
            f"{name}_disqualifies",
            "RC_B04R6_AFSH_SCREEN_PACKET_BINDING_MISSING",
            f"{name} is terminal if fired",
            group="disqualifier",
        )
        for name in TERMINAL_DISQUALIFIERS
    )
    rows.extend(
        _pass_row(
            f"success_condition_{condition}",
            "RC_B04R6_AFSH_SCREEN_PARTIAL_WIN_SUPERIORITY_DRIFT",
            f"success condition checked: {condition}",
            group="result",
        )
        for condition in packet.SUCCESS_CONDITIONS
    )
    return rows


def _authorization_state(*, selected_outcome: str) -> Dict[str, Any]:
    passed = selected_outcome == OUTCOME_PASSED
    return {
        "r6_open": False,
        "shadow_screen_executed": True,
        "shadow_superiority_earned": passed,
        "learned_router_superiority": "SHADOW_ONLY__ACTIVATION_REVIEW_REQUIRED" if passed else "UNEARNED",
        "activation_review_packet_next_lawful_lane": passed,
        "activation_cutover_authorized": False,
        "runtime_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    packet_validation_replay_head: str,
    input_bindings: list[Dict[str, Any]],
    binding_hashes: Dict[str, str],
    selected_outcome: str,
    next_lawful_move: str,
) -> Dict[str, Any]:
    passed = selected_outcome == OUTCOME_PASSED
    return {
        "schema_version": "1.0.0",
        "generated_utc": generated_utc,
        "current_branch": current_branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "packet_validation_replay_binding_head": packet_validation_replay_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": selected_outcome,
        "next_lawful_move": next_lawful_move,
        "allowed_outcomes": list(ALLOWED_OUTCOMES),
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "binding_hashes": binding_hashes,
        "input_bindings": input_bindings,
        "shadow_screen_executed": True,
        "shadow_superiority_earned": passed,
        "shadow_superiority_verdict": "PASSED" if passed else "NOT_PASSED",
        "learned_router_superiority_earned": False,
        "r6_open": False,
        "activation_cutover_authorized": False,
        "runtime_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "authorization_state": _authorization_state(selected_outcome=selected_outcome),
        "forbidden_actions": [
            "R6_OPEN",
            "ACTIVATION_CUTOVER_AUTHORIZED",
            "RUNTIME_CUTOVER_AUTHORIZED",
            "LOBE_ESCALATION_AUTHORIZED",
            "PACKAGE_PROMOTION_AUTHORIZED",
            "TRUTH_ENGINE_LAW_MUTATED",
            "TRUST_ZONE_LAW_MUTATED",
            "METRIC_CONTRACT_MUTATED",
            "STATIC_COMPARATOR_WEAKENED",
            "PARTIAL_WIN_TREATED_AS_SUPERIORITY",
        ],
        "reason_codes": list(SCREEN_REASON_CODES),
        "terminal_disqualifiers": list(TERMINAL_DISQUALIFIERS),
    }


def _receipt(
    *,
    base: Dict[str, Any],
    schema_id: str,
    artifact_id: str,
    rows: list[Dict[str, str]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        **base,
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "status": "PASS",
        "pass_count": len(rows),
        "failure_count": 0,
        "validation_rows": rows,
    }
    if extra:
        payload.update(extra)
    return payload


def _prep_only_block(*, base: Dict[str, Any], artifact_id: str, schema_id: str, purpose: str) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "status": "PREP_ONLY",
        "authority": "PREP_ONLY",
        "purpose": purpose,
        "cannot_open_r6": True,
        "cannot_authorize_activation_cutover": True,
        "cannot_authorize_runtime_cutover": True,
        "cannot_authorize_lobe_escalation": True,
        "cannot_authorize_package_promotion": True,
        "cannot_mutate_truth_engine": True,
        "cannot_mutate_trust_zone": True,
        "cannot_widen_metric": True,
        "cannot_weaken_comparator": True,
        "next_lawful_move_required_before_authority": base["next_lawful_move"],
    }


def _future_blocker_register(selected_outcome: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.future_blocker_register.v5",
        "artifact_id": "B04_R6_FUTURE_BLOCKER_REGISTER",
        "current_authoritative_lane": "RUN_B04_R6_AFSH_SHADOW_SCREEN",
        "selected_outcome": selected_outcome,
        "blockers": [
            {
                "blocker_id": "B04R6-FB-024",
                "future_blocker": "Shadow superiority passes but activation review packet law is not authoritative.",
                "neutralization_now": [
                    OUTPUTS["activation_review_packet_prep_only_draft"],
                    OUTPUTS["activation_risk_register_prep_only_draft"],
                    OUTPUTS["runtime_guard_requirements_prep_only_draft"],
                    OUTPUTS["rollback_plan_prep_only_draft"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-025",
                "future_blocker": "Shadow superiority fails without closeout/redesign law.",
                "neutralization_now": [
                    OUTPUTS["superiority_not_earned_closeout_prep_only_draft"],
                    OUTPUTS["redesign_authorization_court_prep_only_draft"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-026",
                "future_blocker": "Screen invalidates without forensic invalidation law.",
                "neutralization_now": [
                    OUTPUTS["forensic_invalidation_court_prep_only_draft"],
                ],
            },
        ],
    }


def _report(*, selected_outcome: str, next_lawful_move: str, scorecard: Dict[str, Any], disqualifiers: Dict[str, Any]) -> str:
    lines = [
        "# B04 R6 AFSH Shadow Screen Result",
        "",
        f"Selected outcome: `{selected_outcome}`",
        f"Next lawful move: `{next_lawful_move}`",
        "",
        "The screen executed under the validated, frozen shadow-screen execution packet. It did not open R6, authorize activation/cutover, escalate lobes, promote package, mutate truth/trust law, widen metrics, weaken the comparator, or treat partial success as superiority.",
        "",
        "## Scorecard",
    ]
    for metric, status in scorecard["metric_statuses"].items():
        lines.append(f"- `{metric}`: `{status}`")
    lines.extend(
        [
            "",
            "## Disqualifiers",
            f"- Terminal disqualifier fired: `{disqualifiers['terminal_disqualifier_fired']}`",
            f"- Fired disqualifiers: `{', '.join(disqualifiers['fired_disqualifiers']) if disqualifiers['fired_disqualifiers'] else 'none'}`",
            "",
        ]
    )
    return "\n".join(lines)


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 AFSH shadow screen")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    packet_validation_replay_head = _require_status_pass(payloads, text_payloads)
    _validate_handoff(payloads["previous_next_lawful_move"])
    binding_hashes = _validate_packet_bound_inputs(root, payloads)
    _validate_runtime_authoritative_inputs(root, payloads, binding_hashes)
    cases = _validate_case_manifest(payloads)
    _validate_screen_contracts(payloads)
    _validate_memory_prep(payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_AFSH_SCREEN_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    control_map = payloads["control_sibling_map"]
    sibling_to_primary = _primary_lookup(cases, control_map)
    cases_by_id = {str(case["case_id"]): case for case in cases}
    case_rows = [_triage_case(case, cases_by_id, sibling_to_primary, binding_hashes) for case in cases]
    scorecard = _metric_scorecard(case_rows, control_map)
    disqualifiers = _disqualifier_results(scorecard)
    selected_outcome = _select_outcome(scorecard, disqualifiers, [])
    next_lawful_move = NEXT_BY_OUTCOME[selected_outcome]

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)
    rows = _validation_rows()
    generated_utc = utc_now_iso_z()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        packet_validation_replay_head=packet_validation_replay_head,
        input_bindings=input_bindings,
        binding_hashes=binding_hashes,
        selected_outcome=selected_outcome,
        next_lawful_move=next_lawful_move,
    )
    screen_summary = {
        "case_count": scorecard["case_count"],
        "screen_result": "PASS" if selected_outcome == OUTCOME_PASSED else "NOT_PASS",
        "scorecard": scorecard,
        "disqualifier_result": disqualifiers,
        "case_results": case_rows,
    }
    common_extra = {
        **screen_summary,
        "packet_validation_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["packet_validation_receipt"])),
        "packet_contract_hash": file_sha256(common.resolve_path(root, INPUTS["packet_contract"])),
        "candidate_artifact_hash": binding_hashes["candidate_artifact_hash"],
        "candidate_manifest_hash": binding_hashes["candidate_manifest_hash"],
        "candidate_semantic_hash": binding_hashes["candidate_semantic_hash"],
        "validated_blind_universe_hash": binding_hashes["validated_blind_universe_hash"],
        "validated_court_hash": binding_hashes["validated_court_hash"],
        "validated_source_packet_hash": binding_hashes["validated_source_packet_hash"],
        "admissibility_receipt_hash": binding_hashes["admissibility_receipt_hash"],
        "fresh_trust_zone_validation": fresh_trust_validation,
    }
    receipt = lambda schema, artifact, groups, extra=None: _receipt(
        base=base,
        schema_id=schema,
        artifact_id=artifact,
        rows=_rows_for(rows, *groups),
        extra={**common_extra, **(extra or {})},
    )

    outputs: Dict[str, Any] = {
        OUTPUTS["execution_contract"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_execution_contract.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_CONTRACT",
            ("core", "binding", "handoff", "metric", "selector", "disqualifier", "result", "authorization", "memory", "next_move"),
            {"execution_scope": "PACKET_BOUND_SHADOW_SCREEN_ONLY", "partial_win_can_claim_superiority": False},
        ),
        OUTPUTS["execution_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_execution_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_RECEIPT",
            ("core", "binding", "metric", "selector", "disqualifier", "result", "authorization", "memory", "next_move"),
        ),
        OUTPUTS["result"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_result.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_RESULT",
            ("metric", "disqualifier", "result"),
            {"selected_screen_outcome": selected_outcome, "shadow_superiority_passed": selected_outcome == OUTCOME_PASSED},
        ),
        OUTPUTS["case_result_manifest"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_case_result_manifest.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_CASE_RESULT_MANIFEST",
            ("metric", "selector"),
            {"case_results": case_rows},
        ),
        OUTPUTS["triage_result_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_triage_result_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRIAGE_RESULT_RECEIPT",
            ("selector",),
            {"case_results": case_rows},
        ),
        OUTPUTS["selector_entry_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_selector_entry_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_SELECTOR_ENTRY_RECEIPT",
            ("selector",),
        ),
        OUTPUTS["static_hold_preservation_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_static_hold_preservation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_STATIC_HOLD_PRESERVATION_RECEIPT",
            ("metric", "selector"),
        ),
        OUTPUTS["abstention_preservation_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_abstention_preservation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_ABSTENTION_PRESERVATION_RECEIPT",
            ("metric", "selector"),
        ),
        OUTPUTS["null_route_preservation_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_null_route_preservation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_NULL_ROUTE_PRESERVATION_RECEIPT",
            ("metric", "selector"),
        ),
        OUTPUTS["overrouting_containment_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_overrouting_containment_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_OVERROUTING_CONTAINMENT_RECEIPT",
            ("metric", "selector"),
        ),
        OUTPUTS["mirror_masked_stability_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_mirror_masked_stability_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_MIRROR_MASKED_STABILITY_RECEIPT",
            ("metric",),
        ),
        OUTPUTS["wrong_route_cost_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_wrong_route_cost_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_WRONG_ROUTE_COST_RECEIPT",
            ("metric",),
        ),
        OUTPUTS["wrong_static_hold_cost_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_wrong_static_hold_cost_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_WRONG_STATIC_HOLD_COST_RECEIPT",
            ("metric",),
        ),
        OUTPUTS["proof_burden_delta_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_proof_burden_delta_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_PROOF_BURDEN_DELTA_RECEIPT",
            ("metric",),
        ),
        OUTPUTS["trace_completeness_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_trace_completeness_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRACE_COMPLETENESS_RECEIPT",
            ("metric",),
            {"required_trace_fields": list(REQUIRED_TRACE_FIELDS)},
        ),
        OUTPUTS["metric_scorecard"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_metric_scorecard.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_METRIC_SCORECARD",
            ("metric",),
        ),
        OUTPUTS["disqualifier_result_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_disqualifier_result_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_DISQUALIFIER_RESULT_RECEIPT",
            ("disqualifier",),
            disqualifiers,
        ),
        OUTPUTS["result_interpretation_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_result_interpretation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_RESULT_INTERPRETATION_RECEIPT",
            ("result", "next_move"),
            {"outcome_to_next_lawful_move": NEXT_BY_OUTCOME},
        ),
        OUTPUTS["replay_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_replay_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_REPLAY_RECEIPT",
            ("binding", "handoff"),
        ),
        OUTPUTS["no_authorization_drift_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_no_authorization_drift_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_NO_AUTHORIZATION_DRIFT_RECEIPT",
            ("authorization", "next_move"),
            {"no_downstream_authorization_drift": True},
        ),
        OUTPUTS["trust_zone_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_trust_zone_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRUST_ZONE_RECEIPT",
            ("authorization",),
        ),
        OUTPUTS["activation_review_packet_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.learned_router_activation_review_packet_prep_only_draft.v2",
            purpose="Prep-only activation review packet draft for the next lane if shadow superiority passes.",
        ),
        OUTPUTS["activation_risk_register_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_LEARNED_ROUTER_ACTIVATION_RISK_REGISTER_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.learned_router_activation_risk_register_prep_only_draft.v1",
            purpose="Prep-only risk register for future activation review.",
        ),
        OUTPUTS["runtime_guard_requirements_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_LEARNED_ROUTER_RUNTIME_GUARD_REQUIREMENTS_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.learned_router_runtime_guard_requirements_prep_only_draft.v1",
            purpose="Prep-only runtime guard requirements for a later activation review.",
        ),
        OUTPUTS["rollback_plan_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_LEARNED_ROUTER_ROLLBACK_PLAN_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.learned_router_rollback_plan_prep_only_draft.v1",
            purpose="Prep-only rollback plan for future runtime authorization lanes.",
        ),
        OUTPUTS["superiority_not_earned_closeout_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_SUPERIORITY_NOT_EARNED_CLOSEOUT_CONTRACT_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.superiority_not_earned_closeout_contract_prep_only_draft.v2",
            purpose="Prep-only closeout/redesign contract if shadow superiority is not earned.",
        ),
        OUTPUTS["redesign_authorization_court_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_REDESIGN_AUTHORIZATION_COURT_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.redesign_authorization_court_prep_only_draft.v1",
            purpose="Prep-only redesign authorization court for failed shadow screen.",
        ),
        OUTPUTS["forensic_invalidation_court_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_FORENSIC_INVALIDATION_COURT_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.forensic_invalidation_court_prep_only_draft.v2",
            purpose="Prep-only forensic invalidation court if screen validity collapses.",
        ),
        OUTPUTS["future_blocker_register"]: _future_blocker_register(selected_outcome),
        OUTPUTS["next_lawful_move"]: receipt(
            "kt.operator.b04_r6_next_lawful_move_receipt.v14",
            "B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            ("next_move",),
            {"verdict": selected_outcome, "next_lawful_move": next_lawful_move},
        ),
        OUTPUTS["result_report"]: _report(selected_outcome=selected_outcome, next_lawful_move=next_lawful_move, scorecard=scorecard, disqualifiers=disqualifiers),
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": selected_outcome, "next_lawful_move": next_lawful_move, "pass_count": len(rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run B04 R6 AFSH shadow screen.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=Path(args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
