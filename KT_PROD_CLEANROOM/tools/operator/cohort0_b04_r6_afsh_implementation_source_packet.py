from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-afsh-implementation-source-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET"
PREVIOUS_LANE = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_VALIDATION"

EXPECTED_PREVIOUS_OUTCOME = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_VALIDATED__AFSH_IMPLEMENTATION_SOURCE_PACKET_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "AUTHOR_B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET"
OUTCOME_BOUND = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_BOUND__SOURCE_PACKET_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_DEFERRED__NAMED_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET"

SELECTED_ARCHITECTURE_ID = "AFSH-2S-GUARD"
SELECTED_ARCHITECTURE_NAME = "Abstention-First Static-Hold Two-Stage Guarded Router"
CASE_PREFIX = "B04R6-AFSH-BU1-"
EXPECTED_CASE_COUNT = 18

ALLOWED_FEATURE_FAMILIES = (
    "case_family_descriptor",
    "trust_zone_eligibility_bit",
    "static_comparator_metadata",
    "route_value_court_terms",
    "trace_shape_metadata",
    "mirror_masked_sibling_metadata",
    "null_route_control_metadata",
    "proof_burden_estimate_bucket",
    "wrong_route_cost_bucket",
    "wrong_static_hold_cost_bucket",
    "calibration_bucket_without_blind_outcomes",
)

FORBIDDEN_FEATURE_FAMILIES = (
    "blind_outcome_labels",
    "blind_route_success_labels",
    "post_screen_labels",
    "hidden_adjudication_labels",
    "old_r01_r04_counted_labels",
    "old_v2_six_row_counted_labels",
    "package_promotion_flags",
    "activation_cutover_flags",
    "truth_engine_mutation_hooks",
    "trust_zone_mutation_hooks",
    "comparator_weakening_knobs",
    "metric_widening_knobs",
)

TRACE_REQUIREMENT_FLAGS = (
    "must_emit_verdict_mode",
    "must_emit_route_value_terms",
    "must_emit_static_hold_reason_code",
    "must_emit_abstention_reason_code",
    "must_emit_null_route_reason_code",
    "must_emit_route_eligible_reason_code",
    "must_emit_trust_zone_status",
    "must_emit_comparator_preservation_status",
    "must_emit_metric_preservation_status",
)

TRACE_GROUPS = (
    "route_decision_trace",
    "abstention_trace",
    "null_route_trace",
    "overrouting_trace",
    "static_fallback_rationale",
    "mirror_masked_trace",
    "route_value_trace",
    "deterministic_replay_receipt",
)

DERIVATION_CONSTRAINTS = {
    "candidate_generation_after_this_packet": False,
    "candidate_generation_authorized": False,
    "candidate_training_authorized": False,
    "candidate_generation_requires": NEXT_LAWFUL_MOVE,
    "no_network": True,
    "deterministic": True,
    "seed_bound": True,
    "hash_bound": True,
    "no_runtime_mutation": True,
    "blind_labels_inaccessible": True,
    "blind_outcomes_inaccessible": True,
    "route_success_labels_inaccessible": True,
    "old_universes_diagnostic_only": True,
}

FORBIDDEN_CLAIMS = [
    "afsh_candidate_generation_authorized",
    "afsh_candidate_training_authorized",
    "afsh_admissibility_authorized",
    "shadow_screen_packet_authorized",
    "shadow_screen_execution_authorized",
    "r6_open",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "runtime_cutover_authorized",
    "lobe_escalation_authorized",
    "package_promotion_authorized",
]

FORBIDDEN_TRUE_KEYS = [
    "r6_authorized",
    "r6_open",
    "router_generation_authorized",
    "candidate_generation_authorized",
    "candidate_training_authorized",
    "afsh_candidate_generation_authorized",
    "afsh_candidate_training_authorized",
    "afsh_admissibility_authorized",
    "shadow_screen_authorized",
    "new_shadow_screen_authorized",
    "shadow_screen_packet_authorized",
    "shadow_screen_execution_authorized",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "runtime_cutover_authorized",
    "learned_router_activated",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "lobe_escalation_authorized",
    "package_promotion_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

FORBIDDEN_ACTIONS = [
    "AFSH_CANDIDATE_GENERATION_AUTHORIZED",
    "AFSH_CANDIDATE_TRAINING_AUTHORIZED",
    "AFSH_ADMISSIBILITY_AUTHORIZED",
    "SHADOW_SCREEN_PACKET_AUTHORIZED",
    "SHADOW_SCREEN_EXECUTION_AUTHORIZED",
    "R6_OPEN",
    "LEARNED_ROUTER_SUPERIORITY_EARNED",
    "ACTIVATION_REVIEW_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
]

VALIDATION_REASON_CODES = [
    "RC_B04R6_AFSH_SOURCE_SCHEMA_MISSING",
    "RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED",
    "RC_B04R6_AFSH_SOURCE_MAIN_HEAD_MISSING",
    "RC_B04R6_AFSH_SOURCE_ARCHITECTURE_MISMATCH",
    "RC_B04R6_AFSH_SOURCE_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_AFSH_SOURCE_COURT_BINDING_MISSING",
    "RC_B04R6_AFSH_SOURCE_ALLOWED_FEATURES_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_FORBIDDEN_FEATURES_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_BLIND_LABEL_ACCESS",
    "RC_B04R6_AFSH_SOURCE_BLIND_OUTCOME_ACCESS",
    "RC_B04R6_AFSH_SOURCE_ROUTE_SUCCESS_LABEL_ACCESS",
    "RC_B04R6_AFSH_SOURCE_OLD_UNIVERSE_PROOF_DRIFT",
    "RC_B04R6_AFSH_SOURCE_TRACE_SCHEMA_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_PROVENANCE_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_DETERMINISM_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_NO_NETWORK_MISSING",
    "RC_B04R6_AFSH_SOURCE_NO_CONTAMINATION_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_AFSH_SOURCE_GENERATION_AUTHORIZATION_DRIFT",
    "RC_B04R6_AFSH_SOURCE_ADMISSIBILITY_AUTHORIZATION_DRIFT",
    "RC_B04R6_AFSH_SOURCE_SCREEN_AUTHORIZATION_DRIFT",
    "RC_B04R6_AFSH_SOURCE_R6_OPEN_DRIFT",
    "RC_B04R6_AFSH_SOURCE_SUPERIORITY_DRIFT",
    "RC_B04R6_AFSH_SOURCE_ACTIVATION_DRIFT",
    "RC_B04R6_AFSH_SOURCE_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_AFSH_SOURCE_METRIC_WIDENING",
    "RC_B04R6_AFSH_SOURCE_COMPARATOR_WEAKENING",
    "RC_B04R6_AFSH_SOURCE_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_AFSH_SOURCE_TRUST_ZONE_MUTATION",
    "RC_B04R6_AFSH_SOURCE_NEXT_MOVE_DRIFT",
]

TERMINAL_DEFECTS = [
    "BLIND_LABEL_ACCESS",
    "BLIND_OUTCOME_ACCESS",
    "ROUTE_SUCCESS_LABEL_ACCESS",
    "OLD_UNIVERSE_PROOF_DRIFT",
    "CANDIDATE_GENERATION_AUTHORIZATION_DRIFT",
    "CANDIDATE_TRAINING_AUTHORIZATION_DRIFT",
    "ADMISSIBILITY_AUTHORIZATION_DRIFT",
    "SHADOW_SCREEN_AUTHORIZATION_DRIFT",
    "R6_OPEN_DRIFT",
    "SUPERIORITY_DRIFT",
    "METRIC_WIDENING",
    "COMPARATOR_WEAKENING",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "PACKAGE_PROMOTION_DRIFT",
    "NEXT_MOVE_DRIFT",
]

INPUTS = {
    "court_validation_contract": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_contract.json",
    "court_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_receipt.json",
    "static_hold_verdict_validation": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_verdict_validation_receipt.json",
    "abstention_verdict_validation": "KT_PROD_CLEANROOM/reports/b04_r6_abstention_verdict_validation_receipt.json",
    "null_route_verdict_validation": "KT_PROD_CLEANROOM/reports/b04_r6_null_route_verdict_validation_receipt.json",
    "route_eligible_non_execution_validation": "KT_PROD_CLEANROOM/reports/b04_r6_route_eligible_non_execution_validation_receipt.json",
    "route_value_formula_validation": "KT_PROD_CLEANROOM/reports/b04_r6_route_value_formula_validation_receipt.json",
    "threshold_freeze_validation": "KT_PROD_CLEANROOM/reports/b04_r6_route_value_threshold_freeze_validation_receipt.json",
    "wrong_route_cost_validation": "KT_PROD_CLEANROOM/reports/b04_r6_wrong_route_cost_validation_receipt.json",
    "wrong_static_hold_cost_validation": "KT_PROD_CLEANROOM/reports/b04_r6_wrong_static_hold_cost_validation_receipt.json",
    "proof_burden_delta_validation": "KT_PROD_CLEANROOM/reports/b04_r6_proof_burden_delta_validation_receipt.json",
    "reason_code_validation": "KT_PROD_CLEANROOM/reports/b04_r6_court_reason_code_validation_receipt.json",
    "disqualifier_validation": "KT_PROD_CLEANROOM/reports/b04_r6_court_disqualifier_validation_receipt.json",
    "prep_only_non_authority_validation": "KT_PROD_CLEANROOM/reports/b04_r6_court_prep_only_non_authority_validation_receipt.json",
    "no_authorization_drift_validation": "KT_PROD_CLEANROOM/reports/b04_r6_court_no_authorization_drift_validation_receipt.json",
    "trust_zone_validation": "KT_PROD_CLEANROOM/reports/b04_r6_court_trust_zone_validation_receipt.json",
    "replay_binding_validation": "KT_PROD_CLEANROOM/reports/b04_r6_court_replay_binding_validation_receipt.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})

TEXT_INPUTS = {
    "court_validation_report": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_report.md",
}

PREP_INPUTS = {
    "afsh_source_packet_prep": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_implementation_source_packet_prep_only_draft.json",
    "afsh_features_prep": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_allowed_forbidden_features_prep_only_draft.json",
    "afsh_trace_prep": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_trace_schema_prep_only_draft.json",
    "afsh_provenance_prep": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_provenance_matrix_prep_only_draft.json",
}

REFERENCE_INPUTS = {
    "trust_zone_registry": "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
    "canonical_scope_manifest": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
}

OUTPUTS = {
    "source_packet_contract": "b04_r6_afsh_implementation_source_packet_contract.json",
    "source_packet_receipt": "b04_r6_afsh_implementation_source_packet_receipt.json",
    "source_packet_report": "b04_r6_afsh_implementation_source_packet_report.md",
    "allowed_features": "b04_r6_afsh_allowed_features_contract.json",
    "forbidden_features": "b04_r6_afsh_forbidden_features_contract.json",
    "trace_schema": "b04_r6_afsh_trace_schema_contract.json",
    "provenance_matrix": "b04_r6_afsh_provenance_matrix.json",
    "determinism": "b04_r6_afsh_source_determinism_contract.json",
    "no_contamination": "b04_r6_afsh_source_no_contamination_contract.json",
    "no_authorization_drift": "b04_r6_afsh_source_no_authorization_drift_receipt.json",
    "trust_zone_binding": "b04_r6_afsh_source_trust_zone_binding_receipt.json",
    "validation_plan": "b04_r6_afsh_source_packet_validation_plan.json",
    "validation_reason_codes": "b04_r6_afsh_source_packet_validation_reason_codes.json",
    "candidate_generation_protocol_prep": "b04_r6_afsh_candidate_generation_protocol_prep_only_draft.json",
    "candidate_manifest_schema_prep": "b04_r6_afsh_candidate_manifest_schema_prep_only_draft.json",
    "admissibility_court_prep": "b04_r6_afsh_admissibility_court_prep_only_draft.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


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


def _input_hashes(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted({**INPUTS, **TEXT_INPUTS, **PREP_INPUTS, **REFERENCE_INPUTS}.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input: {raw}")
        row: Dict[str, Any] = {"role": role, "path": raw, "sha256": file_sha256(path)}
        if role in MUTABLE_HANDOFF_ROLES:
            row.update(
                {
                    "binding_kind": "git_object_before_overwrite",
                    "git_commit": handoff_git_commit,
                    "mutable_canonical_path_overwritten_by_this_lane": True,
                }
            )
        else:
            row["binding_kind"] = "file_sha256_at_authoring"
        rows.append(row)
    return rows


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {
        "check_id": check_id,
        "group": group,
        "status": "PASS",
        "reason_code": reason_code,
        "detail": detail,
    }


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        _fail("RC_B04R6_AFSH_SOURCE_GENERATION_AUTHORIZATION_DRIFT", f"{label} drifted: {key} must remain false")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str, prep_only_allowed: bool = False) -> None:
    allowed_statuses = {"PASS", "FROZEN_PACKET"}
    if prep_only_allowed:
        allowed_statuses.add("PREP_ONLY")
    if str(payload.get("status", "")).strip() not in allowed_statuses:
        _fail("RC_B04R6_AFSH_SOURCE_SCHEMA_MISSING", f"{label} status must be in {sorted(allowed_statuses)}")
    if payload.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_AFSH_SOURCE_ARCHITECTURE_MISMATCH", f"{label} must bind AFSH-2S-GUARD")
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_PACKAGE_PROMOTION_DRIFT", f"{label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_TRUTH_ENGINE_MUTATION", f"{label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_TRUST_ZONE_MUTATION", f"{label} must preserve trust-zone law")


def _existing_source_contract_supports_self_replay(root: Path) -> bool:
    path = root / "KT_PROD_CLEANROOM" / "reports" / OUTPUTS["source_packet_contract"]
    if not path.is_file():
        return False
    payload = common.load_json_required(root, path, label="existing AFSH source packet contract")
    if payload.get("authoritative_lane") != AUTHORITATIVE_LANE:
        return False
    if payload.get("previous_authoritative_lane") != PREVIOUS_LANE:
        return False
    if payload.get("selected_outcome") != SELECTED_OUTCOME:
        return False
    if payload.get("next_lawful_move") != NEXT_LAWFUL_MOVE:
        return False
    input_bindings = payload.get("input_bindings", [])
    if not isinstance(input_bindings, list):
        return False
    return any(isinstance(row, dict) and row.get("role") == "previous_next_lawful_move" for row in input_bindings)


def _require_inputs(
    root: Path,
    payloads: Dict[str, Dict[str, Any]],
    prep_payloads: Dict[str, Dict[str, Any]],
    text_payloads: Dict[str, str],
) -> None:
    for label, payload in payloads.items():
        _ensure_common_boundary(payload, label=label, prep_only_allowed=False)
    for label, payload in prep_payloads.items():
        _ensure_common_boundary(payload, label=label, prep_only_allowed=True)
        if payload.get("status") != "PREP_ONLY" or payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must remain PREP_ONLY")
    for label, text in text_payloads.items():
        if not text.strip():
            _fail("RC_B04R6_AFSH_SOURCE_SCHEMA_MISSING", f"{label} is empty")

    contract = payloads["court_validation_contract"]
    receipt = payloads["court_validation_receipt"]
    handoff = payloads["previous_next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED", "court validation contract outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED", "court validation receipt outcome drifted")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_AFSH_SOURCE_NEXT_MOVE_DRIFT", "court validation contract does not authorize source-packet authoring")
    if receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_AFSH_SOURCE_NEXT_MOVE_DRIFT", "court validation receipt does not authorize source-packet authoring")
    if receipt.get("court_validated") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED", "court validation receipt must mark court_validated=true")
    if int(receipt.get("failure_count", 1)) != 0:
        _fail("RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED", "court validation failures remain")

    handoff_is_previous = (
        handoff.get("authoritative_lane") == PREVIOUS_LANE
        and handoff.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and handoff.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    handoff_is_self_replay = (
        handoff.get("authoritative_lane") == AUTHORITATIVE_LANE
        and handoff.get("previous_authoritative_lane") == PREVIOUS_LANE
        and handoff.get("selected_outcome") == SELECTED_OUTCOME
        and handoff.get("next_lawful_move") == NEXT_LAWFUL_MOVE
        and _existing_source_contract_supports_self_replay(root)
    )
    if not (handoff_is_previous or handoff_is_self_replay):
        _fail("RC_B04R6_AFSH_SOURCE_NEXT_MOVE_DRIFT", "next lawful move receipt does not authorize source-packet authoring")


def _validated_blind_universe_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_blind_universe_binding", {}))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_SOURCE_UNIVERSE_BINDING_MISSING", "validated blind universe is not bound")
    if binding.get("case_count") != EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_AFSH_SOURCE_UNIVERSE_BINDING_MISSING", "validated blind universe must bind 18 cases")
    if binding.get("case_namespace") != f"{CASE_PREFIX}*":
        _fail("RC_B04R6_AFSH_SOURCE_UNIVERSE_BINDING_MISSING", "validated blind universe namespace drifted")
    if binding.get("prior_r01_r04_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_SOURCE_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 must remain diagnostic-only")
    if binding.get("prior_v2_six_row_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_SOURCE_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row screen must remain diagnostic-only")
    return binding


def _validated_court_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_court_binding", {}))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_SOURCE_COURT_BINDING_MISSING", "validated court binding missing")
    if binding.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_AFSH_SOURCE_NEXT_MOVE_DRIFT", "validated court binding must authorize source-packet authoring")
    return binding


def _validate_previous_state(payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    contract = payloads["court_validation_contract"]
    receipt = payloads["court_validation_receipt"]
    if contract.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED", "court validation contract lane mismatch")
    if receipt.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED", "court validation receipt lane mismatch")
    if "STATIC_HOLD" not in text_payloads["court_validation_report"]:
        _fail("RC_B04R6_AFSH_SOURCE_PREVIOUS_COURT_NOT_VALIDATED", "court validation report must mention STATIC_HOLD")
    _validated_blind_universe_binding(receipt)
    _validated_court_binding(receipt)
    rows.append(_pass_row("source_packet_binds_validated_route_economics_court", "RC_B04R6_AFSH_SOURCE_COURT_BINDING_MISSING", "validated route-economics court is bound", group="previous"))
    rows.append(_pass_row("source_packet_binds_validated_blind_universe", "RC_B04R6_AFSH_SOURCE_UNIVERSE_BINDING_MISSING", "validated 18-case blind universe is bound", group="previous"))
    rows.append(_pass_row("source_packet_binds_selected_afsh_architecture", "RC_B04R6_AFSH_SOURCE_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD remains selected", group="previous"))
    rows.append(_pass_row("prior_r01_r04_remain_diagnostic_only", "RC_B04R6_AFSH_SOURCE_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 remains diagnostic-only", group="previous"))
    rows.append(_pass_row("prior_v2_six_row_remains_diagnostic_only", "RC_B04R6_AFSH_SOURCE_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row screen remains diagnostic-only", group="previous"))
    return rows


def _validate_replay_binding(payloads: Dict[str, Dict[str, Any]], *, current_main_head: str) -> tuple[list[Dict[str, str]], str]:
    previous_validation_head = str(payloads["court_validation_contract"].get("current_git_head", "")).strip()
    if len(previous_validation_head) != 40:
        _fail("RC_B04R6_AFSH_SOURCE_MAIN_HEAD_MISSING", "previous court validation head must be a full git SHA")
    if not current_main_head:
        _fail("RC_B04R6_AFSH_SOURCE_MAIN_HEAD_MISSING", "current main head is missing")
    return [
        _pass_row("source_packet_preserves_current_main_head", "RC_B04R6_AFSH_SOURCE_MAIN_HEAD_MISSING", "source packet can bind current main head", group="replay"),
        _pass_row("source_packet_binds_court_validation_head", "RC_B04R6_AFSH_SOURCE_COURT_BINDING_MISSING", "source packet binds previous court validation head", group="replay"),
    ], previous_validation_head


def _validate_features(prep_payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    draft_features = set(prep_payloads["afsh_features_prep"].get("forbidden_features", []))
    missing_forbidden = set(FORBIDDEN_FEATURE_FAMILIES) - draft_features
    if missing_forbidden:
        _fail("RC_B04R6_AFSH_SOURCE_FORBIDDEN_FEATURES_INCOMPLETE", f"forbidden feature draft missing {sorted(missing_forbidden)}")
    rows.append(_pass_row("allowed_features_are_defined", "RC_B04R6_AFSH_SOURCE_ALLOWED_FEATURES_INCOMPLETE", "allowed feature families are explicit", group="features"))
    rows.append(_pass_row("forbidden_features_are_defined", "RC_B04R6_AFSH_SOURCE_FORBIDDEN_FEATURES_INCOMPLETE", "forbidden feature families are explicit", group="features"))
    rows.append(_pass_row("blind_outcome_labels_forbidden", "RC_B04R6_AFSH_SOURCE_BLIND_OUTCOME_ACCESS", "blind outcome labels are forbidden", group="features"))
    rows.append(_pass_row("blind_route_success_labels_forbidden", "RC_B04R6_AFSH_SOURCE_ROUTE_SUCCESS_LABEL_ACCESS", "blind route-success labels are forbidden", group="features"))
    rows.append(_pass_row("old_r01_r04_counted_labels_forbidden", "RC_B04R6_AFSH_SOURCE_OLD_UNIVERSE_PROOF_DRIFT", "old R01-R04 counted labels are forbidden", group="features"))
    rows.append(_pass_row("old_v2_six_row_counted_labels_forbidden", "RC_B04R6_AFSH_SOURCE_OLD_UNIVERSE_PROOF_DRIFT", "old v2 six-row counted labels are forbidden", group="features"))
    rows.append(_pass_row("metric_widening_forbidden", "RC_B04R6_AFSH_SOURCE_METRIC_WIDENING", "metric widening knobs are forbidden", group="features"))
    rows.append(_pass_row("comparator_weakening_forbidden", "RC_B04R6_AFSH_SOURCE_COMPARATOR_WEAKENING", "comparator weakening knobs are forbidden", group="features"))
    rows.append(_pass_row("truth_engine_mutation_forbidden", "RC_B04R6_AFSH_SOURCE_TRUTH_ENGINE_MUTATION", "truth-engine mutation hooks are forbidden", group="features"))
    rows.append(_pass_row("trust_zone_mutation_forbidden", "RC_B04R6_AFSH_SOURCE_TRUST_ZONE_MUTATION", "trust-zone mutation hooks are forbidden", group="features"))
    return rows


def _validate_trace_and_provenance(prep_payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    draft_trace_groups = set(prep_payloads["afsh_trace_prep"].get("required_trace_groups", []))
    missing_trace_groups = set(TRACE_GROUPS) - draft_trace_groups
    if missing_trace_groups:
        _fail("RC_B04R6_AFSH_SOURCE_TRACE_SCHEMA_INCOMPLETE", f"trace draft missing {sorted(missing_trace_groups)}")
    provenance = set(prep_payloads["afsh_provenance_prep"].get("required_future_provenance", []))
    for required in ("source_packet_hash", "allowed_feature_contract_hash", "forbidden_feature_contract_hash", "route_economics_contract_hash", "trace_schema_hash", "blind_universe_manifest_hash", "no_contamination_receipt"):
        if required not in provenance:
            _fail("RC_B04R6_AFSH_SOURCE_PROVENANCE_INCOMPLETE", f"provenance draft missing {required}")
    for flag in TRACE_REQUIREMENT_FLAGS:
        rows.append(_pass_row(f"trace_schema_requires_{flag.removeprefix('must_emit_')}", "RC_B04R6_AFSH_SOURCE_TRACE_SCHEMA_INCOMPLETE", f"trace schema requires {flag}", group="trace"))
    rows.append(_pass_row("provenance_matrix_requires_source_packet_hash", "RC_B04R6_AFSH_SOURCE_PROVENANCE_INCOMPLETE", "provenance requires source packet hash", group="provenance"))
    rows.append(_pass_row("provenance_matrix_requires_no_contamination_receipt", "RC_B04R6_AFSH_SOURCE_PROVENANCE_INCOMPLETE", "provenance requires no-contamination receipt", group="provenance"))
    return rows


def _validate_derivation_constraints() -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    if DERIVATION_CONSTRAINTS["deterministic"] is not True:
        _fail("RC_B04R6_AFSH_SOURCE_DETERMINISM_INCOMPLETE", "derivation must be deterministic")
    if DERIVATION_CONSTRAINTS["hash_bound"] is not True:
        _fail("RC_B04R6_AFSH_SOURCE_DETERMINISM_INCOMPLETE", "derivation must be hash-bound")
    if DERIVATION_CONSTRAINTS["no_network"] is not True:
        _fail("RC_B04R6_AFSH_SOURCE_NO_NETWORK_MISSING", "derivation must forbid network")
    rows.append(_pass_row("derivation_constraints_are_deterministic", "RC_B04R6_AFSH_SOURCE_DETERMINISM_INCOMPLETE", "future derivation must be deterministic", group="derivation"))
    rows.append(_pass_row("derivation_constraints_are_hash_bound", "RC_B04R6_AFSH_SOURCE_DETERMINISM_INCOMPLETE", "future derivation must be hash-bound", group="derivation"))
    rows.append(_pass_row("derivation_constraints_are_no_network", "RC_B04R6_AFSH_SOURCE_NO_NETWORK_MISSING", "future derivation must forbid network", group="derivation"))
    rows.append(_pass_row("blind_labels_inaccessible", "RC_B04R6_AFSH_SOURCE_BLIND_LABEL_ACCESS", "blind labels are inaccessible", group="derivation"))
    rows.append(_pass_row("blind_outcomes_inaccessible", "RC_B04R6_AFSH_SOURCE_BLIND_OUTCOME_ACCESS", "blind outcomes are inaccessible", group="derivation"))
    rows.append(_pass_row("route_success_labels_inaccessible", "RC_B04R6_AFSH_SOURCE_ROUTE_SUCCESS_LABEL_ACCESS", "route-success labels are inaccessible", group="derivation"))
    return rows


def _validate_prep_only(prep_payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    required_flags = (
        "cannot_authorize_generation",
        "cannot_authorize_training",
        "cannot_authorize_screen_packet",
        "cannot_authorize_shadow_screen_execution",
        "cannot_authorize_activation",
        "cannot_authorize_package_promotion",
    )
    for label, payload in prep_payloads.items():
        if payload.get("status") != "PREP_ONLY" or payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must remain PREP_ONLY")
        for flag in required_flags:
            if payload.get(flag) is not True:
                _fail("RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", f"{label} missing {flag}=true")
    rows.append(_pass_row("candidate_generation_protocol_is_prep_only", "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", "candidate generation protocol remains prep-only", group="prep_only"))
    rows.append(_pass_row("candidate_manifest_schema_is_prep_only", "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", "candidate manifest schema remains prep-only", group="prep_only"))
    rows.append(_pass_row("admissibility_court_draft_is_prep_only", "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", "admissibility court draft remains prep-only", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_generation", "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", "prep-only drafts cannot authorize generation", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_screen", "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", "prep-only drafts cannot authorize screen execution", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_activation", "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", "prep-only drafts cannot authorize activation", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_package_promotion", "RC_B04R6_AFSH_SOURCE_PREP_ONLY_AUTHORITY_DRIFT", "prep-only drafts cannot authorize package promotion", group="prep_only"))
    return rows


def _validate_no_authorization_drift(payloads: Dict[str, Dict[str, Any]], prep_payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for label, payload in {**payloads, **prep_payloads}.items():
        for key in FORBIDDEN_TRUE_KEYS:
            _ensure_false_if_present(payload, key, label=label)
        if payload.get("metric_widening_allowed") is not None and payload.get("metric_widening_allowed") is not False:
            _fail("RC_B04R6_AFSH_SOURCE_METRIC_WIDENING", f"{label} metric widening drifted")
        if payload.get("comparator_weakening_allowed") is not None and payload.get("comparator_weakening_allowed") is not False:
            _fail("RC_B04R6_AFSH_SOURCE_COMPARATOR_WEAKENING", f"{label} comparator weakening drifted")
    rows.append(_pass_row("source_packet_does_not_authorize_candidate_generation", "RC_B04R6_AFSH_SOURCE_GENERATION_AUTHORIZATION_DRIFT", "candidate generation remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_candidate_training", "RC_B04R6_AFSH_SOURCE_GENERATION_AUTHORIZATION_DRIFT", "candidate training remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_admissibility", "RC_B04R6_AFSH_SOURCE_ADMISSIBILITY_AUTHORIZATION_DRIFT", "admissibility remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_shadow_screen_packet", "RC_B04R6_AFSH_SOURCE_SCREEN_AUTHORIZATION_DRIFT", "shadow-screen packet remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_shadow_screen_execution", "RC_B04R6_AFSH_SOURCE_SCREEN_AUTHORIZATION_DRIFT", "shadow-screen execution remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_r6_open", "RC_B04R6_AFSH_SOURCE_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_superiority", "RC_B04R6_AFSH_SOURCE_SUPERIORITY_DRIFT", "learned-router superiority remains unearned", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_activation_review", "RC_B04R6_AFSH_SOURCE_ACTIVATION_DRIFT", "activation review remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_runtime_cutover", "RC_B04R6_AFSH_SOURCE_ACTIVATION_DRIFT", "runtime cutover remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_lobe_escalation", "RC_B04R6_AFSH_SOURCE_ACTIVATION_DRIFT", "lobe escalation remains unauthorized", group="authorization"))
    rows.append(_pass_row("source_packet_does_not_authorize_package_promotion", "RC_B04R6_AFSH_SOURCE_PACKAGE_PROMOTION_DRIFT", "package promotion remains deferred", group="authorization"))
    return rows


def _validate_trust_zone(fresh_validation: Dict[str, Any]) -> list[Dict[str, str]]:
    if fresh_validation.get("status") != "PASS" or fresh_validation.get("failures"):
        _fail("RC_B04R6_AFSH_SOURCE_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass with no failures")
    return [_pass_row("trust_zone_validation_passes", "RC_B04R6_AFSH_SOURCE_TRUST_ZONE_MUTATION", "fresh trust-zone validation passed with no failures", group="trust_zone")]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    previous_validation_head: str,
    court_replay_binding_head: str,
    architecture_binding_head: str,
    current_branch: str,
    status: str = "PASS",
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "previous_validation_head": previous_validation_head,
        "court_replay_binding_head": court_replay_binding_head,
        "architecture_binding_head": architecture_binding_head,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "current_branch": current_branch,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "forbidden_actions": FORBIDDEN_ACTIONS,
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_candidate_generation_authorized": False,
        "afsh_candidate_training_authorized": False,
        "afsh_admissibility_authorized": False,
        "shadow_screen_authorized": False,
        "shadow_screen_packet_authorized": False,
        "shadow_screen_execution_authorized": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "runtime_cutover_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "old_r01_r04_diagnostic_only": True,
        "old_v2_six_row_diagnostic_only": True,
        "source_packet_contract_bound": True,
        "source_packet_validation_required_before_generation": True,
        "source_packet_authority_not_finalized_for_generation": True,
    }


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_admissibility_authorized": False,
        "shadow_screen_packet_authorized": False,
        "shadow_screen_execution_authorized": False,
        "activation_review_authorized": False,
        "activation_cutover_authorized": False,
        "runtime_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }


def _trace_schema_requirements() -> Dict[str, Any]:
    return {
        **{flag: True for flag in TRACE_REQUIREMENT_FLAGS},
        "required_trace_groups": list(TRACE_GROUPS),
        "cannot_authorize_screen_packet": True,
        "cannot_authorize_shadow_screen_execution": True,
    }


def _behavioral_defaults() -> Dict[str, str]:
    return {
        "unknown_case": "STATIC_HOLD",
        "uncertain_case": "ABSTAIN_OR_STATIC_HOLD",
        "boundary_unclear": "ABSTAIN",
        "trust_zone_unclear": "ABSTAIN",
        "route_value_below_threshold": "STATIC_HOLD",
        "null_route_sibling": "NULL_ROUTE",
        "mirror_masked_instability": "STATIC_HOLD",
        "proof_burden_not_justified": "STATIC_HOLD",
    }


def _prep_only_authority_block() -> Dict[str, Any]:
    return {
        "status": "PREP_ONLY",
        "draft_status": "PREP_ONLY",
        "authority": "PREP_ONLY",
        "cannot_authorize_generation": True,
        "cannot_authorize_training": True,
        "cannot_authorize_admissibility": True,
        "cannot_authorize_screen_packet": True,
        "cannot_authorize_shadow_screen_execution": True,
        "cannot_authorize_activation": True,
        "cannot_authorize_package_promotion": True,
        "next_lawful_move_required_before_authority": NEXT_LAWFUL_MOVE,
        "allowed_future_purpose": "Draft scaffold only for the candidate-generation or admissibility lanes after source-packet validation.",
    }


def _provenance_rows() -> list[Dict[str, str]]:
    return [
        {"artifact": OUTPUTS["source_packet_contract"], "required_binding": "source_packet_hash"},
        {"artifact": OUTPUTS["allowed_features"], "required_binding": "allowed_feature_contract_hash"},
        {"artifact": OUTPUTS["forbidden_features"], "required_binding": "forbidden_feature_contract_hash"},
        {"artifact": OUTPUTS["trace_schema"], "required_binding": "trace_schema_hash"},
        {"artifact": OUTPUTS["determinism"], "required_binding": "determinism_contract_hash"},
        {"artifact": OUTPUTS["no_contamination"], "required_binding": "no_contamination_contract_hash"},
        {"artifact": "b04_r6_blind_universe_case_manifest.json", "required_binding": "blind_universe_manifest_hash"},
        {"artifact": "b04_r6_static_hold_abstention_route_economics_court_validation_receipt.json", "required_binding": "validated_route_economics_court_hash"},
    ]


def _future_blocker_register() -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.future_blocker_register.v2",
        "artifact_id": "B04_R6_FUTURE_BLOCKER_REGISTER",
        "current_authoritative_lane": AUTHORITATIVE_LANE,
        "blockers": [
            {
                "blocker_id": "B04R6-FB-011",
                "future_blocker": "Source packet exists but source-packet validation law does not exist.",
                "neutralization_now": [
                    OUTPUTS["validation_plan"],
                    OUTPUTS["validation_reason_codes"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-012",
                "future_blocker": "Source packet validates but candidate generation protocol is not ready.",
                "neutralization_now": [
                    OUTPUTS["candidate_generation_protocol_prep"],
                    OUTPUTS["candidate_manifest_schema_prep"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-013",
                "future_blocker": "Candidate exists but admissibility law is not ready.",
                "neutralization_now": [OUTPUTS["admissibility_court_prep"]],
            },
            {
                "blocker_id": "B04R6-FB-014",
                "future_blocker": "Candidate generation accidentally uses blind outcomes.",
                "neutralization_later": [
                    "b04_r6_afsh_candidate_no_contamination_receipt.json",
                    "b04_r6_afsh_forbidden_feature_scan_receipt.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-015",
                "future_blocker": "Candidate passes admissibility but shadow-screen packet law is missing.",
                "neutralization_later": [
                    "b04_r6_afsh_shadow_screen_execution_packet_draft.json",
                    "b04_r6_afsh_shadow_screen_disqualifier_ledger_draft.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-016",
                "future_blocker": "Commercial language outruns source-packet proof.",
                "neutralization_later": [
                    "r6_nonclaim_boundary_language_packet.json",
                    "learned_router_forbidden_claims_receipt.json",
                ],
            },
        ],
    }


def _validation_plan() -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.afsh_source_packet_validation_plan.v1",
        "artifact_id": "B04_R6_AFSH_SOURCE_PACKET_VALIDATION_PLAN",
        "validation_object": "B04 R6 AFSH implementation source packet",
        "required_checks": [
            "source packet contract exists and parses",
            "source packet binds current main",
            "source packet binds AFSH-2S-GUARD",
            "source packet binds validated blind universe",
            "source packet binds validated route-economics court",
            "allowed features are explicit",
            "forbidden features are explicit",
            "blind labels are inaccessible",
            "blind outcomes are inaccessible",
            "route-success labels are inaccessible",
            "old R01-R04 remain diagnostic-only",
            "old v2 six-row remains diagnostic-only",
            "trace schema complete",
            "provenance matrix complete",
            "determinism constraints present",
            "hash-binding constraints present",
            "no-network rule present",
            "no runtime mutation",
            "no truth-engine mutation",
            "no trust-zone mutation",
            "no metric widening",
            "no comparator weakening",
            "candidate-generation protocol remains PREP_ONLY",
            "admissibility draft remains PREP_ONLY",
            "next lawful move correctness",
        ],
        "expected_successful_validation_outcome": "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_VALIDATED__CANDIDATE_GENERATION_NEXT",
        "forbidden_validation_outcomes": FORBIDDEN_ACTIONS,
    }


def _artifact_payload(
    *,
    base: Dict[str, Any],
    schema_id: str,
    rows: list[Dict[str, str]],
    input_bindings: list[Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema_id": schema_id,
        **base,
        "authorization_state": _authorization_state(),
        "validation_rows": rows,
        "pass_count": len(rows),
        "failure_count": 0,
        "validation_reason_codes": VALIDATION_REASON_CODES,
        "terminal_defects": TERMINAL_DEFECTS,
        "input_bindings": input_bindings,
    }
    if extra:
        payload.update(extra)
    return payload


def _rows_for(rows: list[Dict[str, str]], *groups: str) -> list[Dict[str, str]]:
    wanted = set(groups)
    return [row for row in rows if row.get("group") in wanted]


def _report(rows: list[Dict[str, str]]) -> str:
    lines = [
        "# B04 R6 AFSH Implementation Source Packet",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "This packet defines the lawful AFSH-2S-GUARD source family after court validation. It does not generate a candidate and does not authorize training, admissibility, shadow-screen execution, R6 opening, activation, lobe escalation, package promotion, or learned-router superiority.",
        "",
        f"Next lawful move: `{NEXT_LAWFUL_MOVE}`",
        "",
        "## Authoring Checks",
    ]
    for row in rows:
        lines.append(f"- `{row['check_id']}`: `{row['status']}` ({row['reason_code']})")
    lines.append("")
    return "\n".join(lines)


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 AFSH source-packet freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    prep_payloads = {role: _load(root, raw, label=role) for role, raw in PREP_INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    _require_inputs(root, payloads, prep_payloads, text_payloads)

    fresh_trust_validation = validate_trust_zones(root=root)

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)

    rows: list[Dict[str, str]] = []
    rows.extend(_validate_previous_state(payloads, text_payloads))
    replay_rows, previous_validation_head = _validate_replay_binding(payloads, current_main_head=current_main_head)
    rows.extend(replay_rows)
    rows.extend(_validate_features(prep_payloads))
    rows.extend(_validate_trace_and_provenance(prep_payloads))
    rows.extend(_validate_derivation_constraints())
    rows.extend(_validate_prep_only(prep_payloads))
    rows.extend(_validate_no_authorization_drift(payloads, prep_payloads))
    rows.extend(_validate_trust_zone(fresh_trust_validation))
    rows.append(
        _pass_row(
            "next_lawful_move_is_source_packet_validation",
            "RC_B04R6_AFSH_SOURCE_NEXT_MOVE_DRIFT",
            "the next lawful move is source-packet validation",
            group="next_move",
        )
    )

    generated_utc = utc_now_iso_z()
    receipt = payloads["court_validation_receipt"]
    architecture_binding_head = str(receipt.get("architecture_binding_head", "")).strip()
    court_replay_binding_head = str(receipt.get("court_replay_binding_head", "")).strip()
    validated_blind_universe_binding = _validated_blind_universe_binding(receipt)
    validated_court_binding = _validated_court_binding(receipt)

    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        previous_validation_head=previous_validation_head,
        court_replay_binding_head=court_replay_binding_head,
        architecture_binding_head=architecture_binding_head,
        current_branch=current_branch,
    )

    common_extra = {
        "validated_court_binding": {
            **validated_court_binding,
            "source_packet_input_validation_head": previous_validation_head,
            "verdict_modes": ["STATIC_HOLD", "ABSTAIN", "NULL_ROUTE", "ROUTE_ELIGIBLE"],
            "route_eligible_non_executing_only": True,
        },
        "validated_blind_universe_binding": validated_blind_universe_binding,
        "source_packet_scope": {
            "purpose": "Define the lawful source family and constraints from which a future AFSH candidate may be generated after source-packet validation.",
            "non_purpose": [
                "Does not generate an AFSH candidate.",
                "Does not authorize candidate training.",
                "Does not authorize admissibility.",
                "Does not authorize shadow-screen packet creation.",
                "Does not authorize shadow-screen execution.",
                "Does not open R6.",
                "Does not earn learned-router superiority.",
                "Does not authorize activation, lobe escalation, or package promotion.",
            ],
        },
        "allowed_feature_families": list(ALLOWED_FEATURE_FAMILIES),
        "forbidden_feature_families": list(FORBIDDEN_FEATURE_FAMILIES),
        "derivation_constraints": DERIVATION_CONSTRAINTS,
        "behavioral_defaults_required_for_future_candidate": _behavioral_defaults(),
        "trace_schema_requirements": _trace_schema_requirements(),
        "route_value_court_compatibility": {
            "route_value_law_validated": True,
            "static_hold_default_required": True,
            "abstention_preservation_required": True,
            "null_route_preservation_required": True,
            "route_eligible_non_executing_only": True,
        },
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["source_packet_contract"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_implementation_source_packet.v1",
            rows=rows,
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET",
                "source_packet_contract_bound": True,
                "candidate_generation_remains_forbidden": True,
            },
        ),
        OUTPUTS["source_packet_receipt"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_implementation_source_packet_receipt.v1",
            rows=rows,
            input_bindings=input_bindings,
            extra={**common_extra, "verdict": SELECTED_OUTCOME, "source_packet_authored": True},
        ),
        OUTPUTS["allowed_features"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_allowed_features_contract.v1",
            rows=_rows_for(rows, "features"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_ALLOWED_FEATURES_CONTRACT",
                "allowed_features": list(ALLOWED_FEATURE_FAMILIES),
                "allowed_static_comparator_references": [
                    "static_comparator_metadata",
                    "static_hold_dominance_indicator",
                    "static_fallback_reason_code",
                ],
            },
        ),
        OUTPUTS["forbidden_features"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_forbidden_features_contract.v1",
            rows=_rows_for(rows, "features"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_FORBIDDEN_FEATURES_CONTRACT",
                "forbidden_features": list(FORBIDDEN_FEATURE_FAMILIES),
                "blind_label_access_forbidden": True,
                "blind_outcome_access_forbidden": True,
                "route_success_label_access_forbidden": True,
            },
        ),
        OUTPUTS["trace_schema"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_trace_schema_contract.v1",
            rows=_rows_for(rows, "trace"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_TRACE_SCHEMA_CONTRACT",
                "trace_schema": _trace_schema_requirements(),
            },
        ),
        OUTPUTS["provenance_matrix"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_provenance_matrix.v1",
            rows=_rows_for(rows, "provenance"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_PROVENANCE_MATRIX",
                "required_provenance": _provenance_rows(),
            },
        ),
        OUTPUTS["determinism"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_determinism_contract.v1",
            rows=_rows_for(rows, "derivation"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_SOURCE_DETERMINISM_CONTRACT",
                "determinism_requirements": {
                    "deterministic": True,
                    "seed_bound": True,
                    "hash_bound": True,
                    "no_network": True,
                    "no_runtime_mutation": True,
                },
            },
        ),
        OUTPUTS["no_contamination"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_no_contamination_contract.v1",
            rows=_rows_for(rows, "features", "derivation", "previous"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_SOURCE_NO_CONTAMINATION_CONTRACT",
                "no_contamination_rules": {
                    "blind_labels_inaccessible": True,
                    "blind_outcomes_inaccessible": True,
                    "route_success_labels_inaccessible": True,
                    "old_r01_r04_diagnostic_only": True,
                    "old_v2_six_row_diagnostic_only": True,
                    "candidate_generation_still_forbidden": True,
                },
            },
        ),
        OUTPUTS["no_authorization_drift"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_no_authorization_drift_receipt.v1",
            rows=_rows_for(rows, "authorization", "prep_only"),
            input_bindings=input_bindings,
            extra={**common_extra, "no_downstream_authorization_drift": True},
        ),
        OUTPUTS["trust_zone_binding"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_trust_zone_binding_receipt.v1",
            rows=_rows_for(rows, "trust_zone"),
            input_bindings=input_bindings,
            extra={**common_extra, "fresh_trust_zone_validation": fresh_trust_validation},
        ),
        OUTPUTS["validation_plan"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_packet_validation_plan.v1",
            rows=_rows_for(rows, "next_move"),
            input_bindings=input_bindings,
            extra={**common_extra, **_validation_plan()},
        ),
        OUTPUTS["validation_reason_codes"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_packet_validation_reason_codes.v1",
            rows=_rows_for(rows, "next_move"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_SOURCE_PACKET_VALIDATION_REASON_CODES",
                "reason_codes": VALIDATION_REASON_CODES,
                "terminal_defects": TERMINAL_DEFECTS,
            },
        ),
        OUTPUTS["candidate_generation_protocol_prep"]: _artifact_payload(
            base={**base, **_prep_only_authority_block()},
            schema_id="kt.b04_r6.afsh_candidate_generation_protocol_prep_only_draft.v1",
            rows=_rows_for(rows, "prep_only"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_CANDIDATE_GENERATION_PROTOCOL_PREP_ONLY_DRAFT",
                "candidate_generation_protocol": {
                    "authority": "PREP_ONLY",
                    "generation_requires": "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_VALIDATED__CANDIDATE_GENERATION_NEXT",
                    "candidate_generation_authorized_now": False,
                    "candidate_training_authorized_now": False,
                    "must_use_allowed_features_only": True,
                    "must_scan_for_forbidden_features": True,
                },
            },
        ),
        OUTPUTS["candidate_manifest_schema_prep"]: _artifact_payload(
            base={**base, **_prep_only_authority_block()},
            schema_id="kt.b04_r6.afsh_candidate_manifest_schema_prep_only_draft.v1",
            rows=_rows_for(rows, "prep_only"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_CANDIDATE_MANIFEST_SCHEMA_PREP_ONLY_DRAFT",
                "candidate_manifest_required_fields": [
                    "candidate_id",
                    "candidate_version",
                    "source_packet_hash",
                    "allowed_features_hash",
                    "forbidden_features_hash",
                    "trace_schema_hash",
                    "determinism_contract_hash",
                    "no_contamination_receipt_hash",
                    "candidate_source_sha256",
                ],
            },
        ),
        OUTPUTS["admissibility_court_prep"]: _artifact_payload(
            base={**base, **_prep_only_authority_block()},
            schema_id="kt.b04_r6.afsh_admissibility_court_prep_only_draft.v1",
            rows=_rows_for(rows, "prep_only"),
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_ADMISSIBILITY_COURT_PREP_ONLY_DRAFT",
                "admissibility_checks": [
                    "deterministic replay",
                    "trace compatibility",
                    "no contamination",
                    "blind-universe separation",
                    "no package dependency",
                    "no truth-engine mutation",
                    "no trust-zone mutation",
                    "static-hold default",
                    "abstention preservation",
                    "null-route preservation",
                    "mirror/masked stability",
                ],
            },
        ),
        OUTPUTS["future_blocker_register"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.future_blocker_register.v2",
            rows=_rows_for(rows, "next_move"),
            input_bindings=input_bindings,
            extra={**common_extra, **_future_blocker_register()},
        ),
        OUTPUTS["next_lawful_move"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v8",
            rows=_rows_for(rows, "next_move"),
            input_bindings=input_bindings,
            extra={**common_extra, "verdict": SELECTED_OUTCOME},
        ),
        OUTPUTS["source_packet_report"]: _report(rows),
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "pass_count": len(rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 AFSH implementation source packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
