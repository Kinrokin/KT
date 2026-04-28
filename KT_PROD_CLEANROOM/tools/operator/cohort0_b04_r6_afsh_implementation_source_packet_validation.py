from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-afsh-source-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_VALIDATION"
PREVIOUS_LANE = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET"

EXPECTED_PREVIOUS_OUTCOME = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_BOUND__SOURCE_PACKET_VALIDATION_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "VALIDATE_B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET"
OUTCOME_VALIDATED = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_VALIDATED__CANDIDATE_GENERATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "GENERATE_B04_R6_AFSH_CANDIDATE"

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

PROVENANCE_BINDINGS = (
    "source_packet_hash",
    "allowed_feature_contract_hash",
    "forbidden_feature_contract_hash",
    "trace_schema_hash",
    "determinism_contract_hash",
    "no_contamination_contract_hash",
    "blind_universe_manifest_hash",
    "validated_route_economics_court_hash",
)

FORBIDDEN_CLAIMS = [
    "afsh_candidate_generation_executed",
    "afsh_candidate_training_executed",
    "afsh_admissibility_executed",
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
    "afsh_candidate_generation_executed",
    "afsh_candidate_training_authorized",
    "afsh_candidate_training_executed",
    "afsh_admissibility_authorized",
    "afsh_admissibility_executed",
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
    "AFSH_CANDIDATE_GENERATION_EXECUTED",
    "AFSH_CANDIDATE_TRAINING_EXECUTED",
    "AFSH_ADMISSIBILITY_EXECUTED",
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
    "RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_RECEIPT_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_AFSH_SOURCE_VAL_ARCHITECTURE_MISMATCH",
    "RC_B04R6_AFSH_SOURCE_VAL_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_COURT_BINDING_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_ALLOWED_FEATURES_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_FORBIDDEN_FEATURES_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_BLIND_OUTCOME_ACCESS",
    "RC_B04R6_AFSH_SOURCE_VAL_BLIND_ROUTE_SUCCESS_ACCESS",
    "RC_B04R6_AFSH_SOURCE_VAL_POST_SCREEN_LABEL_ACCESS",
    "RC_B04R6_AFSH_SOURCE_VAL_HIDDEN_ADJUDICATION_ACCESS",
    "RC_B04R6_AFSH_SOURCE_VAL_OLD_R01_R04_COUNTED_LABEL_ACCESS",
    "RC_B04R6_AFSH_SOURCE_VAL_OLD_V2_SIX_ROW_COUNTED_LABEL_ACCESS",
    "RC_B04R6_AFSH_SOURCE_VAL_OLD_UNIVERSE_PROOF_DRIFT",
    "RC_B04R6_AFSH_SOURCE_VAL_TRACE_SCHEMA_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_VAL_PROVENANCE_MATRIX_INCOMPLETE",
    "RC_B04R6_AFSH_SOURCE_VAL_DETERMINISM_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_HASH_BINDING_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_NETWORK_ALLOWED",
    "RC_B04R6_AFSH_SOURCE_VAL_RUNTIME_MUTATION_ALLOWED",
    "RC_B04R6_AFSH_SOURCE_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_AFSH_SOURCE_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_AFSH_SOURCE_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_AFSH_SOURCE_VAL_ACTIVATION_CUTOVER_DRIFT",
    "RC_B04R6_AFSH_SOURCE_VAL_STATIC_HOLD_DEFAULT_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_ABSTENTION_PRESERVATION_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_NULL_ROUTE_PRESERVATION_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_MIRROR_MASKED_STABILITY_MISSING",
    "RC_B04R6_AFSH_SOURCE_VAL_ROUTE_VALUE_COURT_INCOMPATIBLE",
    "RC_B04R6_AFSH_SOURCE_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_AFSH_SOURCE_VAL_GENERATION_AUTHORIZED",
    "RC_B04R6_AFSH_SOURCE_VAL_TRAINING_AUTHORIZED",
    "RC_B04R6_AFSH_SOURCE_VAL_ADMISSIBILITY_AUTHORIZED",
    "RC_B04R6_AFSH_SOURCE_VAL_SHADOW_PACKET_AUTHORIZED",
    "RC_B04R6_AFSH_SOURCE_VAL_SHADOW_SCREEN_AUTHORIZED",
    "RC_B04R6_AFSH_SOURCE_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_AFSH_SOURCE_VAL_SUPERIORITY_DRIFT",
    "RC_B04R6_AFSH_SOURCE_VAL_METRIC_WIDENING",
    "RC_B04R6_AFSH_SOURCE_VAL_COMPARATOR_WEAKENING",
    "RC_B04R6_AFSH_SOURCE_VAL_NEXT_MOVE_DRIFT",
]

TERMINAL_DEFECTS = [
    "BLIND_OUTCOME_ACCESS",
    "BLIND_ROUTE_SUCCESS_ACCESS",
    "POST_SCREEN_LABEL_ACCESS",
    "OLD_UNIVERSE_PROOF_DRIFT",
    "PREP_ONLY_AUTHORITY_DRIFT",
    "GENERATION_AUTHORIZED",
    "TRAINING_AUTHORIZED",
    "ADMISSIBILITY_AUTHORIZED",
    "SHADOW_SCREEN_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "SUPERIORITY_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "METRIC_WIDENING",
    "COMPARATOR_WEAKENING",
    "NEXT_MOVE_DRIFT",
]

INPUTS = {
    "source_packet_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_implementation_source_packet_contract.json",
    "source_packet_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_implementation_source_packet_receipt.json",
    "allowed_features": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_allowed_features_contract.json",
    "forbidden_features": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_forbidden_features_contract.json",
    "trace_schema": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_trace_schema_contract.json",
    "provenance_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_provenance_matrix.json",
    "determinism": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_determinism_contract.json",
    "no_contamination": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_no_contamination_contract.json",
    "no_authorization_drift": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_no_authorization_drift_receipt.json",
    "trust_zone_binding": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_trust_zone_binding_receipt.json",
    "source_validation_plan": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_packet_validation_plan.json",
    "source_validation_reason_codes": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_packet_validation_reason_codes.json",
    "candidate_generation_protocol_prep": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_generation_protocol_prep_only_draft.json",
    "candidate_manifest_schema_prep": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_manifest_schema_prep_only_draft.json",
    "admissibility_court_prep": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_admissibility_court_prep_only_draft.json",
    "future_blocker_register": "KT_PROD_CLEANROOM/reports/b04_r6_future_blocker_register.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})

TEXT_INPUTS = {
    "source_packet_report": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_implementation_source_packet_report.md",
}

REFERENCE_INPUTS = {
    "trust_zone_registry": "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
    "canonical_scope_manifest": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
}

OUTPUTS = {
    "validation_contract": "b04_r6_afsh_source_packet_validation_contract.json",
    "validation_receipt": "b04_r6_afsh_source_packet_validation_receipt.json",
    "validation_report": "b04_r6_afsh_source_packet_validation_report.md",
    "allowed_features_validation": "b04_r6_afsh_allowed_features_validation_receipt.json",
    "forbidden_features_validation": "b04_r6_afsh_forbidden_features_validation_receipt.json",
    "trace_schema_validation": "b04_r6_afsh_trace_schema_validation_receipt.json",
    "provenance_matrix_validation": "b04_r6_afsh_provenance_matrix_validation_receipt.json",
    "determinism_validation": "b04_r6_afsh_source_determinism_validation_receipt.json",
    "no_contamination_validation": "b04_r6_afsh_no_contamination_validation_receipt.json",
    "prep_only_non_authority_validation": "b04_r6_afsh_prep_only_non_authority_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_afsh_source_no_authorization_drift_validation_receipt.json",
    "trust_zone_validation": "b04_r6_afsh_source_trust_zone_validation_receipt.json",
    "replay_binding_validation": "b04_r6_afsh_source_replay_binding_validation_receipt.json",
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
    for role, raw in sorted({**INPUTS, **TEXT_INPUTS, **REFERENCE_INPUTS}.items()):
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
            row["binding_kind"] = "file_sha256_at_validation"
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
        _fail("RC_B04R6_AFSH_SOURCE_VAL_GENERATION_AUTHORIZED", f"{label} drifted: {key} must remain false")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str, prep_only_allowed: bool = False) -> None:
    allowed_statuses = {"PASS", "FROZEN_PACKET"}
    if prep_only_allowed:
        allowed_statuses.add("PREP_ONLY")
    if str(payload.get("status", "")).strip() not in allowed_statuses:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", f"{label} status must be in {sorted(allowed_statuses)}")
    if payload.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_ARCHITECTURE_MISMATCH", f"{label} must bind AFSH-2S-GUARD")
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_PACKAGE_PROMOTION_DRIFT", f"{label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_TRUTH_ENGINE_MUTATION", f"{label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_TRUST_ZONE_MUTATION", f"{label} must preserve trust-zone law")


def _existing_validation_contract_supports_self_replay(root: Path) -> bool:
    path = root / "KT_PROD_CLEANROOM" / "reports" / OUTPUTS["validation_contract"]
    if not path.is_file():
        return False
    payload = common.load_json_required(root, path, label="existing AFSH source validation contract")
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


def _require_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        prep_only = label in {
            "candidate_generation_protocol_prep",
            "candidate_manifest_schema_prep",
            "admissibility_court_prep",
        }
        _ensure_common_boundary(payload, label=label, prep_only_allowed=prep_only)
        if prep_only and (payload.get("status") != "PREP_ONLY" or payload.get("authority") != "PREP_ONLY"):
            _fail("RC_B04R6_AFSH_SOURCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must remain PREP_ONLY")
    for label, text in text_payloads.items():
        if not text.strip():
            _fail("RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", f"{label} is empty")

    contract = payloads["source_packet_contract"]
    receipt = payloads["source_packet_receipt"]
    handoff = payloads["previous_next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "source-packet contract outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_RECEIPT_MISSING", "source-packet receipt outcome drifted")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_NEXT_MOVE_DRIFT", "source-packet contract does not authorize validation")
    if receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_NEXT_MOVE_DRIFT", "source-packet receipt does not authorize validation")
    if receipt.get("source_packet_authored") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_RECEIPT_MISSING", "source-packet receipt must mark source_packet_authored=true")
    if int(receipt.get("failure_count", 1)) != 0:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_RECEIPT_MISSING", "source-packet receipt failures remain")

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
        and _existing_validation_contract_supports_self_replay(root)
    )
    if not (handoff_is_previous or handoff_is_self_replay):
        _fail("RC_B04R6_AFSH_SOURCE_VAL_NEXT_MOVE_DRIFT", "next lawful move receipt does not authorize source-packet validation")


def _validated_blind_universe_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_blind_universe_binding", {}))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_UNIVERSE_BINDING_MISSING", "validated blind universe is not bound")
    if binding.get("case_count") != EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_UNIVERSE_BINDING_MISSING", "validated blind universe must bind 18 cases")
    if binding.get("case_namespace") != f"{CASE_PREFIX}*":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_UNIVERSE_BINDING_MISSING", "validated blind universe namespace drifted")
    if binding.get("prior_r01_r04_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 must remain diagnostic-only")
    if binding.get("prior_v2_six_row_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row screen must remain diagnostic-only")
    return binding


def _validated_court_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_court_binding", {}))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_COURT_BINDING_MISSING", "validated court binding missing")
    if binding.get("route_eligible_non_executing_only") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_ROUTE_VALUE_COURT_INCOMPATIBLE", "route-eligible must remain non-executing")
    return binding


def _validate_previous_state(payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    contract = payloads["source_packet_contract"]
    receipt = payloads["source_packet_receipt"]
    if contract.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "source-packet contract lane mismatch")
    if receipt.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_RECEIPT_MISSING", "source-packet receipt lane mismatch")
    if "source packet" not in text_payloads["source_packet_report"].lower():
        _fail("RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "source-packet report must discuss source packet")
    _validated_blind_universe_binding(receipt)
    _validated_court_binding(receipt)
    rows.append(_pass_row("source_packet_contract_exists_and_parses", "RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "source-packet contract exists and parses", group="source_packet"))
    rows.append(_pass_row("source_packet_receipt_exists_and_parses", "RC_B04R6_AFSH_SOURCE_VAL_RECEIPT_MISSING", "source-packet receipt exists and parses", group="source_packet"))
    rows.append(_pass_row("source_packet_report_exists", "RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "source-packet report exists and is non-empty", group="source_packet"))
    rows.append(_pass_row("validation_contract_binds_selected_afsh_architecture", "RC_B04R6_AFSH_SOURCE_VAL_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD remains bound", group="source_packet"))
    rows.append(_pass_row("validation_contract_binds_validated_blind_universe", "RC_B04R6_AFSH_SOURCE_VAL_UNIVERSE_BINDING_MISSING", "validated blind universe remains bound", group="source_packet"))
    rows.append(_pass_row("validation_contract_binds_validated_route_economics_court", "RC_B04R6_AFSH_SOURCE_VAL_COURT_BINDING_MISSING", "validated route-economics court remains bound", group="source_packet"))
    rows.append(_pass_row("prior_r01_r04_remain_diagnostic_only", "RC_B04R6_AFSH_SOURCE_VAL_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 remains diagnostic-only", group="source_packet"))
    rows.append(_pass_row("prior_v2_six_row_remain_diagnostic_only", "RC_B04R6_AFSH_SOURCE_VAL_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row screen remains diagnostic-only", group="source_packet"))
    return rows


def _validate_replay_binding(payloads: Dict[str, Dict[str, Any]], *, current_main_head: str) -> tuple[list[Dict[str, str]], str]:
    source_packet_head = str(payloads["source_packet_contract"].get("current_git_head", "")).strip()
    if len(source_packet_head) != 40:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_MAIN_HEAD_MISMATCH", "source-packet replay head must be a full git SHA")
    if not current_main_head:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_MAIN_HEAD_MISMATCH", "current main head is missing")
    return [
        _pass_row("validation_contract_preserves_current_main_head", "RC_B04R6_AFSH_SOURCE_VAL_MAIN_HEAD_MISMATCH", "validation can bind current main head", group="replay"),
        _pass_row("source_packet_replay_binding_validated", "RC_B04R6_AFSH_SOURCE_VAL_MAIN_HEAD_MISMATCH", "source packet replay head is bound", group="replay"),
    ], source_packet_head


def _validate_features(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    allowed = set(payloads["allowed_features"].get("allowed_features", []))
    forbidden = set(payloads["forbidden_features"].get("forbidden_features", []))
    if not set(ALLOWED_FEATURE_FAMILIES).issubset(allowed):
        _fail("RC_B04R6_AFSH_SOURCE_VAL_ALLOWED_FEATURES_MISSING", "allowed feature contract incomplete")
    if not set(FORBIDDEN_FEATURE_FAMILIES).issubset(forbidden):
        _fail("RC_B04R6_AFSH_SOURCE_VAL_FORBIDDEN_FEATURES_MISSING", "forbidden feature contract incomplete")
    for field, code in (
        ("blind_label_access_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_BLIND_OUTCOME_ACCESS"),
        ("blind_outcome_access_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_BLIND_OUTCOME_ACCESS"),
        ("route_success_label_access_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_BLIND_ROUTE_SUCCESS_ACCESS"),
    ):
        if payloads["forbidden_features"].get(field) is not True:
            _fail(code, f"forbidden feature contract missing {field}=true")
    rows.append(_pass_row("allowed_features_contract_bound", "RC_B04R6_AFSH_SOURCE_VAL_ALLOWED_FEATURES_MISSING", "allowed features are explicit", group="allowed_features"))
    rows.append(_pass_row("forbidden_features_contract_bound", "RC_B04R6_AFSH_SOURCE_VAL_FORBIDDEN_FEATURES_MISSING", "forbidden features are explicit", group="forbidden_features"))
    rows.append(_pass_row("blind_outcome_labels_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_BLIND_OUTCOME_ACCESS", "blind outcome labels are forbidden", group="forbidden_features"))
    rows.append(_pass_row("blind_route_success_labels_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_BLIND_ROUTE_SUCCESS_ACCESS", "blind route-success labels are forbidden", group="forbidden_features"))
    rows.append(_pass_row("post_screen_labels_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_POST_SCREEN_LABEL_ACCESS", "post-screen labels are forbidden", group="forbidden_features"))
    rows.append(_pass_row("hidden_adjudication_labels_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_HIDDEN_ADJUDICATION_ACCESS", "hidden adjudication labels are forbidden", group="forbidden_features"))
    rows.append(_pass_row("old_r01_r04_counted_labels_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_OLD_R01_R04_COUNTED_LABEL_ACCESS", "old R01-R04 counted labels are forbidden", group="forbidden_features"))
    rows.append(_pass_row("old_v2_six_row_counted_labels_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_OLD_V2_SIX_ROW_COUNTED_LABEL_ACCESS", "old v2 six-row counted labels are forbidden", group="forbidden_features"))
    rows.append(_pass_row("metric_widening_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_METRIC_WIDENING", "metric widening knobs are forbidden", group="forbidden_features"))
    rows.append(_pass_row("comparator_weakening_forbidden", "RC_B04R6_AFSH_SOURCE_VAL_COMPARATOR_WEAKENING", "comparator weakening knobs are forbidden", group="forbidden_features"))
    return rows


def _validate_trace(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    schema = dict(payloads["trace_schema"].get("trace_schema", {}))
    groups = set(schema.get("required_trace_groups", []))
    if not set(TRACE_GROUPS).issubset(groups):
        _fail("RC_B04R6_AFSH_SOURCE_VAL_TRACE_SCHEMA_INCOMPLETE", "trace schema missing required groups")
    for flag in TRACE_REQUIREMENT_FLAGS:
        if schema.get(flag) is not True:
            _fail("RC_B04R6_AFSH_SOURCE_VAL_TRACE_SCHEMA_INCOMPLETE", f"trace schema missing {flag}=true")
        rows.append(_pass_row(f"trace_schema_requires_{flag.removeprefix('must_emit_')}", "RC_B04R6_AFSH_SOURCE_VAL_TRACE_SCHEMA_INCOMPLETE", f"trace schema requires {flag}", group="trace_schema"))
    rows.append(_pass_row("trace_schema_contract_bound", "RC_B04R6_AFSH_SOURCE_VAL_TRACE_SCHEMA_INCOMPLETE", "trace schema contract is bound", group="trace_schema"))
    return rows


def _validate_provenance_and_determinism(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    provenance_rows = payloads["provenance_matrix"].get("required_provenance", [])
    bindings = {str(row.get("required_binding", "")) for row in provenance_rows if isinstance(row, dict)}
    if not set(PROVENANCE_BINDINGS).issubset(bindings):
        _fail("RC_B04R6_AFSH_SOURCE_VAL_PROVENANCE_MATRIX_INCOMPLETE", "provenance matrix missing required bindings")
    determinism = dict(payloads["determinism"].get("determinism_requirements", {}))
    for key, code in (
        ("deterministic", "RC_B04R6_AFSH_SOURCE_VAL_DETERMINISM_MISSING"),
        ("seed_bound", "RC_B04R6_AFSH_SOURCE_VAL_DETERMINISM_MISSING"),
        ("hash_bound", "RC_B04R6_AFSH_SOURCE_VAL_HASH_BINDING_MISSING"),
        ("no_network", "RC_B04R6_AFSH_SOURCE_VAL_NETWORK_ALLOWED"),
        ("no_runtime_mutation", "RC_B04R6_AFSH_SOURCE_VAL_RUNTIME_MUTATION_ALLOWED"),
    ):
        if determinism.get(key) is not True:
            _fail(code, f"determinism contract missing {key}=true")
    rows.append(_pass_row("provenance_matrix_bound", "RC_B04R6_AFSH_SOURCE_VAL_PROVENANCE_MATRIX_INCOMPLETE", "provenance matrix is bound", group="provenance"))
    rows.append(_pass_row("source_determinism_contract_bound", "RC_B04R6_AFSH_SOURCE_VAL_DETERMINISM_MISSING", "source determinism contract is bound", group="determinism"))
    rows.append(_pass_row("source_is_hash_bound", "RC_B04R6_AFSH_SOURCE_VAL_HASH_BINDING_MISSING", "source is hash-bound", group="determinism"))
    rows.append(_pass_row("source_is_no_network", "RC_B04R6_AFSH_SOURCE_VAL_NETWORK_ALLOWED", "source derivation forbids network", group="determinism"))
    rows.append(_pass_row("source_forbids_runtime_mutation", "RC_B04R6_AFSH_SOURCE_VAL_RUNTIME_MUTATION_ALLOWED", "source derivation forbids runtime mutation", group="determinism"))
    return rows


def _validate_no_contamination(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    rules = dict(payloads["no_contamination"].get("no_contamination_rules", {}))
    required = {
        "blind_labels_inaccessible",
        "blind_outcomes_inaccessible",
        "route_success_labels_inaccessible",
        "old_r01_r04_diagnostic_only",
        "old_v2_six_row_diagnostic_only",
        "candidate_generation_still_forbidden",
    }
    for key in required:
        if rules.get(key) is not True:
            _fail("RC_B04R6_AFSH_SOURCE_VAL_OLD_UNIVERSE_PROOF_DRIFT", f"no-contamination contract missing {key}=true")
    rows.append(_pass_row("no_contamination_contract_bound", "RC_B04R6_AFSH_SOURCE_VAL_OLD_UNIVERSE_PROOF_DRIFT", "no-contamination contract is bound", group="no_contamination"))
    rows.append(_pass_row("source_forbids_truth_engine_mutation", "RC_B04R6_AFSH_SOURCE_VAL_TRUTH_ENGINE_MUTATION", "truth-engine mutation remains forbidden", group="no_contamination"))
    rows.append(_pass_row("source_forbids_trust_zone_mutation", "RC_B04R6_AFSH_SOURCE_VAL_TRUST_ZONE_MUTATION", "trust-zone mutation remains forbidden", group="no_contamination"))
    rows.append(_pass_row("source_forbids_package_promotion_behavior", "RC_B04R6_AFSH_SOURCE_VAL_PACKAGE_PROMOTION_DRIFT", "package-promotion behavior remains forbidden", group="no_contamination"))
    rows.append(_pass_row("source_forbids_activation_cutover_behavior", "RC_B04R6_AFSH_SOURCE_VAL_ACTIVATION_CUTOVER_DRIFT", "activation/cutover behavior remains forbidden", group="no_contamination"))
    return rows


def _validate_behavioral_requirements(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    contract = payloads["source_packet_contract"]
    defaults = dict(contract.get("behavioral_defaults_required_for_future_candidate", {}))
    compatibility = dict(contract.get("route_value_court_compatibility", {}))
    if defaults.get("unknown_case") != "STATIC_HOLD":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_STATIC_HOLD_DEFAULT_MISSING", "unknown cases must default static hold")
    if defaults.get("boundary_unclear") != "ABSTAIN":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_ABSTENTION_PRESERVATION_MISSING", "boundary unclear must abstain")
    if defaults.get("null_route_sibling") != "NULL_ROUTE":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_NULL_ROUTE_PRESERVATION_MISSING", "null-route sibling must preserve NULL_ROUTE")
    if defaults.get("mirror_masked_instability") != "STATIC_HOLD":
        _fail("RC_B04R6_AFSH_SOURCE_VAL_MIRROR_MASKED_STABILITY_MISSING", "mirror/masked instability must static hold")
    for key in (
        "route_value_law_validated",
        "static_hold_default_required",
        "abstention_preservation_required",
        "null_route_preservation_required",
        "route_eligible_non_executing_only",
    ):
        if compatibility.get(key) is not True:
            _fail("RC_B04R6_AFSH_SOURCE_VAL_ROUTE_VALUE_COURT_INCOMPATIBLE", f"route-value compatibility missing {key}=true")
    rows.append(_pass_row("static_hold_default_preserved", "RC_B04R6_AFSH_SOURCE_VAL_STATIC_HOLD_DEFAULT_MISSING", "static-hold default is preserved", group="behavior"))
    rows.append(_pass_row("abstention_preservation_required", "RC_B04R6_AFSH_SOURCE_VAL_ABSTENTION_PRESERVATION_MISSING", "abstention preservation is required", group="behavior"))
    rows.append(_pass_row("null_route_preservation_required", "RC_B04R6_AFSH_SOURCE_VAL_NULL_ROUTE_PRESERVATION_MISSING", "null-route preservation is required", group="behavior"))
    rows.append(_pass_row("mirror_masked_stability_required", "RC_B04R6_AFSH_SOURCE_VAL_MIRROR_MASKED_STABILITY_MISSING", "mirror/masked stability is required", group="behavior"))
    rows.append(_pass_row("route_value_court_compatibility_preserved", "RC_B04R6_AFSH_SOURCE_VAL_ROUTE_VALUE_COURT_INCOMPATIBLE", "route-value court compatibility is preserved", group="behavior"))
    return rows


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    required_flags = (
        "cannot_authorize_generation",
        "cannot_authorize_training",
        "cannot_authorize_admissibility",
        "cannot_authorize_screen_packet",
        "cannot_authorize_shadow_screen_execution",
        "cannot_authorize_activation",
        "cannot_authorize_package_promotion",
    )
    for label in ("candidate_generation_protocol_prep", "candidate_manifest_schema_prep", "admissibility_court_prep"):
        payload = payloads[label]
        if payload.get("status") != "PREP_ONLY" or payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_SOURCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must remain PREP_ONLY")
        for flag in required_flags:
            if payload.get(flag) is not True:
                _fail("RC_B04R6_AFSH_SOURCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} missing {flag}=true")
    rows.append(_pass_row("candidate_generation_protocol_is_prep_only", "RC_B04R6_AFSH_SOURCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", "candidate generation protocol remains prep-only", group="prep_only"))
    rows.append(_pass_row("candidate_manifest_schema_is_prep_only", "RC_B04R6_AFSH_SOURCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", "candidate manifest schema remains prep-only", group="prep_only"))
    rows.append(_pass_row("admissibility_court_draft_is_prep_only", "RC_B04R6_AFSH_SOURCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", "admissibility court draft remains prep-only", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_generation", "RC_B04R6_AFSH_SOURCE_VAL_GENERATION_AUTHORIZED", "prep-only drafts cannot authorize generation", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_training", "RC_B04R6_AFSH_SOURCE_VAL_TRAINING_AUTHORIZED", "prep-only drafts cannot authorize training", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_admissibility", "RC_B04R6_AFSH_SOURCE_VAL_ADMISSIBILITY_AUTHORIZED", "prep-only drafts cannot authorize admissibility", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_shadow_screen_packet", "RC_B04R6_AFSH_SOURCE_VAL_SHADOW_PACKET_AUTHORIZED", "prep-only drafts cannot authorize shadow-screen packet", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_shadow_screen_execution", "RC_B04R6_AFSH_SOURCE_VAL_SHADOW_SCREEN_AUTHORIZED", "prep-only drafts cannot authorize shadow-screen execution", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_activation", "RC_B04R6_AFSH_SOURCE_VAL_ACTIVATION_CUTOVER_DRIFT", "prep-only drafts cannot authorize activation", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_lobe_escalation", "RC_B04R6_AFSH_SOURCE_VAL_ACTIVATION_CUTOVER_DRIFT", "prep-only drafts cannot authorize lobe escalation", group="prep_only"))
    rows.append(_pass_row("prep_only_drafts_cannot_authorize_package_promotion", "RC_B04R6_AFSH_SOURCE_VAL_PACKAGE_PROMOTION_DRIFT", "prep-only drafts cannot authorize package promotion", group="prep_only"))
    return rows


def _validate_no_authorization_drift(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for label, payload in payloads.items():
        for key in FORBIDDEN_TRUE_KEYS:
            _ensure_false_if_present(payload, key, label=label)
        if payload.get("metric_widening_allowed") is not None and payload.get("metric_widening_allowed") is not False:
            _fail("RC_B04R6_AFSH_SOURCE_VAL_METRIC_WIDENING", f"{label} metric widening drifted")
        if payload.get("comparator_weakening_allowed") is not None and payload.get("comparator_weakening_allowed") is not False:
            _fail("RC_B04R6_AFSH_SOURCE_VAL_COMPARATOR_WEAKENING", f"{label} comparator weakening drifted")
    if payloads["no_authorization_drift"].get("no_downstream_authorization_drift") is not True:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_GENERATION_AUTHORIZED", "no-authorization-drift receipt must pass")
    rows.append(_pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_AFSH_SOURCE_VAL_GENERATION_AUTHORIZED", "no-authorization-drift receipt passes", group="authorization"))
    rows.append(_pass_row("no_candidate_generation_execution", "RC_B04R6_AFSH_SOURCE_VAL_GENERATION_AUTHORIZED", "candidate generation is not executed", group="authorization"))
    rows.append(_pass_row("no_candidate_training_execution", "RC_B04R6_AFSH_SOURCE_VAL_TRAINING_AUTHORIZED", "candidate training is not executed", group="authorization"))
    rows.append(_pass_row("no_admissibility_execution", "RC_B04R6_AFSH_SOURCE_VAL_ADMISSIBILITY_AUTHORIZED", "admissibility is not executed", group="authorization"))
    rows.append(_pass_row("no_shadow_screen_packet_authorization", "RC_B04R6_AFSH_SOURCE_VAL_SHADOW_PACKET_AUTHORIZED", "shadow-screen packet remains unauthorized", group="authorization"))
    rows.append(_pass_row("no_shadow_screen_execution_authorization", "RC_B04R6_AFSH_SOURCE_VAL_SHADOW_SCREEN_AUTHORIZED", "shadow-screen execution remains unauthorized", group="authorization"))
    rows.append(_pass_row("no_r6_open_drift", "RC_B04R6_AFSH_SOURCE_VAL_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"))
    rows.append(_pass_row("no_superiority_drift", "RC_B04R6_AFSH_SOURCE_VAL_SUPERIORITY_DRIFT", "learned-router superiority remains unearned", group="authorization"))
    rows.append(_pass_row("no_activation_or_cutover_drift", "RC_B04R6_AFSH_SOURCE_VAL_ACTIVATION_CUTOVER_DRIFT", "activation/cutover remains false", group="authorization"))
    rows.append(_pass_row("no_package_promotion_drift", "RC_B04R6_AFSH_SOURCE_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion remains deferred", group="authorization"))
    return rows


def _validate_future_blockers(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    blockers = payloads["future_blocker_register"].get("blockers", [])
    if not isinstance(blockers, list) or len(blockers) < 3:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "future-blocker register must name downstream blockers")
    text = " ".join(str(row.get("future_blocker", "")) for row in blockers if isinstance(row, dict)).lower()
    if "candidate" not in text or "admissibility" not in text:
        _fail("RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "future-blocker register must name candidate/admissibility blockers")
    return [_pass_row("future_blocker_register_present", "RC_B04R6_AFSH_SOURCE_VAL_CONTRACT_MISSING", "future blockers are registered", group="future")]


def _validate_trust_zone(payloads: Dict[str, Dict[str, Any]], fresh_validation: Dict[str, Any]) -> list[Dict[str, str]]:
    prior = payloads["trust_zone_binding"].get("fresh_trust_zone_validation", {})
    if not isinstance(prior, dict) or prior.get("status") != "PASS" or prior.get("failures"):
        _fail("RC_B04R6_AFSH_SOURCE_VAL_TRUST_ZONE_MUTATION", "source trust-zone binding receipt must pass")
    if fresh_validation.get("status") != "PASS" or fresh_validation.get("failures"):
        _fail("RC_B04R6_AFSH_SOURCE_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass with no failures")
    return [
        _pass_row("trust_zone_binding_receipt_passes", "RC_B04R6_AFSH_SOURCE_VAL_TRUST_ZONE_MUTATION", "source trust-zone binding receipt passes", group="trust_zone"),
        _pass_row("fresh_trust_zone_validation_passes", "RC_B04R6_AFSH_SOURCE_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation passed", group="trust_zone"),
    ]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    source_packet_replay_binding_head: str,
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
        "source_packet_replay_binding_head": source_packet_replay_binding_head,
        "architecture_binding_head": architecture_binding_head,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "current_branch": current_branch,
        "allowed_outcomes": [OUTCOME_VALIDATED, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "forbidden_actions": FORBIDDEN_ACTIONS,
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "candidate_generation_executed": False,
        "candidate_training_authorized": False,
        "afsh_candidate_generation_authorized": False,
        "afsh_candidate_generation_executed": False,
        "afsh_candidate_training_authorized": False,
        "afsh_candidate_training_executed": False,
        "afsh_admissibility_authorized": False,
        "afsh_admissibility_executed": False,
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
        "candidate_generation_next_lawful": True,
        "candidate_generation_not_executed_by_validation": True,
    }


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_generation_executed": False,
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
        "# B04 R6 AFSH Implementation Source Packet Validation",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "The validation court confirms the AFSH source packet is complete, provenance-bound, leakage-guarded, deterministic, no-network, trust-zone compatible, and non-executing.",
        "",
        "No AFSH candidate generation, candidate training, admissibility, shadow-screen packet, shadow-screen execution, R6 opening, activation, lobe escalation, package promotion, or learned-router superiority is executed or authorized by this validation lane.",
        "",
        f"Next lawful move: `{NEXT_LAWFUL_MOVE}`",
        "",
        "## Validation Rows",
    ]
    for row in rows:
        lines.append(f"- `{row['check_id']}`: `{row['status']}` ({row['reason_code']})")
    lines.append("")
    return "\n".join(lines)


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 AFSH source-packet validation freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    _require_inputs(root, payloads, text_payloads)

    fresh_trust_validation = validate_trust_zones(root=root)

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)

    rows: list[Dict[str, str]] = []
    rows.extend(_validate_previous_state(payloads, text_payloads))
    replay_rows, source_packet_replay_binding_head = _validate_replay_binding(payloads, current_main_head=current_main_head)
    rows.extend(replay_rows)
    rows.extend(_validate_features(payloads))
    rows.extend(_validate_trace(payloads))
    rows.extend(_validate_provenance_and_determinism(payloads))
    rows.extend(_validate_no_contamination(payloads))
    rows.extend(_validate_behavioral_requirements(payloads))
    rows.extend(_validate_prep_only(payloads))
    rows.extend(_validate_no_authorization_drift(payloads))
    rows.extend(_validate_future_blockers(payloads))
    rows.extend(_validate_trust_zone(payloads, fresh_trust_validation))
    rows.append(
        _pass_row(
            "next_lawful_move_is_candidate_generation",
            "RC_B04R6_AFSH_SOURCE_VAL_NEXT_MOVE_DRIFT",
            "the next lawful move is candidate generation lane, not candidate execution inside validation",
            group="next_move",
        )
    )

    generated_utc = utc_now_iso_z()
    receipt = payloads["source_packet_receipt"]
    architecture_binding_head = str(receipt.get("architecture_binding_head", "")).strip()
    validated_blind_universe_binding = _validated_blind_universe_binding(receipt)
    validated_court_binding = _validated_court_binding(receipt)
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        source_packet_replay_binding_head=source_packet_replay_binding_head,
        architecture_binding_head=architecture_binding_head,
        current_branch=current_branch,
    )
    common_extra = {
        "validated_source_packet_binding": {
            "status": "BOUND_AND_VALIDATED",
            "source_packet_replay_binding_head": source_packet_replay_binding_head,
            "previous_outcome": EXPECTED_PREVIOUS_OUTCOME,
            "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
            "selected_validation_outcome": SELECTED_OUTCOME,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        "validated_blind_universe_binding": validated_blind_universe_binding,
        "validated_court_binding": validated_court_binding,
        "allowed_feature_families": list(ALLOWED_FEATURE_FAMILIES),
        "forbidden_feature_families": list(FORBIDDEN_FEATURE_FAMILIES),
        "trace_requirement_flags": list(TRACE_REQUIREMENT_FLAGS),
        "provenance_bindings": list(PROVENANCE_BINDINGS),
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["validation_contract"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_packet_validation_contract.v1",
            rows=rows,
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_AFSH_SOURCE_PACKET_VALIDATION_CONTRACT",
                "validation_object": "B04 R6 AFSH implementation source packet",
                "validation_goal": "Prove the source packet is complete, deterministic, provenance-bound, leakage-guarded, trust-zone compatible, and incapable of authorizing downstream execution.",
            },
        ),
        OUTPUTS["validation_receipt"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_packet_validation_receipt.v1",
            rows=rows,
            input_bindings=input_bindings,
            extra={**common_extra, "source_packet_validated": True, "verdict": SELECTED_OUTCOME},
        ),
        OUTPUTS["allowed_features_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_allowed_features_validation_receipt.v1",
            rows=_rows_for(rows, "allowed_features"),
            input_bindings=input_bindings,
            extra={**common_extra, "allowed_features_validated": True},
        ),
        OUTPUTS["forbidden_features_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_forbidden_features_validation_receipt.v1",
            rows=_rows_for(rows, "forbidden_features"),
            input_bindings=input_bindings,
            extra={**common_extra, "forbidden_features_validated": True},
        ),
        OUTPUTS["trace_schema_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_trace_schema_validation_receipt.v1",
            rows=_rows_for(rows, "trace_schema"),
            input_bindings=input_bindings,
            extra={**common_extra, "trace_schema_validated": True},
        ),
        OUTPUTS["provenance_matrix_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_provenance_matrix_validation_receipt.v1",
            rows=_rows_for(rows, "provenance"),
            input_bindings=input_bindings,
            extra={**common_extra, "provenance_matrix_validated": True},
        ),
        OUTPUTS["determinism_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_determinism_validation_receipt.v1",
            rows=_rows_for(rows, "determinism"),
            input_bindings=input_bindings,
            extra={**common_extra, "source_determinism_validated": True},
        ),
        OUTPUTS["no_contamination_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_no_contamination_validation_receipt.v1",
            rows=_rows_for(rows, "no_contamination", "source_packet"),
            input_bindings=input_bindings,
            extra={**common_extra, "no_contamination_validated": True},
        ),
        OUTPUTS["prep_only_non_authority_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_prep_only_non_authority_validation_receipt.v1",
            rows=_rows_for(rows, "prep_only", "future"),
            input_bindings=input_bindings,
            extra={**common_extra, "prep_only_non_authority_validated": True},
        ),
        OUTPUTS["no_authorization_drift_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_no_authorization_drift_validation_receipt.v1",
            rows=_rows_for(rows, "authorization"),
            input_bindings=input_bindings,
            extra={**common_extra, "no_downstream_authorization_drift": True},
        ),
        OUTPUTS["trust_zone_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_trust_zone_validation_receipt.v1",
            rows=_rows_for(rows, "trust_zone"),
            input_bindings=input_bindings,
            extra={**common_extra, "fresh_trust_zone_validation": fresh_trust_validation},
        ),
        OUTPUTS["replay_binding_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.afsh_source_replay_binding_validation_receipt.v1",
            rows=_rows_for(rows, "replay"),
            input_bindings=input_bindings,
            extra={**common_extra, "source_packet_replay_binding_validated": True},
        ),
        OUTPUTS["next_lawful_move"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v9",
            rows=_rows_for(rows, "next_move"),
            input_bindings=input_bindings,
            extra={**common_extra, "verdict": SELECTED_OUTCOME},
        ),
        OUTPUTS["validation_report"]: _report(rows),
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "pass_count": len(rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate B04 R6 AFSH implementation source packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
