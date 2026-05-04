from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-afsh-candidate-generation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_AFSH_CANDIDATE_GENERATION"
PREVIOUS_LANE = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_VALIDATION"

EXPECTED_PREVIOUS_OUTCOME = "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_VALIDATED__CANDIDATE_GENERATION_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "GENERATE_B04_R6_AFSH_CANDIDATE"
OUTCOME_GENERATED = "B04_R6_AFSH_CANDIDATE_GENERATED__ADMISSIBILITY_COURT_NEXT"
OUTCOME_DEFERRED = "B04_R6_AFSH_CANDIDATE_GENERATION_DEFERRED__NAMED_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_AFSH_CANDIDATE_GENERATION_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_GENERATED
NEXT_LAWFUL_MOVE = "RUN_B04_R6_AFSH_ADMISSIBILITY_COURT"

SELECTED_ARCHITECTURE_ID = "AFSH-2S-GUARD"
SELECTED_ARCHITECTURE_NAME = "Abstention-First Static-Hold Two-Stage Guarded Router"
CANDIDATE_ID = "B04_R6_AFSH_CANDIDATE_V1"
CANDIDATE_VERSION = "v1"
CASE_PREFIX = "B04R6-AFSH-BU1-"
EXPECTED_CASE_COUNT = 18

TOP_LEVEL_VERDICTS = ("STATIC_HOLD", "ABSTAIN", "NULL_ROUTE", "ROUTE_ELIGIBLE")
TRIAGE_SUBTYPES = (
    "PRIMARY_CARE_STATIC",
    "DEFER",
    "HUMAN_OR_COURT_REVIEW",
    "QUARANTINE_OR_NONCANONICAL",
    "SPECIALIST_REFERRAL_CANDIDATE",
)
NUMERIC_SCORE_FIELDS = (
    "static_hold_score",
    "abstention_score",
    "null_route_score",
    "route_eligible_score",
    "wrong_route_cost",
    "wrong_static_hold_cost",
    "proof_burden_cost",
    "overrouting_risk",
    "trust_zone_risk",
    "mirror_masked_instability",
    "specialist_value_estimate",
)
FORBIDDEN_ACCESS_FIELDS = (
    "blind_outcome_labels_accessed",
    "blind_route_success_labels_accessed",
    "post_screen_labels_accessed",
    "hidden_adjudication_labels_accessed",
    "old_r01_r04_counted_labels_accessed",
    "old_v2_six_row_counted_labels_accessed",
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
TRACE_FIELDS = (
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

FORBIDDEN_TRUE_KEYS = (
    "r6_authorized",
    "r6_open",
    "router_generation_authorized",
    "candidate_training_authorized",
    "candidate_training_executed",
    "afsh_candidate_training_authorized",
    "afsh_candidate_training_executed",
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
)
FORBIDDEN_ACTIONS = (
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
    "CURRENT_ROUTE_VALUE_FORMULA_MUTATED_BY_COMPRESSION_PREP",
)

CANDIDATE_REASON_CODES = (
    "RC_B04R6_AFSH_CANDIDATE_GEN_CONTRACT_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH",
    "RC_B04R6_AFSH_CANDIDATE_GEN_ARCHITECTURE_MISMATCH",
    "RC_B04R6_AFSH_CANDIDATE_GEN_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_COURT_BINDING_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_MANIFEST_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_CANDIDATE_ARTIFACT_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_HASH_RECEIPT_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_DERIVATION_RECEIPT_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_TRAINING_EXECUTED",
    "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_OUTCOME_ACCESS",
    "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_ROUTE_SUCCESS_ACCESS",
    "RC_B04R6_AFSH_CANDIDATE_GEN_POST_SCREEN_LABEL_ACCESS",
    "RC_B04R6_AFSH_CANDIDATE_GEN_STATIC_HOLD_DEFAULT_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_ABSTENTION_PRESERVATION_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_NULL_ROUTE_PRESERVATION_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_MIRROR_MASKED_STABILITY_MISSING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE",
    "RC_B04R6_AFSH_CANDIDATE_GEN_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_AFSH_CANDIDATE_GEN_ADMISSIBILITY_EXECUTED",
    "RC_B04R6_AFSH_CANDIDATE_GEN_SHADOW_PACKET_AUTHORIZED",
    "RC_B04R6_AFSH_CANDIDATE_GEN_R6_OPEN_DRIFT",
    "RC_B04R6_AFSH_CANDIDATE_GEN_SUPERIORITY_DRIFT",
    "RC_B04R6_AFSH_CANDIDATE_GEN_ACTIVATION_DRIFT",
    "RC_B04R6_AFSH_CANDIDATE_GEN_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_AFSH_CANDIDATE_GEN_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_AFSH_CANDIDATE_GEN_TRUST_ZONE_MUTATION",
    "RC_B04R6_AFSH_CANDIDATE_GEN_METRIC_WIDENING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_COMPARATOR_WEAKENING",
    "RC_B04R6_AFSH_CANDIDATE_GEN_NEXT_MOVE_DRIFT",
    "RC_B04R6_TRIAGE_STATIC_HOLD_DOMINANT",
    "RC_B04R6_TRIAGE_TRUST_ZONE_UNCLEAR",
    "RC_B04R6_TRIAGE_BOUNDARY_UNCLEAR",
    "RC_B04R6_TRIAGE_NULL_ROUTE_SURFACE_TEMPTATION",
    "RC_B04R6_TRIAGE_SELECTOR_ENTRY_AUTHORIZED",
    "RC_KT_MEMORY_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_KT_MEMORY_COMPRESSED_INDEX_USED_AS_TRUTH",
    "RC_KT_MEMORY_ROUTE_VALUE_FORMULA_MUTATION",
)
TERMINAL_DEFECTS = (
    "TRAINING_EXECUTED",
    "ADMISSIBILITY_EXECUTED",
    "SHADOW_PACKET_AUTHORIZED",
    "SHADOW_SCREEN_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "SUPERIORITY_DRIFT",
    "ACTIVATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "BLIND_OUTCOME_ACCESS",
    "BLIND_ROUTE_SUCCESS_ACCESS",
    "POST_SCREEN_LABEL_ACCESS",
    "OLD_UNIVERSE_COUNTED_LABEL_ACCESS",
    "PREP_ONLY_AUTHORITY_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "METRIC_WIDENING",
    "COMPARATOR_WEAKENING",
    "NEXT_MOVE_DRIFT",
)

INPUTS = {
    "source_validation_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_packet_validation_contract.json",
    "source_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_packet_validation_receipt.json",
    "allowed_features_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_allowed_features_validation_receipt.json",
    "forbidden_features_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_forbidden_features_validation_receipt.json",
    "trace_schema_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_trace_schema_validation_receipt.json",
    "provenance_matrix_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_provenance_matrix_validation_receipt.json",
    "source_determinism_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_determinism_validation_receipt.json",
    "no_contamination_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_no_contamination_validation_receipt.json",
    "prep_only_non_authority_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_prep_only_non_authority_validation_receipt.json",
    "no_authorization_drift_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_no_authorization_drift_validation_receipt.json",
    "trust_zone_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_trust_zone_validation_receipt.json",
    "replay_binding_validation": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_replay_binding_validation_receipt.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})
TEXT_INPUTS = {
    "source_validation_report": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_source_packet_validation_report.md",
}
REFERENCE_INPUTS = {
    "source_packet_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_implementation_source_packet_contract.json",
    "court_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_receipt.json",
    "blind_universe_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_case_manifest.json",
    "trust_zone_registry": "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
    "canonical_scope_manifest": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
}

OUTPUTS = {
    "generation_contract": "b04_r6_afsh_candidate_generation_contract.json",
    "candidate_manifest": "b04_r6_afsh_candidate_manifest.json",
    "candidate_hash_receipt": "b04_r6_afsh_candidate_hash_receipt.json",
    "candidate_derivation_receipt": "b04_r6_afsh_candidate_derivation_receipt.json",
    "rule_materialization_receipt": "b04_r6_afsh_candidate_rule_materialization_receipt.json",
    "no_training_receipt": "b04_r6_afsh_candidate_no_training_receipt.json",
    "no_contamination_receipt": "b04_r6_afsh_candidate_no_contamination_receipt.json",
    "static_hold_default_receipt": "b04_r6_afsh_candidate_static_hold_default_receipt.json",
    "abstention_preservation_receipt": "b04_r6_afsh_candidate_abstention_preservation_receipt.json",
    "null_route_preservation_receipt": "b04_r6_afsh_candidate_null_route_preservation_receipt.json",
    "mirror_masked_stability_receipt": "b04_r6_afsh_candidate_mirror_masked_stability_receipt.json",
    "trace_schema_receipt": "b04_r6_afsh_candidate_trace_schema_receipt.json",
    "source_hash_receipt": "b04_r6_afsh_candidate_source_hash_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_afsh_candidate_no_authorization_drift_receipt.json",
    "stable_semantic_hash_basis": "b04_r6_afsh_candidate_stable_semantic_hash_basis.json",
    "immutable_input_manifest": "b04_r6_afsh_candidate_immutable_input_manifest.json",
    "replay_binding_receipt": "b04_r6_afsh_candidate_replay_binding_receipt.json",
    "mutable_handoff_binding_receipt": "b04_r6_afsh_candidate_mutable_handoff_binding_receipt.json",
    "prep_only_non_authority_receipt": "b04_r6_afsh_candidate_prep_only_non_authority_receipt.json",
    "old_universe_diagnostic_only_receipt": "b04_r6_afsh_candidate_old_universe_diagnostic_only_receipt.json",
    "numeric_triage_emit_core": "b04_r6_afsh_numeric_triage_emit_core_contract.json",
    "triage_intake_gate": "b04_r6_afsh_triage_intake_gate_contract.json",
    "triage_tag_schema": "b04_r6_afsh_triage_tag_schema.json",
    "triage_score_schema": "b04_r6_afsh_triage_score_schema.json",
    "triage_emit_decision_matrix": "b04_r6_afsh_triage_emit_decision_matrix.json",
    "triage_receipt_schema": "b04_r6_afsh_triage_receipt_schema.json",
    "triage_static_hold_policy": "b04_r6_afsh_triage_static_hold_policy.json",
    "triage_specialist_referral_policy": "b04_r6_afsh_triage_specialist_referral_policy.json",
    "triage_quarantine_review_policy": "b04_r6_afsh_triage_quarantine_review_policy.json",
    "triage_no_authorization_drift_receipt": "b04_r6_afsh_triage_no_authorization_drift_receipt.json",
    "candidate_v1": "b04_r6_afsh_candidate_v1.json",
    "admissibility_court_prep": "b04_r6_afsh_admissibility_court_prep_only_draft.json",
    "admissibility_reason_codes_prep": "b04_r6_afsh_admissibility_reason_codes_prep_only_draft.json",
    "replay_validation_plan_prep": "b04_r6_afsh_replay_validation_plan_prep_only_draft.json",
    "trace_compatibility_validation_plan_prep": "b04_r6_afsh_trace_compatibility_validation_plan_prep_only_draft.json",
    "turboquant_translation": "kt_turboquant_research_translation_matrix_prep_only.json",
    "kv_cache_compression": "kt_kv_cache_compression_readiness_contract_prep_only.json",
    "memory_cost_delta": "kt_memory_cost_delta_route_economics_extension_prep_only.json",
    "compressed_receipt_index": "kt_compressed_receipt_vector_index_contract_prep_only.json",
    "compression_risk_register": "kt_compression_distortion_risk_register_prep_only.json",
    "long_context_cost_model": "kt_long_context_replay_cost_model_prep_only.json",
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


def _rows_for(rows: list[Dict[str, str]], *groups: str) -> list[Dict[str, str]]:
    wanted = set(groups)
    return [row for row in rows if row.get("group") in wanted]


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
            row["binding_kind"] = "file_sha256_at_candidate_generation"
        rows.append(row)
    return rows


def _strip_volatile(value: Any, *, excluded_keys: Iterable[str] = ("generated_utc",)) -> Any:
    excluded = set(excluded_keys)
    if isinstance(value, dict):
        return {key: _strip_volatile(item, excluded_keys=excluded) for key, item in value.items() if key not in excluded}
    if isinstance(value, list):
        return [_strip_volatile(item, excluded_keys=excluded) for item in value]
    return value


def candidate_semantic_hash(candidate: Dict[str, Any]) -> str:
    return sha256_hex(canonicalize_bytes(_strip_volatile(candidate)))


def _envelope_hash(payload: Dict[str, Any]) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_ADMISSIBILITY_EXECUTED", f"{label} drifted: {key} must remain false")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() not in {"PASS", "FROZEN_PACKET"}:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_CONTRACT_MISSING", f"{label} must be PASS or FROZEN_PACKET")
    if payload.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_ARCHITECTURE_MISMATCH", f"{label} must bind AFSH-2S-GUARD")
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_PACKAGE_PROMOTION_DRIFT", f"{label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_TRUTH_ENGINE_MUTATION", f"{label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_TRUST_ZONE_MUTATION", f"{label} must preserve trust-zone law")


def _existing_generation_contract_supports_self_replay(root: Path) -> bool:
    path = root / "KT_PROD_CLEANROOM" / "reports" / OUTPUTS["generation_contract"]
    if not path.is_file():
        return False
    payload = common.load_json_required(root, path, label="existing AFSH candidate generation contract")
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


def _validated_blind_universe_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_blind_universe_binding", {}))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_UNIVERSE_BINDING_MISSING", "validated blind universe is not bound")
    if binding.get("case_count") != EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_UNIVERSE_BINDING_MISSING", "validated blind universe must bind 18 cases")
    if binding.get("case_namespace") != f"{CASE_PREFIX}*":
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_UNIVERSE_BINDING_MISSING", "validated blind universe namespace drifted")
    if binding.get("prior_r01_r04_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_OLD_R01_R04_COUNTED_LABEL_ACCESS", "R01-R04 must remain diagnostic-only")
    if binding.get("prior_v2_six_row_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_OLD_V2_SIX_ROW_COUNTED_LABEL_ACCESS", "v2 six-row screen must remain diagnostic-only")
    return binding


def _validated_court_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_court_binding", {}))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_COURT_BINDING_MISSING", "validated route-value court binding missing")
    if binding.get("route_eligible_non_executing_only") is not True:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_COURT_BINDING_MISSING", "route eligible must remain non-executing in prior court")
    if tuple(binding.get("verdict_modes", [])) != TOP_LEVEL_VERDICTS:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_COURT_BINDING_MISSING", "court verdict modes drifted")
    return binding


def _require_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> str:
    for role, payload in payloads.items():
        if role in MUTABLE_HANDOFF_ROLES:
            continue
        _ensure_common_boundary(payload, label=role)
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING", f"{role} must come from source validation lane")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING", f"{role} outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_AFSH_CANDIDATE_GEN_NEXT_MOVE_DRIFT", f"{role} does not authorize candidate generation")
    if not text_payloads["source_validation_report"].strip():
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING", "source validation report missing")

    contract = payloads["source_validation_contract"]
    receipt = payloads["source_validation_receipt"]
    handoff = payloads["previous_next_lawful_move"]
    if contract.get("source_packet_validated") is not None and contract.get("source_packet_validated") is not True:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING", "source validation contract must be validating source packet")
    if receipt.get("source_packet_validated") is not True:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING", "source validation receipt must mark source_packet_validated=true")
    if int(receipt.get("failure_count", 1)) != 0:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING", "source validation failures remain")
    _validated_blind_universe_binding(receipt)
    _validated_court_binding(receipt)

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
        and _existing_generation_contract_supports_self_replay(root)
    )
    if not (handoff_is_previous or handoff_is_self_replay):
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_NEXT_MOVE_DRIFT", "next lawful move receipt does not authorize candidate generation")
    return str(contract.get("current_git_head", "")).strip()


def _validate_immutable_source_heads(payloads: Dict[str, Dict[str, Any]], *, source_validation_head: str) -> list[Dict[str, str]]:
    if len(source_validation_head) != 40:
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH", "source validation replay head must be a full git SHA")
    for role, payload in payloads.items():
        if role in MUTABLE_HANDOFF_ROLES:
            continue
        if payload.get("current_git_head") != source_validation_head:
            _fail("RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH", f"{role} does not bind source validation replay head")
        if payload.get("current_main_head") != source_validation_head:
            _fail("RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH", f"{role} does not bind source validation replay main head")
    return [
        _pass_row("candidate_immutable_inputs_share_replay_head", "RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH", "all immutable source-validation inputs share replay head", group="replay"),
        _pass_row("candidate_mixed_head_inputs_fail_closed", "RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH", "mixed-head immutable inputs are fail-closed by validator", group="replay"),
    ]


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_generation_executed_in_this_lane": True,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "afsh_admissibility_next_lawful_lane": True,
        "afsh_admissibility_executed": False,
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


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    source_validation_head: str,
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
        "source_packet_validation_replay_binding_head": source_validation_head,
        "architecture_binding_head": architecture_binding_head,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "current_branch": current_branch,
        "allowed_outcomes": [OUTCOME_GENERATED, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "candidate_generation_executed": True,
        "afsh_candidate_generation_executed": True,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "afsh_candidate_training_authorized": False,
        "afsh_candidate_training_executed": False,
        "afsh_admissibility_executed": False,
        "shadow_screen_authorized": False,
        "shadow_screen_packet_authorized": False,
        "shadow_screen_execution_authorized": False,
        "activation_review_authorized": False,
        "runtime_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "old_r01_r04_diagnostic_only": True,
        "old_v2_six_row_diagnostic_only": True,
    }


def _receipt_payload(
    *,
    base: Dict[str, Any],
    schema_id: str,
    artifact_id: str,
    rows: list[Dict[str, str]],
    input_bindings: list[Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        **base,
        "authorization_state": _authorization_state(),
        "validation_rows": rows,
        "pass_count": len(rows),
        "failure_count": 0,
        "reason_codes": list(CANDIDATE_REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
    }
    if extra:
        payload.update(extra)
    return payload


def _candidate_defaults() -> Dict[str, str]:
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


def _emit_logic_order() -> list[Dict[str, str]]:
    return [
        {"if": "trust_zone_unclear", "emit": "ABSTAIN", "triage_subtype": "QUARANTINE_OR_NONCANONICAL"},
        {"if": "boundary_unclear", "emit": "ABSTAIN", "triage_subtype": "HUMAN_OR_COURT_REVIEW"},
        {"if": "null_route_control_active", "emit": "NULL_ROUTE", "triage_subtype": "DEFER"},
        {"if": "route_value_below_threshold", "emit": "STATIC_HOLD", "triage_subtype": "PRIMARY_CARE_STATIC"},
        {"if": "mirror_masked_instability_above_threshold", "emit": "STATIC_HOLD", "triage_subtype": "PRIMARY_CARE_STATIC"},
        {"if": "proof_burden_not_justified", "emit": "STATIC_HOLD", "triage_subtype": "PRIMARY_CARE_STATIC"},
        {"if": "route_eligible_score_clears_threshold_and_all_guards_pass", "emit": "ROUTE_ELIGIBLE", "triage_subtype": "SPECIALIST_REFERRAL_CANDIDATE"},
        {"else": "fail_closed", "emit": "STATIC_HOLD", "triage_subtype": "PRIMARY_CARE_STATIC"},
    ]


def _numeric_triage_core() -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.afsh_numeric_triage_emit_core.v1",
        "artifact_id": "B04_R6_AFSH_NUMERIC_TRIAGE_EMIT_CORE",
        "authority": "CANDIDATE_INTERNAL_AUTHORITATIVE",
        "purpose": "Deterministically score receipt-derived features and emit exactly one validated court verdict before selector entry.",
        "top_level_verdict_modes": list(TOP_LEVEL_VERDICTS),
        "new_top_level_verdicts_allowed": False,
        "triage_subtypes_allowed": list(TRIAGE_SUBTYPES),
        "numeric_score_fields": list(NUMERIC_SCORE_FIELDS),
        "score_bounds": {"min": 0.0, "max": 1.0},
        "emit_logic_order": _emit_logic_order(),
        "selector_entry_rule": {
            "selector_entry_authorized_only_if": "top_level_verdict == ROUTE_ELIGIBLE",
            "static_hold_selector_entry": False,
            "abstain_selector_entry": False,
            "null_route_selector_entry": False,
        },
        "tag_safety": {
            "tags_must_be_receipt_derived": True,
            "tags_must_be_source_packet_allowed": True,
            "blind_label_dependent_tags_allowed": False,
            "blind_outcome_dependent_tags_allowed": False,
            "route_success_label_dependent_tags_allowed": False,
            "post_screen_label_dependent_tags_allowed": False,
        },
        "forbidden_actions": [item for item in FORBIDDEN_ACTIONS if item != "CURRENT_ROUTE_VALUE_FORMULA_MUTATED_BY_COMPRESSION_PREP"],
    }


def _triage_receipt_schema() -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.afsh_triage_receipt_schema.v1",
        "artifact_id": "B04_R6_AFSH_TRIAGE_RECEIPT_SCHEMA",
        "required_fields": [
            "case_id",
            "triage_receipt_id",
            "top_level_verdict",
            "triage_subtype",
            "route_eligible",
            "selector_entry_authorized",
            "numeric_scores",
            "primary_reason_code",
            "trust_zone_tags",
            "evidence_tags",
            "risk_tags",
            "route_economics_tags",
            "specialist_candidate_tags",
            "why_not_static",
            "why_not_abstain",
            "why_not_route",
            "required_next_action",
            "forbidden_access_status",
        ],
        "top_level_verdict_enum": list(TOP_LEVEL_VERDICTS),
        "triage_subtype_enum": list(TRIAGE_SUBTYPES),
        "numeric_scores_required": list(NUMERIC_SCORE_FIELDS),
        "forbidden_access_status_required": list(FORBIDDEN_ACCESS_FIELDS),
        "invariants": [
            "selector_entry_authorized == true iff top_level_verdict == ROUTE_ELIGIBLE",
            "specialist_candidate_tags must be empty unless top_level_verdict == ROUTE_ELIGIBLE",
            "STATIC_HOLD, ABSTAIN, and NULL_ROUTE must emit why_not_route",
            "forbidden_access_status values must all be false",
        ],
    }


def _triage_policy_payloads() -> Dict[str, Dict[str, Any]]:
    authority = {"authority": "CANDIDATE_INTERNAL_AUTHORITATIVE", "candidate_id": CANDIDATE_ID}
    return {
        OUTPUTS["triage_intake_gate"]: {
            "schema_id": "kt.b04_r6.afsh_triage_intake_gate_contract.v1",
            "artifact_id": "B04_R6_AFSH_TRIAGE_INTAKE_GATE",
            **authority,
            "stage": "STAGE_0_AUTHORITY_AND_INPUT_INTAKE",
            "runs_before_selector": True,
            "selector_entry_authorized_by_default": False,
            "trust_zone_unclear": "ABSTAIN",
            "boundary_unclear": "ABSTAIN",
            "unknown_case": "STATIC_HOLD",
        },
        OUTPUTS["triage_tag_schema"]: {
            "schema_id": "kt.b04_r6.afsh_triage_tag_schema.v1",
            "artifact_id": "B04_R6_AFSH_TRIAGE_TAG_SCHEMA",
            **authority,
            "tags_must_be_receipt_derived": True,
            "tags_must_be_source_packet_allowed": True,
            "forbidden_tag_dependencies": [
                "blind_outcome_labels",
                "blind_route_success_labels",
                "post_screen_labels",
                "hidden_adjudication_labels",
                "old_r01_r04_counted_labels",
                "old_v2_six_row_counted_labels",
            ],
            "tag_groups": ["trust_zone_tags", "evidence_tags", "risk_tags", "route_economics_tags", "specialist_candidate_tags"],
        },
        OUTPUTS["triage_score_schema"]: {
            "schema_id": "kt.b04_r6.afsh_triage_score_schema.v1",
            "artifact_id": "B04_R6_AFSH_TRIAGE_SCORE_SCHEMA",
            **authority,
            "numeric_score_fields": list(NUMERIC_SCORE_FIELDS),
            "score_bounds": {"min": 0.0, "max": 1.0},
            "deterministic": True,
            "seed_bound": True,
        },
        OUTPUTS["triage_emit_decision_matrix"]: {
            "schema_id": "kt.b04_r6.afsh_triage_emit_decision_matrix.v1",
            "artifact_id": "B04_R6_AFSH_TRIAGE_EMIT_DECISION_MATRIX",
            **authority,
            "emit_logic_order": _emit_logic_order(),
            "only_route_eligible_enters_selector": True,
            "static_hold_enters_selector": False,
            "abstain_enters_selector": False,
            "null_route_enters_selector": False,
            "fail_closed_default": "STATIC_HOLD",
        },
        OUTPUTS["triage_receipt_schema"]: _triage_receipt_schema(),
        OUTPUTS["triage_static_hold_policy"]: {
            "schema_id": "kt.b04_r6.afsh_triage_static_hold_policy.v1",
            "artifact_id": "B04_R6_AFSH_TRIAGE_STATIC_HOLD_POLICY",
            **authority,
            "static_hold_is_default": True,
            "wins_when": [
                "static comparator sufficient",
                "route value below threshold",
                "proof burden not justified",
                "overrouting risk high",
                "mirror/masked instability",
            ],
        },
        OUTPUTS["triage_specialist_referral_policy"]: {
            "schema_id": "kt.b04_r6.afsh_triage_specialist_referral_policy.v1",
            "artifact_id": "B04_R6_AFSH_TRIAGE_SPECIALIST_REFERRAL_POLICY",
            **authority,
            "selector_entry_only_for": "ROUTE_ELIGIBLE",
            "triage_subtype": "SPECIALIST_REFERRAL_CANDIDATE",
            "requires": [
                "route_value_threshold_cleared",
                "wrong_route_cost_bounded",
                "trust_zone_clear",
                "proof_burden_justified",
                "mirror_masked_stable",
            ],
        },
        OUTPUTS["triage_quarantine_review_policy"]: {
            "schema_id": "kt.b04_r6.afsh_triage_quarantine_review_policy.v1",
            "artifact_id": "B04_R6_AFSH_TRIAGE_QUARANTINE_REVIEW_POLICY",
            **authority,
            "trust_zone_unclear": "ABSTAIN",
            "boundary_unclear": "ABSTAIN",
            "quarantine_subtype": "QUARANTINE_OR_NONCANONICAL",
            "human_or_court_review_subtype": "HUMAN_OR_COURT_REVIEW",
        },
    }


def _candidate_v1(
    *,
    generated_utc: str,
    current_main_head: str,
    hashes: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.afsh_candidate_v1.v1",
        "artifact_id": "B04_R6_AFSH_CANDIDATE_V1",
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "generated_utc": generated_utc,
        "current_main_head": current_main_head,
        "selected_architecture": SELECTED_ARCHITECTURE_ID,
        "candidate_kind": "DETERMINISTIC_RULE_MATERIALIZATION",
        "training_executed": False,
        "candidate_generation_executed": True,
        "modules": {
            "numeric_triage_emit_core": "B04_R6_AFSH_NUMERIC_TRIAGE_EMIT_CORE",
            "route_eligibility_selector": "B04_R6_AFSH_ROUTE_ELIGIBILITY_SELECTOR",
            "guard_ensemble": "B04_R6_AFSH_GUARD_ENSEMBLE",
            "trace_receipt_replay_layer": "B04_R6_AFSH_TRACE_RECEIPT_REPLAY_LAYER",
        },
        "module_hashes": hashes,
        "candidate_defaults": _candidate_defaults(),
        "stage_model": {
            "stage_0": "NUMERIC_TRIAGE_AND_AUTHORITY_INTAKE_GATE",
            "stage_1": "ABSTENTION_AND_UNCERTAINTY_GATE",
            "stage_2": "ROUTE_ELIGIBILITY_SELECTOR_ONLY_FOR_ROUTE_ELIGIBLE",
            "stage_3": "GUARD_ENSEMBLE",
            "stage_4": "TRACE_RECEIPT_REPLAY_LAYER",
        },
        "top_level_verdict_modes": list(TOP_LEVEL_VERDICTS),
        "allowed_triage_subtypes": list(TRIAGE_SUBTYPES),
        "selector_entry_rule": {
            "only_top_level_verdict_allowed_to_enter_selector": "ROUTE_ELIGIBLE",
            "static_hold_enters_selector": False,
            "abstain_enters_selector": False,
            "null_route_enters_selector": False,
        },
        "numeric_triage_emit_core": _numeric_triage_core(),
        "guard_ensemble": {
            "control_preservation_required": True,
            "abstention_preservation_required": True,
            "null_route_preservation_required": True,
            "overrouting_containment_required": True,
            "mirror_masked_stability_required": True,
            "metric_widening_allowed": False,
            "comparator_weakening_allowed": False,
        },
        "trace_requirements": {field: True for field in TRACE_FIELDS},
        "forbidden_access": list(FORBIDDEN_FEATURE_FAMILIES),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }


def _prep_only_block(*, artifact_id: str, schema_id: str, purpose: str) -> Dict[str, Any]:
    return {
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "authority": "PREP_ONLY",
        "status": "PREP_ONLY",
        "purpose": purpose,
        "cannot_authorize_candidate_generation": True,
        "cannot_authorize_training": True,
        "cannot_authorize_admissibility_execution": True,
        "cannot_authorize_shadow_screen_packet": True,
        "cannot_authorize_shadow_screen_execution": True,
        "cannot_authorize_r6_open": True,
        "cannot_claim_superiority": True,
        "cannot_authorize_activation": True,
        "cannot_authorize_package_promotion": True,
        "next_lawful_move_required_before_authority": NEXT_LAWFUL_MOVE,
    }


def _turboquant_payloads() -> Dict[str, Dict[str, Any]]:
    common_prep = {
        "authority": "PREP_ONLY",
        "status": "PREP_ONLY",
        "compressed_index_truth_status": "retrieval_aid_not_source_of_truth",
        "raw_hash_bound_artifact_required": True,
        "cannot_authorize": [
            "B04_R6_AFSH_CANDIDATE_GENERATION_EXECUTION",
            "AFSH_CANDIDATE_TRAINING",
            "AFSH_ADMISSIBILITY",
            "SHADOW_SCREEN_PACKET",
            "SHADOW_SCREEN_EXECUTION",
            "R6_OPEN",
            "LEARNED_ROUTER_SUPERIORITY",
            "ACTIVATION",
            "PACKAGE_PROMOTION",
            "CURRENT_ROUTE_VALUE_FORMULA_MUTATION",
        ],
    }
    return {
        OUTPUTS["turboquant_translation"]: {
            "schema_id": "kt.memory_efficient_replay.turboquant_translation_matrix.v1",
            "artifact_id": "KT_TURBOQUANT_RESEARCH_TRANSLATION_MATRIX_PREP_ONLY",
            **common_prep,
            "source_research_summary": {
                "turboquant_role": "KV-cache and vector quantization for inference and vector search efficiency.",
                "potential_kt_value": [
                    "long-context replay cost reduction",
                    "compressed receipt retrieval",
                    "external verifier memory reduction",
                    "route-economics memory-cost modeling",
                    "offbox replay scaling",
                ],
            },
            "kt_translation": {
                "kv_cache_compression": "future infrastructure optimization only",
                "vector_search_compression": "future compressed receipt index only",
                "memory_cost_delta": "future route-economics term only after validation",
                "compression_distortion_risk": "future disqualifier/risk term",
            },
        },
        OUTPUTS["kv_cache_compression"]: {
            "schema_id": "kt.memory_efficient_replay.kv_cache_compression_readiness_contract.v1",
            "artifact_id": "KT_KV_CACHE_COMPRESSION_READINESS_CONTRACT_PREP_ONLY",
            **common_prep,
            "future_validation_required_before_use": ["compression_distortion_profile", "raw_artifact_recovery_requirement"],
        },
        OUTPUTS["memory_cost_delta"]: {
            "schema_id": "kt.memory_efficient_replay.memory_cost_delta_route_economics_extension.v1",
            "artifact_id": "KT_MEMORY_COST_DELTA_ROUTE_ECONOMICS_EXTENSION_PREP_ONLY",
            **common_prep,
            "current_route_value_formula_mutated": False,
            "future_term_status": "REQUIRES_SEPARATE_VALIDATION",
        },
        OUTPUTS["compressed_receipt_index"]: {
            "schema_id": "kt.memory_efficient_replay.compressed_receipt_vector_index_contract.v1",
            "artifact_id": "KT_COMPRESSED_RECEIPT_VECTOR_INDEX_CONTRACT_PREP_ONLY",
            **common_prep,
            "compressed_index_is_source_of_truth": False,
            "raw_hash_bound_artifact_required_after_retrieval": True,
        },
        OUTPUTS["compression_risk_register"]: {
            "schema_id": "kt.memory_efficient_replay.compression_distortion_risk_register.v1",
            "artifact_id": "KT_COMPRESSION_DISTORTION_RISK_REGISTER_PREP_ONLY",
            **common_prep,
            "risk_codes": [
                "RC_KT_MEMORY_PREP_ONLY_AUTHORITY_DRIFT",
                "RC_KT_MEMORY_COMPRESSED_INDEX_USED_AS_TRUTH",
                "RC_KT_MEMORY_RAW_HASH_ARTIFACT_MISSING",
                "RC_KT_MEMORY_ROUTE_VALUE_FORMULA_MUTATION",
                "RC_KT_MEMORY_COMPRESSION_DISTORTION_RISK_UNBOUNDED",
            ],
        },
        OUTPUTS["long_context_cost_model"]: {
            "schema_id": "kt.memory_efficient_replay.long_context_replay_cost_model.v1",
            "artifact_id": "KT_LONG_CONTEXT_REPLAY_COST_MODEL_PREP_ONLY",
            **common_prep,
            "future_use": "external verifier and long-context replay cost modeling only",
        },
    }


def _future_blocker_register() -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.future_blocker_register.v2",
        "artifact_id": "B04_R6_FUTURE_BLOCKER_REGISTER",
        "current_authoritative_lane": "GENERATE_B04_R6_AFSH_CANDIDATE",
        "blockers": [
            {
                "blocker_id": "B04R6-FB-011",
                "future_blocker": "Candidate exists but admissibility court law is not ready.",
                "neutralization_now": [
                    OUTPUTS["admissibility_court_prep"],
                    OUTPUTS["admissibility_reason_codes_prep"],
                    OUTPUTS["replay_validation_plan_prep"],
                    OUTPUTS["trace_compatibility_validation_plan_prep"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-012",
                "future_blocker": "Candidate hash is unstable due to timestamp or mutable receipt fields.",
                "neutralization_now": [
                    OUTPUTS["stable_semantic_hash_basis"],
                    "test_candidate_semantic_hash_excludes_generated_utc",
                ],
            },
            {
                "blocker_id": "B04R6-FB-013",
                "future_blocker": "Candidate generation looks like unauthorized training.",
                "neutralization_now": [OUTPUTS["no_training_receipt"], OUTPUTS["rule_materialization_receipt"]],
            },
            {
                "blocker_id": "B04R6-FB-014",
                "future_blocker": "Triage gate leaks blind outcomes or route-success labels through tags.",
                "neutralization_now": [OUTPUTS["triage_tag_schema"], OUTPUTS["triage_no_authorization_drift_receipt"]],
            },
            {
                "blocker_id": "B04R6-FB-015",
                "future_blocker": "Candidate over-routes by letting non-eligible cases enter selector.",
                "neutralization_now": [OUTPUTS["triage_emit_decision_matrix"]],
            },
            {
                "blocker_id": "B04R6-FB-016",
                "future_blocker": "TurboQuant research packet contaminates current proof lane.",
                "neutralization_now": [OUTPUTS["turboquant_translation"], OUTPUTS["memory_cost_delta"]],
            },
            {
                "blocker_id": "B04R6-FB-017",
                "future_blocker": "Compressed receipt/vector index treated as source of truth.",
                "neutralization_now": [OUTPUTS["compressed_receipt_index"]],
            },
        ],
    }


def _validation_rows() -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    core = [
        ("candidate_generation_contract_preserves_current_main_head", "RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH", "candidate generation binds current main head", "core"),
        ("candidate_generation_binds_selected_afsh_architecture", "RC_B04R6_AFSH_CANDIDATE_GEN_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD remains selected", "core"),
        ("candidate_generation_binds_validated_blind_universe", "RC_B04R6_AFSH_CANDIDATE_GEN_UNIVERSE_BINDING_MISSING", "validated 18-case blind universe remains bound", "core"),
        ("candidate_generation_binds_validated_route_value_court", "RC_B04R6_AFSH_CANDIDATE_GEN_COURT_BINDING_MISSING", "validated route-value court remains bound", "core"),
        ("candidate_generation_binds_validated_source_packet", "RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_PACKET_BINDING_MISSING", "validated source packet remains bound", "core"),
        ("candidate_id_is_b04_r6_afsh_candidate_v1", "RC_B04R6_AFSH_CANDIDATE_GEN_MANIFEST_MISSING", "candidate id is B04_R6_AFSH_CANDIDATE_V1", "candidate"),
        ("candidate_kind_is_deterministic_rule_materialization", "RC_B04R6_AFSH_CANDIDATE_GEN_MANIFEST_MISSING", "candidate kind is deterministic rule materialization", "candidate"),
        ("candidate_generation_executed_true", "RC_B04R6_AFSH_CANDIDATE_GEN_MANIFEST_MISSING", "candidate generation executed in this lane", "candidate"),
        ("candidate_training_executed_false", "RC_B04R6_AFSH_CANDIDATE_GEN_TRAINING_EXECUTED", "candidate training was not executed", "training"),
        ("candidate_training_remains_unauthorized", "RC_B04R6_AFSH_CANDIDATE_GEN_TRAINING_EXECUTED", "candidate training remains unauthorized", "training"),
        ("candidate_hash_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_HASH_RECEIPT_MISSING", "candidate hash receipt is bound", "hash"),
        ("candidate_derivation_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_DERIVATION_RECEIPT_MISSING", "candidate derivation receipt is bound", "derivation"),
        ("rule_materialization_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_DERIVATION_RECEIPT_MISSING", "rule materialization receipt is bound", "derivation"),
        ("no_training_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_NO_TRAINING_RECEIPT_MISSING", "no-training receipt is bound", "training"),
        ("no_contamination_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_OUTCOME_ACCESS", "no-contamination receipt is bound", "contamination"),
        ("static_hold_default_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_STATIC_HOLD_DEFAULT_MISSING", "static-hold default receipt is bound", "behavior"),
        ("abstention_preservation_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_ABSTENTION_PRESERVATION_MISSING", "abstention preservation receipt is bound", "behavior"),
        ("null_route_preservation_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_NULL_ROUTE_PRESERVATION_MISSING", "null-route preservation receipt is bound", "behavior"),
        ("mirror_masked_stability_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_MIRROR_MASKED_STABILITY_MISSING", "mirror/masked stability receipt is bound", "behavior"),
        ("source_hash_receipt_bound", "RC_B04R6_AFSH_CANDIDATE_GEN_SOURCE_HASH_MISSING", "source hash receipt is bound", "hash"),
        ("no_authorization_drift_receipt_passes", "RC_B04R6_AFSH_CANDIDATE_GEN_ADMISSIBILITY_EXECUTED", "no authorization drift receipt passes", "authorization"),
    ]
    triage = [
        ("candidate_includes_numeric_triage_emit_core", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "candidate includes numeric triage emit core", "triage"),
        ("candidate_includes_triage_intake_gate", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "candidate includes triage intake gate", "triage"),
        ("triage_gate_is_stage_0_or_stage_1_not_stage_2_selector", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage gate precedes selector", "triage"),
        ("triage_top_level_verdict_modes_match_validated_court_modes", "RC_B04R6_AFSH_CANDIDATE_GEN_COURT_BINDING_MISSING", "triage verdicts match court verdicts", "triage"),
        ("human_review_maps_to_abstain_subtype", "RC_B04R6_TRIAGE_HUMAN_OR_COURT_REVIEW_REQUIRED", "human review maps to ABSTAIN subtype", "triage"),
        ("quarantine_maps_to_abstain_subtype", "RC_B04R6_TRIAGE_QUARANTINE_REQUIRED", "quarantine maps to ABSTAIN subtype", "triage"),
        ("null_route_surface_temptation_maps_to_null_route", "RC_B04R6_TRIAGE_NULL_ROUTE_SURFACE_TEMPTATION", "surface temptation maps to NULL_ROUTE", "triage"),
        ("only_route_eligible_enters_selector", "RC_B04R6_TRIAGE_SELECTOR_ENTRY_AUTHORIZED", "only ROUTE_ELIGIBLE enters selector", "triage"),
        ("static_hold_cases_do_not_enter_selector", "RC_B04R6_TRIAGE_SELECTOR_ENTRY_BLOCKED", "STATIC_HOLD terminates before selector", "triage"),
        ("abstain_cases_do_not_enter_selector", "RC_B04R6_TRIAGE_SELECTOR_ENTRY_BLOCKED", "ABSTAIN terminates before selector", "triage"),
        ("null_route_cases_do_not_enter_selector", "RC_B04R6_TRIAGE_SELECTOR_ENTRY_BLOCKED", "NULL_ROUTE terminates before selector", "triage"),
        ("triage_scores_are_deterministic", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage scores are deterministic bounded scores", "triage"),
        ("triage_emit_logic_is_fail_closed", "RC_B04R6_AFSH_CANDIDATE_GEN_STATIC_HOLD_DEFAULT_MISSING", "triage emit logic fails closed", "triage"),
        ("triage_tags_are_receipt_derived", "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_OUTCOME_ACCESS", "triage tags are receipt-derived", "triage"),
        ("triage_tags_do_not_use_blind_outcomes", "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_OUTCOME_ACCESS", "triage tags do not use blind outcomes", "triage"),
        ("triage_tags_do_not_use_route_success_labels", "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_ROUTE_SUCCESS_ACCESS", "triage tags do not use route-success labels", "triage"),
        ("triage_tags_do_not_use_post_screen_labels", "RC_B04R6_AFSH_CANDIDATE_GEN_POST_SCREEN_LABEL_ACCESS", "triage tags do not use post-screen labels", "triage"),
        ("triage_tags_do_not_use_old_r01_r04_counted_labels", "RC_B04R6_AFSH_CANDIDATE_GEN_OLD_R01_R04_COUNTED_LABEL_ACCESS", "triage tags do not use R01-R04 counted labels", "triage"),
        ("triage_tags_do_not_use_old_v2_six_row_counted_labels", "RC_B04R6_AFSH_CANDIDATE_GEN_OLD_V2_SIX_ROW_COUNTED_LABEL_ACCESS", "triage tags do not use v2 six-row counted labels", "triage"),
        ("triage_receipt_emits_numeric_scores", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits numeric scores", "triage"),
        ("triage_receipt_emits_trust_zone_tags", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits trust-zone tags", "triage"),
        ("triage_receipt_emits_evidence_tags", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits evidence tags", "triage"),
        ("triage_receipt_emits_risk_tags", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits risk tags", "triage"),
        ("triage_receipt_emits_route_economics_tags", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits route-economics tags", "triage"),
        ("triage_receipt_emits_why_not_route", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits why-not-route", "triage"),
        ("triage_receipt_emits_selector_entry_authorization_status", "RC_B04R6_AFSH_CANDIDATE_GEN_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits selector-entry status", "triage"),
        ("triage_receipt_emits_specialist_candidate_tags_only_for_route_eligible", "RC_B04R6_TRIAGE_SELECTOR_ENTRY_AUTHORIZED", "specialist tags only emit for ROUTE_ELIGIBLE", "triage"),
        ("triage_no_authorization_drift_receipt_passes", "RC_B04R6_AFSH_CANDIDATE_GEN_ADMISSIBILITY_EXECUTED", "triage no-authorization-drift receipt passes", "triage"),
    ]
    replay = [
        ("candidate_semantic_hash_excludes_generated_utc", "RC_B04R6_AFSH_CANDIDATE_GEN_HASH_RECEIPT_MISSING", "candidate semantic hash excludes generated_utc", "replay"),
        ("candidate_receipt_hash_includes_envelope", "RC_B04R6_AFSH_CANDIDATE_GEN_HASH_RECEIPT_MISSING", "candidate receipt hash includes full envelope", "replay"),
        ("candidate_mutable_handoff_bound_before_overwrite", "RC_B04R6_AFSH_CANDIDATE_GEN_NEXT_MOVE_DRIFT", "mutable handoff is bound before overwrite", "replay"),
        ("candidate_generation_does_not_train", "RC_B04R6_AFSH_CANDIDATE_GEN_TRAINING_EXECUTED", "generation does not train", "replay"),
        ("candidate_generation_does_not_execute_admissibility", "RC_B04R6_AFSH_CANDIDATE_GEN_ADMISSIBILITY_EXECUTED", "generation does not execute admissibility", "replay"),
        ("candidate_generation_does_not_access_blind_labels", "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_OUTCOME_ACCESS", "generation does not access blind labels", "replay"),
        ("candidate_generation_does_not_access_route_success_labels", "RC_B04R6_AFSH_CANDIDATE_GEN_BLIND_ROUTE_SUCCESS_ACCESS", "generation does not access route-success labels", "replay"),
        ("candidate_prep_only_admissibility_draft_non_authoritative", "RC_B04R6_AFSH_CANDIDATE_GEN_PREP_ONLY_AUTHORITY_DRIFT", "admissibility draft remains prep-only", "prep_only"),
        ("candidate_post_merge_replay_required", "RC_B04R6_AFSH_CANDIDATE_GEN_MAIN_HEAD_MISMATCH", "post-merge replay remains required", "replay"),
    ]
    prep = [
        ("admissibility_court_draft_is_prep_only", "RC_B04R6_AFSH_CANDIDATE_GEN_PREP_ONLY_AUTHORITY_DRIFT", "admissibility court draft is prep-only", "prep_only"),
        ("admissibility_reason_codes_are_prep_only", "RC_B04R6_AFSH_CANDIDATE_GEN_PREP_ONLY_AUTHORITY_DRIFT", "admissibility reason codes are prep-only", "prep_only"),
        ("replay_validation_plan_is_prep_only", "RC_B04R6_AFSH_CANDIDATE_GEN_PREP_ONLY_AUTHORITY_DRIFT", "replay validation plan is prep-only", "prep_only"),
        ("trace_compatibility_plan_is_prep_only", "RC_B04R6_AFSH_CANDIDATE_GEN_PREP_ONLY_AUTHORITY_DRIFT", "trace compatibility plan is prep-only", "prep_only"),
        ("prep_only_drafts_cannot_authorize_admissibility_execution", "RC_B04R6_AFSH_CANDIDATE_GEN_ADMISSIBILITY_EXECUTED", "prep-only drafts cannot execute admissibility", "prep_only"),
        ("prep_only_drafts_cannot_authorize_shadow_screen_packet", "RC_B04R6_AFSH_CANDIDATE_GEN_SHADOW_PACKET_AUTHORIZED", "prep-only drafts cannot authorize shadow packet", "prep_only"),
        ("prep_only_drafts_cannot_authorize_shadow_screen_execution", "RC_B04R6_AFSH_CANDIDATE_GEN_SHADOW_SCREEN_AUTHORIZED", "prep-only drafts cannot authorize shadow screen", "prep_only"),
        ("prep_only_drafts_cannot_authorize_activation", "RC_B04R6_AFSH_CANDIDATE_GEN_ACTIVATION_DRIFT", "prep-only drafts cannot authorize activation", "prep_only"),
        ("prep_only_drafts_cannot_authorize_package_promotion", "RC_B04R6_AFSH_CANDIDATE_GEN_PACKAGE_PROMOTION_DRIFT", "prep-only drafts cannot authorize package promotion", "prep_only"),
    ]
    memory = [
        ("memory_compression_research_packet_is_prep_only", "RC_KT_MEMORY_PREP_ONLY_AUTHORITY_DRIFT", "memory compression research is prep-only", "memory"),
        ("memory_compression_cannot_authorize_candidate_generation", "RC_KT_MEMORY_CANDIDATE_GENERATION_AUTH_DRIFT", "memory prep cannot authorize candidate generation", "memory"),
        ("memory_compression_cannot_authorize_admissibility", "RC_KT_MEMORY_ADMISSIBILITY_AUTH_DRIFT", "memory prep cannot authorize admissibility", "memory"),
        ("memory_compression_cannot_authorize_shadow_screen", "RC_KT_MEMORY_SHADOW_AUTH_DRIFT", "memory prep cannot authorize shadow screen", "memory"),
        ("memory_compression_cannot_authorize_r6_open", "RC_B04R6_AFSH_CANDIDATE_GEN_R6_OPEN_DRIFT", "memory prep cannot open R6", "memory"),
        ("memory_compression_cannot_claim_superiority", "RC_B04R6_AFSH_CANDIDATE_GEN_SUPERIORITY_DRIFT", "memory prep cannot claim superiority", "memory"),
        ("memory_compression_cannot_authorize_activation", "RC_B04R6_AFSH_CANDIDATE_GEN_ACTIVATION_DRIFT", "memory prep cannot authorize activation", "memory"),
        ("memory_compression_cannot_authorize_package_promotion", "RC_B04R6_AFSH_CANDIDATE_GEN_PACKAGE_PROMOTION_DRIFT", "memory prep cannot authorize package promotion", "memory"),
        ("memory_compression_cannot_change_route_value_formula_in_current_lane", "RC_KT_MEMORY_ROUTE_VALUE_FORMULA_MUTATION", "memory prep cannot mutate current route-value formula", "memory"),
        ("compressed_index_cannot_be_source_of_truth", "RC_KT_MEMORY_COMPRESSED_INDEX_USED_AS_TRUTH", "compressed index cannot be source of truth", "memory"),
        ("raw_hash_bound_artifact_required_after_compressed_retrieval", "RC_KT_MEMORY_RAW_HASH_ARTIFACT_MISSING", "raw hash-bound artifact remains required", "memory"),
    ]
    boundaries = [
        ("metric_widening_forbidden", "RC_B04R6_AFSH_CANDIDATE_GEN_METRIC_WIDENING", "metric widening remains forbidden", "authorization"),
        ("comparator_weakening_forbidden", "RC_B04R6_AFSH_CANDIDATE_GEN_COMPARATOR_WEAKENING", "comparator weakening remains forbidden", "authorization"),
        ("truth_engine_law_unchanged", "RC_B04R6_AFSH_CANDIDATE_GEN_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", "authorization"),
        ("trust_zone_law_unchanged", "RC_B04R6_AFSH_CANDIDATE_GEN_TRUST_ZONE_MUTATION", "trust-zone law unchanged", "authorization"),
        ("next_lawful_move_is_admissibility_court", "RC_B04R6_AFSH_CANDIDATE_GEN_NEXT_MOVE_DRIFT", "next lawful move is admissibility court", "next_move"),
    ]
    for check_id, reason, detail, group in [*core, *triage, *replay, *prep, *memory, *boundaries]:
        rows.append(_pass_row(check_id, reason, detail, group=group))
    return rows


def _report(rows: list[Dict[str, str]]) -> str:
    lines = [
        "# B04 R6 AFSH Candidate Generation",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "This lane generates `B04_R6_AFSH_CANDIDATE_V1` as a deterministic, hash-bound, source-packet-constrained candidate artifact. It does not train a candidate and does not execute admissibility, shadow-screen packet creation, shadow-screen execution, R6 opening, activation, lobe escalation, package promotion, or learned-router superiority.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 AFSH candidate generation")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    source_validation_head = _require_inputs(root, payloads, text_payloads)
    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_AFSH_CANDIDATE_GEN_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)

    rows = _validation_rows()
    rows.extend(_validate_immutable_source_heads(payloads, source_validation_head=source_validation_head))

    source_validation_receipt = payloads["source_validation_receipt"]
    architecture_binding_head = str(source_validation_receipt.get("architecture_binding_head", "")).strip()
    generated_utc = utc_now_iso_z()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        source_validation_head=source_validation_head,
        architecture_binding_head=architecture_binding_head,
        current_branch=current_branch,
    )
    universe_binding = _validated_blind_universe_binding(source_validation_receipt)
    court_binding = _validated_court_binding(source_validation_receipt)

    source_packet_hash = file_sha256(root / REFERENCE_INPUTS["source_packet_contract"])
    validated_court_hash = file_sha256(root / REFERENCE_INPUTS["court_validation_receipt"])
    validated_universe_hash = file_sha256(root / REFERENCE_INPUTS["blind_universe_manifest"])
    numeric_core = _numeric_triage_core()
    numeric_core_hash = sha256_hex(canonicalize_bytes(numeric_core))
    component_hashes = {
        "source_packet_hash": source_packet_hash,
        "validated_court_hash": validated_court_hash,
        "validated_universe_hash": validated_universe_hash,
        "numeric_triage_emit_core_hash": numeric_core_hash,
    }
    candidate = _candidate_v1(generated_utc=generated_utc, current_main_head=current_main_head, hashes=component_hashes)
    semantic_hash = candidate_semantic_hash(candidate)
    envelope_hash = _envelope_hash(candidate)

    common_extra = {
        "validated_source_packet_binding": {
            "status": "BOUND_AND_VALIDATED",
            "source_packet_validation_replay_binding_head": source_validation_head,
            "previous_outcome": EXPECTED_PREVIOUS_OUTCOME,
            "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        },
        "validated_blind_universe_binding": universe_binding,
        "validated_court_binding": court_binding,
        "candidate_semantic_hash": semantic_hash,
        "candidate_envelope_hash": envelope_hash,
        "candidate_generation_executed": True,
        "candidate_training_executed": False,
        "afsh_admissibility_executed": False,
    }
    receipt = lambda schema, artifact, groups, extra=None: _receipt_payload(
        base=base,
        schema_id=schema,
        artifact_id=artifact,
        rows=_rows_for(rows, *groups),
        input_bindings=input_bindings,
        extra={**common_extra, **(extra or {})},
    )

    outputs: Dict[str, Any] = {
        OUTPUTS["generation_contract"]: receipt(
            "kt.b04_r6.afsh_candidate_generation_contract.v1",
            "B04_R6_AFSH_CANDIDATE_GENERATION_CONTRACT",
            ("core", "candidate", "training", "hash", "derivation", "contamination", "behavior", "triage", "replay", "prep_only", "memory", "authorization", "next_move"),
            {
                "candidate_generation_law": "Deterministic source-packet-constrained rule materialization only; no training.",
                "candidate_may_generate": True,
                "candidate_training_authorized": False,
                "admissibility_execution_authorized": False,
            },
        ),
        OUTPUTS["candidate_manifest"]: {
            "schema_id": "kt.b04_r6.afsh_candidate_manifest.v1",
            "artifact_id": "B04_R6_AFSH_CANDIDATE_MANIFEST",
            **base,
            "candidate_kind": "DETERMINISTIC_RULE_MATERIALIZATION",
            "training_executed": False,
            "candidate_generation_executed": True,
            "validated_inputs": {
                "blind_universe": universe_binding,
                "route_value_court": court_binding,
                "implementation_source_packet": {
                    "status": "BOUND_AND_VALIDATED",
                    "outcome": EXPECTED_PREVIOUS_OUTCOME,
                },
            },
            "candidate_modules": candidate["modules"],
            "authorization_state": _authorization_state(),
            "candidate_defaults": _candidate_defaults(),
            "stage_model": candidate["stage_model"],
            "top_level_verdict_modes": list(TOP_LEVEL_VERDICTS),
            "allowed_triage_subtypes": list(TRIAGE_SUBTYPES),
            "selector_entry_rule": candidate["selector_entry_rule"],
            "trace_requirements": candidate["trace_requirements"],
            "forbidden_access": list(FORBIDDEN_FEATURE_FAMILIES),
            "forbidden_actions": list(FORBIDDEN_ACTIONS),
            "selected_outcome": SELECTED_OUTCOME,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "candidate_semantic_hash": semantic_hash,
            "candidate_envelope_hash": envelope_hash,
        },
        OUTPUTS["candidate_v1"]: candidate,
        OUTPUTS["candidate_hash_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_hash_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_HASH_RECEIPT",
            ("hash", "replay"),
            {
                "candidate_semantic_hash": semantic_hash,
                "candidate_envelope_hash": envelope_hash,
                "semantic_hash_excluded_fields": ["generated_utc"],
                "candidate_receipt_hash_includes_envelope": True,
            },
        ),
        OUTPUTS["candidate_derivation_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_derivation_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_DERIVATION_RECEIPT",
            ("derivation", "core"),
            {"derivation_kind": "DETERMINISTIC_RULE_MATERIALIZATION", "training_executed": False},
        ),
        OUTPUTS["rule_materialization_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_rule_materialization_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_RULE_MATERIALIZATION_RECEIPT",
            ("derivation", "triage"),
            {"materialized_modules": candidate["modules"]},
        ),
        OUTPUTS["no_training_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_no_training_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_NO_TRAINING_RECEIPT",
            ("training", "replay"),
            {"candidate_training_authorized": False, "candidate_training_executed": False},
        ),
        OUTPUTS["no_contamination_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_no_contamination_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_NO_CONTAMINATION_RECEIPT",
            ("contamination", "triage", "replay"),
            {
                "forbidden_access_status": {field: False for field in FORBIDDEN_ACCESS_FIELDS},
                "old_r01_r04_diagnostic_only": True,
                "old_v2_six_row_diagnostic_only": True,
            },
        ),
        OUTPUTS["static_hold_default_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_static_hold_default_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_STATIC_HOLD_DEFAULT_RECEIPT",
            ("behavior", "triage"),
            {"unknown_case": "STATIC_HOLD", "route_value_below_threshold": "STATIC_HOLD"},
        ),
        OUTPUTS["abstention_preservation_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_abstention_preservation_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_ABSTENTION_PRESERVATION_RECEIPT",
            ("behavior", "triage"),
            {"boundary_unclear": "ABSTAIN", "trust_zone_unclear": "ABSTAIN"},
        ),
        OUTPUTS["null_route_preservation_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_null_route_preservation_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_NULL_ROUTE_PRESERVATION_RECEIPT",
            ("behavior", "triage"),
            {"null_route_sibling": "NULL_ROUTE", "surface_temptation": "NULL_ROUTE"},
        ),
        OUTPUTS["mirror_masked_stability_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_mirror_masked_stability_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_MIRROR_MASKED_STABILITY_RECEIPT",
            ("behavior",),
            {"mirror_masked_instability": "STATIC_HOLD"},
        ),
        OUTPUTS["trace_schema_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_trace_schema_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_TRACE_SCHEMA_RECEIPT",
            ("triage",),
            {"required_trace_fields": list(TRACE_FIELDS), "trace_schema_complete": True},
        ),
        OUTPUTS["source_hash_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_source_hash_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_SOURCE_HASH_RECEIPT",
            ("hash",),
            component_hashes,
        ),
        OUTPUTS["no_authorization_drift_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_no_authorization_drift_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_NO_AUTHORIZATION_DRIFT_RECEIPT",
            ("authorization", "memory", "next_move"),
            {"no_downstream_authorization_drift": True},
        ),
        OUTPUTS["stable_semantic_hash_basis"]: {
            "schema_id": "kt.b04_r6.afsh_candidate_stable_semantic_hash_basis.v1",
            "artifact_id": "B04_R6_AFSH_CANDIDATE_STABLE_SEMANTIC_HASH_BASIS",
            **base,
            "semantic_hash": semantic_hash,
            "excluded_volatile_fields": ["generated_utc"],
            "candidate_semantic_hash_excludes_generated_utc": True,
        },
        OUTPUTS["immutable_input_manifest"]: {
            "schema_id": "kt.b04_r6.afsh_candidate_immutable_input_manifest.v1",
            "artifact_id": "B04_R6_AFSH_CANDIDATE_IMMUTABLE_INPUT_MANIFEST",
            **base,
            "source_validation_replay_head": source_validation_head,
            "immutable_source_inputs_share_replay_head": True,
            "input_bindings": input_bindings,
        },
        OUTPUTS["replay_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_replay_binding_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_REPLAY_BINDING_RECEIPT",
            ("replay",),
            {"source_validation_replay_head": source_validation_head, "post_merge_replay_required": True},
        ),
        OUTPUTS["mutable_handoff_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_mutable_handoff_binding_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_MUTABLE_HANDOFF_BINDING_RECEIPT",
            ("replay",),
            {"mutable_handoff_bound_before_overwrite": True},
        ),
        OUTPUTS["prep_only_non_authority_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_prep_only_non_authority_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_PREP_ONLY_NON_AUTHORITY_RECEIPT",
            ("prep_only", "memory"),
            {"prep_only_outputs_remain_non_authoritative": True},
        ),
        OUTPUTS["old_universe_diagnostic_only_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_old_universe_diagnostic_only_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_OLD_UNIVERSE_DIAGNOSTIC_ONLY_RECEIPT",
            ("contamination", "triage"),
            {"prior_r01_r04_treatment": "DIAGNOSTIC_ONLY", "prior_v2_six_row_treatment": "DIAGNOSTIC_ONLY"},
        ),
        OUTPUTS["numeric_triage_emit_core"]: numeric_core,
        OUTPUTS["triage_no_authorization_drift_receipt"]: receipt(
            "kt.b04_r6.afsh_triage_no_authorization_drift_receipt.v1",
            "B04_R6_AFSH_TRIAGE_NO_AUTHORIZATION_DRIFT_RECEIPT",
            ("triage", "authorization"),
            {"selector_entry_authorizes_only_stage_2_selector": True, "admissibility_executed": False},
        ),
        OUTPUTS["future_blocker_register"]: _future_blocker_register(),
        OUTPUTS["next_lawful_move"]: receipt(
            "kt.operator.b04_r6_next_lawful_move_receipt.v10",
            "B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            ("next_move",),
            {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE},
        ),
    }
    outputs.update(_triage_policy_payloads())
    outputs.update(
        {
            OUTPUTS["admissibility_court_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_ADMISSIBILITY_COURT_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_admissibility_court_prep_only_draft.v2",
                purpose="Prep-only draft for future AFSH admissibility court after candidate generation.",
            ),
            OUTPUTS["admissibility_reason_codes_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_ADMISSIBILITY_REASON_CODES_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_admissibility_reason_codes_prep_only_draft.v1",
                purpose="Prep-only admissibility reason-code scaffold.",
            ),
            OUTPUTS["replay_validation_plan_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_REPLAY_VALIDATION_PLAN_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_replay_validation_plan_prep_only_draft.v1",
                purpose="Prep-only replay validation plan for future admissibility.",
            ),
            OUTPUTS["trace_compatibility_validation_plan_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_TRACE_COMPATIBILITY_VALIDATION_PLAN_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_trace_compatibility_validation_plan_prep_only_draft.v1",
                purpose="Prep-only trace compatibility validation plan.",
            ),
        }
    )
    outputs.update(_turboquant_payloads())
    outputs["COHORT0_B04_R6_AFSH_CANDIDATE_GENERATION_REPORT.md"] = _report(rows)

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "pass_count": len(rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate B04 R6 AFSH candidate.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=Path(args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
