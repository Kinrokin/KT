from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-static-hold-abstention-route-economics-court-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_VALIDATION"
PREVIOUS_LANE = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT"

EXPECTED_PREVIOUS_OUTCOME = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_BOUND__COURT_VALIDATION_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "VALIDATE_B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT"
OUTCOME_VALIDATED = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_VALIDATED__AFSH_IMPLEMENTATION_SOURCE_PACKET_NEXT"
OUTCOME_DEFERRED = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET"

SELECTED_ARCHITECTURE_ID = "AFSH-2S-GUARD"
SELECTED_ARCHITECTURE_NAME = "Abstention-First Static-Hold Two-Stage Guarded Router"
CASE_PREFIX = "B04R6-AFSH-BU1-"
EXPECTED_CASE_COUNT = 18

ROUTE_VALUE_POSITIVE_TERMS = (
    "expected_quality_delta",
    "expected_governance_benefit",
    "expected_proof_burden_reduction",
    "expected_error_surface_reduction",
)
ROUTE_VALUE_PENALTY_TERMS = (
    "wrong_route_cost",
    "wrong_static_hold_cost_if_applicable",
    "overrouting_penalty",
    "abstention_violation_penalty",
    "null_route_violation_penalty",
    "mirror_masked_instability_penalty",
    "trace_complexity_penalty",
    "trust_zone_risk_penalty",
)
ROUTE_VALUE_TERMS = ROUTE_VALUE_POSITIVE_TERMS + ROUTE_VALUE_PENALTY_TERMS
ROUTE_ELIGIBILITY_GATES = (
    "route_value > frozen_route_threshold",
    "static_hold_dominance == false",
    "abstention_required == false",
    "null_route_required == false",
    "trust_zone_pass == true",
    "mirror_masked_stability == pass",
    "trace_requirements_satisfied == true",
    "comparator_not_weakened == true",
    "metric_not_widened == true",
    "no_authorization_drift == true",
)
ROUTE_ELIGIBLE_FORBIDDEN_AUTHORIZATIONS = (
    "AFSH source packet finalization",
    "AFSH candidate generation",
    "candidate training",
    "shadow-screen packet authorization",
    "shadow-screen execution",
    "learned-router superiority",
    "R6 opening",
    "activation review",
    "runtime cutover",
    "lobe escalation",
    "package promotion",
)

FORBIDDEN_CLAIMS = [
    "afsh_source_packet_authorized",
    "afsh_candidate_generation_authorized",
    "afsh_candidate_training_authorized",
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
    "afsh_source_packet_authorized",
    "afsh_candidate_generation_authorized",
    "afsh_candidate_training_authorized",
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

REASON_CODES = [
    "RC_B04R6_COURT_VAL_SCHEMA_MISSING",
    "RC_B04R6_COURT_VAL_CONTRACT_MISSING",
    "RC_B04R6_COURT_VAL_RECEIPT_MISSING",
    "RC_B04R6_COURT_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_COURT_VAL_REPLAY_BINDING_MISMATCH",
    "RC_B04R6_COURT_VAL_ARCHITECTURE_MISMATCH",
    "RC_B04R6_COURT_VAL_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_COURT_VAL_STATIC_HOLD_NOT_DEFAULT",
    "RC_B04R6_COURT_VAL_ABSTAIN_NOT_POSITIVE",
    "RC_B04R6_COURT_VAL_NULL_ROUTE_NOT_CONTROL",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_EXECUTING",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SOURCE_PACKET",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_GENERATION",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_TRAINING",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN_PACKET",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_R6_OPEN",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SUPERIORITY",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_ACTIVATION",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_CUTOVER",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_LOBE_ESCALATION",
    "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_PACKAGE_PROMOTION",
    "RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE",
    "RC_B04R6_COURT_VAL_WRONG_ROUTE_COST_MISSING",
    "RC_B04R6_COURT_VAL_WRONG_STATIC_HOLD_COST_MISSING",
    "RC_B04R6_COURT_VAL_PROOF_BURDEN_DELTA_MISSING",
    "RC_B04R6_COURT_VAL_THRESHOLD_NOT_FROZEN",
    "RC_B04R6_COURT_VAL_REASON_CODES_INCOMPLETE",
    "RC_B04R6_COURT_VAL_DISQUALIFIER_LEDGER_INCOMPLETE",
    "RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_COURT_VAL_METRIC_WIDENING",
    "RC_B04R6_COURT_VAL_COMPARATOR_WEAKENING",
    "RC_B04R6_COURT_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_COURT_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_COURT_VAL_OLD_UNIVERSE_PROOF_DRIFT",
    "RC_B04R6_COURT_VAL_NEXT_MOVE_DRIFT",
]

TERMINAL_DEFECTS = [
    "ROUTE_ELIGIBLE_AUTHORIZES_GENERATION",
    "ROUTE_ELIGIBLE_AUTHORIZES_SCREEN",
    "ROUTE_ELIGIBLE_AUTHORIZES_R6_OPEN",
    "ROUTE_ELIGIBLE_AUTHORIZES_SUPERIORITY",
    "METRIC_WIDENING",
    "COMPARATOR_WEAKENING",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "PREP_ONLY_AUTHORITY_DRIFT",
    "OLD_UNIVERSE_PROOF_DRIFT",
    "NEXT_MOVE_DRIFT",
]

INPUTS = {
    "court_contract": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_contract.json",
    "court_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_receipt.json",
    "static_hold_control": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_control_contract.json",
    "abstention_registry": "KT_PROD_CLEANROOM/reports/b04_r6_abstention_control_registry.json",
    "null_route_control": "KT_PROD_CLEANROOM/reports/b04_r6_null_route_control_contract.json",
    "route_economics": "KT_PROD_CLEANROOM/reports/b04_r6_route_economics_matrix.json",
    "wrong_route_cost": "KT_PROD_CLEANROOM/reports/b04_r6_wrong_route_cost_contract.json",
    "wrong_static_hold_cost": "KT_PROD_CLEANROOM/reports/b04_r6_wrong_static_hold_cost_contract.json",
    "proof_burden_delta": "KT_PROD_CLEANROOM/reports/b04_r6_proof_burden_delta_contract.json",
    "threshold_profile": "KT_PROD_CLEANROOM/reports/b04_r6_route_value_threshold_profile.json",
    "reason_codes": "KT_PROD_CLEANROOM/reports/b04_r6_court_reason_code_taxonomy.json",
    "disqualifier_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_court_disqualifier_ledger.json",
    "no_authorization_drift": "KT_PROD_CLEANROOM/reports/b04_r6_court_no_authorization_drift_receipt.json",
    "validation_plan": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_plan.json",
    "validation_reason_codes": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_reason_codes.json",
    "future_blocker_register": "KT_PROD_CLEANROOM/reports/b04_r6_future_blocker_register.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

TEXT_INPUTS = {
    "court_report": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_report.md",
    "validation_test_plan": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_abstention_route_economics_court_validation_test_plan.md",
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
    "validation_contract": "b04_r6_static_hold_abstention_route_economics_court_validation_contract.json",
    "validation_receipt": "b04_r6_static_hold_abstention_route_economics_court_validation_receipt.json",
    "validation_report": "b04_r6_static_hold_abstention_route_economics_court_validation_report.md",
    "static_hold_verdict": "b04_r6_static_hold_verdict_validation_receipt.json",
    "abstention_verdict": "b04_r6_abstention_verdict_validation_receipt.json",
    "null_route_verdict": "b04_r6_null_route_verdict_validation_receipt.json",
    "route_eligible_non_execution": "b04_r6_route_eligible_non_execution_validation_receipt.json",
    "route_value_formula": "b04_r6_route_value_formula_validation_receipt.json",
    "threshold_freeze": "b04_r6_route_value_threshold_freeze_validation_receipt.json",
    "wrong_route_cost": "b04_r6_wrong_route_cost_validation_receipt.json",
    "wrong_static_hold_cost": "b04_r6_wrong_static_hold_cost_validation_receipt.json",
    "proof_burden_delta": "b04_r6_proof_burden_delta_validation_receipt.json",
    "reason_code": "b04_r6_court_reason_code_validation_receipt.json",
    "disqualifier": "b04_r6_court_disqualifier_validation_receipt.json",
    "prep_only_non_authority": "b04_r6_court_prep_only_non_authority_validation_receipt.json",
    "no_authorization_drift": "b04_r6_court_no_authorization_drift_validation_receipt.json",
    "trust_zone": "b04_r6_court_trust_zone_validation_receipt.json",
    "replay_binding": "b04_r6_court_replay_binding_validation_receipt.json",
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


def _input_hashes(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**INPUTS, **TEXT_INPUTS, **PREP_INPUTS, **REFERENCE_INPUTS}.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
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
        _fail("RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} drifted: {key} must remain false")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str, prep_only_allowed: bool = False) -> None:
    allowed_statuses = {"PASS", "FROZEN_PACKET"}
    if prep_only_allowed:
        allowed_statuses.add("PREP_ONLY")
    if str(payload.get("status", "")).strip() not in allowed_statuses:
        _fail("RC_B04R6_COURT_VAL_SCHEMA_MISSING", f"{label} status must be in {sorted(allowed_statuses)}")
    if payload.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_COURT_VAL_ARCHITECTURE_MISMATCH", f"{label} must bind AFSH-2S-GUARD")
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        _fail("RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        _fail("RC_B04R6_COURT_VAL_TRUTH_ENGINE_MUTATION", f"{label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        _fail("RC_B04R6_COURT_VAL_TRUST_ZONE_MUTATION", f"{label} must preserve trust-zone law")


def _existing_validation_contract_supports_self_replay(root: Path) -> bool:
    path = root / "KT_PROD_CLEANROOM" / "reports" / OUTPUTS["validation_contract"]
    if not path.is_file():
        return False
    payload = common.load_json_required(root, path, label="existing court validation contract")
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
            _fail("RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must remain PREP_ONLY")
    for label, text in text_payloads.items():
        if not text.strip():
            _fail("RC_B04R6_COURT_VAL_SCHEMA_MISSING", f"{label} is empty")

    contract = payloads["court_contract"]
    receipt = payloads["court_receipt"]
    handoff = payloads["previous_next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COURT_VAL_NEXT_MOVE_DRIFT", "court contract outcome must be court-validation-next")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COURT_VAL_NEXT_MOVE_DRIFT", "court contract must authorize validation only")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COURT_VAL_RECEIPT_MISSING", "court receipt outcome must match court contract")
    if receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COURT_VAL_NEXT_MOVE_DRIFT", "court receipt must authorize validation only")

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
        _fail("RC_B04R6_COURT_VAL_NEXT_MOVE_DRIFT", "previous next lawful move receipt does not authorize court validation")


def _validated_universe_binding(contract: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(contract.get("validated_blind_universe_binding", {}))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_COURT_VAL_UNIVERSE_BINDING_MISSING", "validated blind universe is not bound")
    if binding.get("case_count") != EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_COURT_VAL_UNIVERSE_BINDING_MISSING", "validated blind universe must bind 18 cases")
    if binding.get("case_namespace") != f"{CASE_PREFIX}*":
        _fail("RC_B04R6_COURT_VAL_UNIVERSE_BINDING_MISSING", "validated blind universe namespace drifted")
    if binding.get("prior_r01_r04_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_COURT_VAL_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 must remain diagnostic-only")
    if binding.get("prior_v2_six_row_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_COURT_VAL_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row screen must remain diagnostic-only")
    return binding


def _require_forbidden_authorization(label: str, cannot_authorize: Sequence[str], value: str, code: str) -> None:
    if value not in cannot_authorize:
        _fail(code, f"{label} does not forbid {value}")


def _validate_previous_state(payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    contract = payloads["court_contract"]
    receipt = payloads["court_receipt"]
    binding = _validated_universe_binding(contract)
    if contract.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_COURT_VAL_CONTRACT_MISSING", "court contract authoritative lane mismatch")
    if receipt.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_COURT_VAL_RECEIPT_MISSING", "court receipt authoritative lane mismatch")
    if "STATIC_HOLD" not in text_payloads["court_report"]:
        _fail("RC_B04R6_COURT_VAL_CONTRACT_MISSING", "court report must discuss STATIC_HOLD")
    rows.append(_pass_row("court_contract_exists_and_parses", "RC_B04R6_COURT_VAL_CONTRACT_MISSING", "court contract exists and parses", group="replay"))
    rows.append(_pass_row("court_receipt_exists_and_parses", "RC_B04R6_COURT_VAL_RECEIPT_MISSING", "court receipt exists and parses", group="replay"))
    rows.append(_pass_row("court_report_exists", "RC_B04R6_COURT_VAL_SCHEMA_MISSING", "court report exists and is non-empty", group="replay"))
    rows.append(_pass_row("court_binds_selected_afsh_architecture", "RC_B04R6_COURT_VAL_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD remains bound", group="replay"))
    rows.append(_pass_row("court_binds_validated_blind_universe", "RC_B04R6_COURT_VAL_UNIVERSE_BINDING_MISSING", f"validated universe binding: {binding['case_namespace']}", group="replay"))
    rows.append(_pass_row("prior_r01_r04_remain_diagnostic_only", "RC_B04R6_COURT_VAL_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 remains diagnostic-only", group="replay"))
    rows.append(_pass_row("prior_v2_six_row_remains_diagnostic_only", "RC_B04R6_COURT_VAL_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row screen remains diagnostic-only", group="replay"))
    return rows


def _validate_replay_binding(
    payloads: Dict[str, Dict[str, Any]],
    *,
    current_main_head: str,
) -> tuple[list[Dict[str, str]], str]:
    court_head = str(payloads["court_contract"].get("current_git_head", "")).strip()
    if len(court_head) != 40:
        _fail("RC_B04R6_COURT_VAL_REPLAY_BINDING_MISMATCH", "court replay head must be a full git SHA")
    for role, payload in payloads.items():
        if payload.get("current_git_head") != court_head:
            _fail("RC_B04R6_COURT_VAL_REPLAY_BINDING_MISMATCH", f"{role} does not bind court replay head")
        if payload.get("current_main_head") != court_head:
            _fail("RC_B04R6_COURT_VAL_MAIN_HEAD_MISMATCH", f"{role} does not bind replay main head")
    if not current_main_head:
        _fail("RC_B04R6_COURT_VAL_MAIN_HEAD_MISMATCH", "current main head is missing")
    return [
        _pass_row("validation_contract_binds_current_main_head", "RC_B04R6_COURT_VAL_MAIN_HEAD_MISMATCH", "validation can bind current main head", group="replay"),
        _pass_row("validation_contract_binds_court_replay_head", "RC_B04R6_COURT_VAL_REPLAY_BINDING_MISMATCH", "all court artifacts share one replay head", group="replay"),
    ], court_head


def _validate_verdict_modes(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    contract = payloads["court_contract"]
    modes = dict(contract.get("verdict_modes", {}))
    required_modes = {"STATIC_HOLD", "ABSTAIN", "NULL_ROUTE", "ROUTE_ELIGIBLE"}
    if set(modes) != required_modes:
        _fail("RC_B04R6_COURT_VAL_SCHEMA_MISSING", "court must define exactly four verdict modes")
    if modes["STATIC_HOLD"].get("default") is not True or modes["STATIC_HOLD"].get("positive_verdict") is not True:
        _fail("RC_B04R6_COURT_VAL_STATIC_HOLD_NOT_DEFAULT", "STATIC_HOLD must be default positive verdict")
    if payloads["static_hold_control"].get("default_verdict") is not True:
        _fail("RC_B04R6_COURT_VAL_STATIC_HOLD_NOT_DEFAULT", "static-hold control must affirm default verdict")
    if modes["ABSTAIN"].get("positive_verdict") is not True:
        _fail("RC_B04R6_COURT_VAL_ABSTAIN_NOT_POSITIVE", "ABSTAIN must be positive success")
    if payloads["abstention_registry"].get("positive_success") is not True:
        _fail("RC_B04R6_COURT_VAL_ABSTAIN_NOT_POSITIVE", "abstention registry must affirm positive success")
    if modes["NULL_ROUTE"].get("anti_overrouting_control") is not True:
        _fail("RC_B04R6_COURT_VAL_NULL_ROUTE_NOT_CONTROL", "NULL_ROUTE must be anti-overrouting control")
    if payloads["null_route_control"].get("anti_overrouting_control") is not True:
        _fail("RC_B04R6_COURT_VAL_NULL_ROUTE_NOT_CONTROL", "null-route control must affirm anti-overrouting")
    route_eligible = modes["ROUTE_ELIGIBLE"]
    if route_eligible.get("non_executing_precondition_only") is not True or route_eligible.get("positive_verdict") is not False:
        _fail("RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_EXECUTING", "ROUTE_ELIGIBLE must be non-executing only")
    law = dict(contract.get("route_eligible_law", {}))
    if law.get("non_executing_precondition_only") is not True:
        _fail("RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_EXECUTING", "route eligible law must be non-executing")
    cannot_authorize = tuple(law.get("cannot_authorize", []))
    for value, code in (
        ("AFSH source packet finalization", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SOURCE_PACKET"),
        ("AFSH candidate generation", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_GENERATION"),
        ("candidate training", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_TRAINING"),
        ("shadow-screen packet authorization", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN_PACKET"),
        ("shadow-screen execution", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN"),
        ("R6 opening", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_R6_OPEN"),
        ("learned-router superiority", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SUPERIORITY"),
        ("activation review", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_ACTIVATION"),
        ("runtime cutover", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_CUTOVER"),
        ("lobe escalation", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_LOBE_ESCALATION"),
        ("package promotion", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_PACKAGE_PROMOTION"),
    ):
        _require_forbidden_authorization("ROUTE_ELIGIBLE", cannot_authorize, value, code)
    rows.append(_pass_row("static_hold_is_default_positive_verdict", "RC_B04R6_COURT_VAL_STATIC_HOLD_NOT_DEFAULT", "STATIC_HOLD is default positive verdict", group="static_hold"))
    rows.append(_pass_row("abstain_is_positive_success_verdict", "RC_B04R6_COURT_VAL_ABSTAIN_NOT_POSITIVE", "ABSTAIN is positive success verdict", group="abstention"))
    rows.append(_pass_row("null_route_is_anti_overrouting_control", "RC_B04R6_COURT_VAL_NULL_ROUTE_NOT_CONTROL", "NULL_ROUTE is anti-overrouting control", group="null_route"))
    rows.append(_pass_row("route_eligible_is_non_executing_only", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_EXECUTING", "ROUTE_ELIGIBLE is a non-executing precondition only", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_source_packet_finality", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SOURCE_PACKET", "ROUTE_ELIGIBLE cannot finalize source-packet authority", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_candidate_generation", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_GENERATION", "ROUTE_ELIGIBLE cannot authorize candidate generation", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_candidate_training", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_TRAINING", "ROUTE_ELIGIBLE cannot authorize candidate training", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_shadow_screen_packet", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN_PACKET", "ROUTE_ELIGIBLE cannot authorize a shadow-screen packet", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_shadow_screen_execution", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN", "ROUTE_ELIGIBLE cannot authorize shadow-screen execution", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_r6_opening", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_R6_OPEN", "ROUTE_ELIGIBLE cannot open R6", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_superiority", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SUPERIORITY", "ROUTE_ELIGIBLE cannot earn superiority", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_activation_review", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_ACTIVATION", "ROUTE_ELIGIBLE cannot authorize activation review", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_runtime_cutover", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_CUTOVER", "ROUTE_ELIGIBLE cannot authorize runtime cutover", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_lobe_escalation", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_LOBE_ESCALATION", "ROUTE_ELIGIBLE cannot authorize lobe escalation", group="route_eligible"))
    rows.append(_pass_row("route_eligible_cannot_authorize_package_promotion", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_PACKAGE_PROMOTION", "ROUTE_ELIGIBLE cannot authorize package promotion", group="route_eligible"))
    return rows


def _validate_route_value(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    contract_formula = dict(payloads["court_contract"].get("route_value_formula", {}))
    terms = set(contract_formula.get("terms", []))
    if not set(ROUTE_VALUE_TERMS).issubset(terms):
        _fail("RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", "route-value formula missing required terms")
    gates = set(contract_formula.get("route_eligible_requires", []))
    if not set(ROUTE_ELIGIBILITY_GATES).issubset(gates):
        _fail("RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", "route-value formula missing required gates")
    economics = payloads["route_economics"]
    if set(economics.get("positive_terms", [])) != set(ROUTE_VALUE_POSITIVE_TERMS):
        _fail("RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", "route economics positive terms drifted")
    if set(economics.get("penalty_terms", [])) != set(ROUTE_VALUE_PENALTY_TERMS):
        _fail("RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", "route economics penalty terms drifted")
    if economics.get("route_eligible_is_non_executing") is not True:
        _fail("RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_EXECUTING", "route economics must keep eligibility non-executing")
    if economics.get("routing_requires_positive_permission") is not True:
        _fail("RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", "routing must require positive permission")

    for term in ROUTE_VALUE_POSITIVE_TERMS:
        rows.append(_pass_row(f"route_value_formula_has_{term}", "RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", f"formula includes {term}", group="route_value_formula"))
    for term in ROUTE_VALUE_PENALTY_TERMS:
        rows.append(_pass_row(f"route_value_formula_has_{term}", "RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", f"formula includes {term}", group="route_value_formula"))
    rows.append(_pass_row("route_value_formula_has_required_gates", "RC_B04R6_COURT_VAL_ROUTE_VALUE_FORMULA_INCOMPLETE", "formula includes all route-eligibility gates", group="route_value_formula"))
    return rows


def _validate_costs_and_thresholds(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    wrong_route = payloads["wrong_route_cost"]
    wrong_static = payloads["wrong_static_hold_cost"]
    proof = payloads["proof_burden_delta"]
    threshold = payloads["threshold_profile"]
    if wrong_route.get("wrong_route_cost_required") is not True:
        _fail("RC_B04R6_COURT_VAL_WRONG_ROUTE_COST_MISSING", "wrong-route cost must be required")
    if wrong_static.get("wrong_static_hold_cost_required") is not True:
        _fail("RC_B04R6_COURT_VAL_WRONG_STATIC_HOLD_COST_MISSING", "wrong-static-hold cost must be required")
    if wrong_static.get("tracked_but_not_route_authorizing_by_itself") is not True:
        _fail("RC_B04R6_COURT_VAL_WRONG_STATIC_HOLD_COST_MISSING", "wrong-static-hold cost cannot authorize routing by itself")
    if proof.get("proof_burden_delta_required") is not True:
        _fail("RC_B04R6_COURT_VAL_PROOF_BURDEN_DELTA_MISSING", "proof-burden delta must be required")
    if proof.get("routing_must_reduce_or_justify_proof_burden") is not True:
        _fail("RC_B04R6_COURT_VAL_PROOF_BURDEN_DELTA_MISSING", "routing must reduce or justify proof burden")
    if proof.get("proof_burden_can_block_route") is not True:
        _fail("RC_B04R6_COURT_VAL_PROOF_BURDEN_DELTA_MISSING", "proof burden must be able to block route")
    if threshold.get("threshold_kind") != "FROZEN_BEFORE_CANDIDATE_GENERATION":
        _fail("RC_B04R6_COURT_VAL_THRESHOLD_NOT_FROZEN", "threshold profile must freeze before candidate generation")
    if threshold.get("route_threshold_mutation_requires_later_court") is not True:
        _fail("RC_B04R6_COURT_VAL_THRESHOLD_NOT_FROZEN", "threshold mutation must require later court")
    rows.append(_pass_row("wrong_route_cost_contract_bound", "RC_B04R6_COURT_VAL_WRONG_ROUTE_COST_MISSING", "wrong-route cost is bound", group="wrong_route_cost"))
    rows.append(_pass_row("wrong_static_hold_cost_contract_bound", "RC_B04R6_COURT_VAL_WRONG_STATIC_HOLD_COST_MISSING", "wrong-static-hold cost is bound and non-authorizing by itself", group="wrong_static_hold_cost"))
    rows.append(_pass_row("proof_burden_delta_contract_bound", "RC_B04R6_COURT_VAL_PROOF_BURDEN_DELTA_MISSING", "proof-burden delta is bound", group="proof_burden_delta"))
    rows.append(_pass_row("threshold_profile_frozen_before_candidate_generation", "RC_B04R6_COURT_VAL_THRESHOLD_NOT_FROZEN", "threshold profile is frozen before candidate generation", group="threshold_freeze"))
    return rows


def _validate_reason_codes_and_disqualifiers(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    reason_payload = payloads["reason_codes"]
    reasons = dict(reason_payload.get("reason_codes", {}))
    for mode in ("STATIC_HOLD", "ABSTAIN", "NULL_ROUTE", "ROUTE_ELIGIBLE", "TERMINAL_DEFECT"):
        if not isinstance(reasons.get(mode), list) or not reasons.get(mode):
            _fail("RC_B04R6_COURT_VAL_REASON_CODES_INCOMPLETE", f"reason code taxonomy missing {mode}")
        rows.append(_pass_row(f"reason_code_taxonomy_covers_{mode.lower()}", "RC_B04R6_COURT_VAL_REASON_CODES_INCOMPLETE", f"reason codes cover {mode}", group="reason_code"))
    ledger = payloads["disqualifier_ledger"]
    terminal = set(ledger.get("terminal_disqualifiers", []))
    required = {
        "metric_widening",
        "comparator_weakening",
        "truth_engine_mutation",
        "trust_zone_mutation",
        "candidate_generation_authorization_drift",
        "shadow_screen_authorization_drift",
        "r6_open_drift",
        "activation_authorization_drift",
        "package_promotion_drift",
        "old_universe_reused_as_fresh_proof",
        "label_or_outcome_leakage",
        "route_eligibility_authorizes_execution",
    }
    if not required.issubset(terminal):
        _fail("RC_B04R6_COURT_VAL_DISQUALIFIER_LEDGER_INCOMPLETE", "disqualifier ledger missing terminal drift conditions")
    rows.append(_pass_row("disqualifier_ledger_marks_terminal_authorization_drift", "RC_B04R6_COURT_VAL_DISQUALIFIER_LEDGER_INCOMPLETE", "terminal authorization drift is disqualified", group="disqualifier"))
    rows.append(_pass_row("disqualifier_ledger_forbids_metric_widening", "RC_B04R6_COURT_VAL_METRIC_WIDENING", "metric widening is terminal", group="disqualifier"))
    rows.append(_pass_row("disqualifier_ledger_forbids_comparator_weakening", "RC_B04R6_COURT_VAL_COMPARATOR_WEAKENING", "comparator weakening is terminal", group="disqualifier"))
    rows.append(_pass_row("disqualifier_ledger_forbids_old_universe_proof_drift", "RC_B04R6_COURT_VAL_OLD_UNIVERSE_PROOF_DRIFT", "old universe fresh-proof drift is terminal", group="disqualifier"))
    return rows


def _validate_prep_only(prep_payloads: Dict[str, Dict[str, Any]], payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
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
            _fail("RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must remain PREP_ONLY")
        for flag in required_flags:
            if payload.get(flag) is not True:
                _fail("RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} missing {flag}=true")
        if payload.get("next_lawful_move_required_before_authority") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must require court validation before authority")
    blockers = payloads["future_blocker_register"].get("blockers", [])
    if not isinstance(blockers, list) or len(blockers) < 10:
        _fail("RC_B04R6_COURT_VAL_SCHEMA_MISSING", "future-blocker register must name downstream blockers")
    rows.append(_pass_row("prep_only_source_packet_draft_cannot_authorize_generation", "RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", "source-packet draft cannot authorize generation", group="prep_only"))
    rows.append(_pass_row("prep_only_feature_draft_cannot_authorize_training", "RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", "feature draft cannot authorize training", group="prep_only"))
    rows.append(_pass_row("prep_only_trace_schema_draft_cannot_authorize_screen", "RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", "trace draft cannot authorize screen execution", group="prep_only"))
    rows.append(_pass_row("prep_only_provenance_matrix_cannot_authorize_candidate", "RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", "provenance draft cannot authorize a candidate", group="prep_only"))
    rows.append(_pass_row("future_blocker_register_present", "RC_B04R6_COURT_VAL_SCHEMA_MISSING", "future blocker register is present", group="prep_only"))
    return rows


def _validate_no_authorization_drift(payloads: Dict[str, Dict[str, Any]], prep_payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for label, payload in {**payloads, **prep_payloads}.items():
        for key in FORBIDDEN_TRUE_KEYS:
            _ensure_false_if_present(payload, key, label=label)
        if payload.get("metric_widening_allowed") is not None and payload.get("metric_widening_allowed") is not False:
            _fail("RC_B04R6_COURT_VAL_METRIC_WIDENING", f"{label} metric widening drifted")
        if payload.get("comparator_weakening_allowed") is not None and payload.get("comparator_weakening_allowed") is not False:
            _fail("RC_B04R6_COURT_VAL_COMPARATOR_WEAKENING", f"{label} comparator weakening drifted")
    no_auth = payloads["no_authorization_drift"]
    if no_auth.get("no_downstream_authority_drift") is not True:
        _fail("RC_B04R6_COURT_VAL_PREP_ONLY_AUTHORITY_DRIFT", "no-authorization-drift receipt must pass")
    rows.append(_pass_row("no_candidate_generation_authorization_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_GENERATION", "candidate generation remains unauthorized", group="authorization"))
    rows.append(_pass_row("no_candidate_training_authorization_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_TRAINING", "candidate training remains unauthorized", group="authorization"))
    rows.append(_pass_row("no_shadow_screen_packet_authorization_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN_PACKET", "shadow-screen packet remains unauthorized", group="authorization"))
    rows.append(_pass_row("no_shadow_screen_execution_authorization_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SCREEN", "shadow-screen execution remains unauthorized", group="authorization"))
    rows.append(_pass_row("no_r6_open_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_R6_OPEN", "R6 remains closed", group="authorization"))
    rows.append(_pass_row("no_superiority_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_SUPERIORITY", "learned-router superiority remains unearned", group="authorization"))
    rows.append(_pass_row("no_activation_or_cutover_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_ACTIVATION", "activation and cutover remain false", group="authorization"))
    rows.append(_pass_row("no_lobe_escalation_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_LOBE_ESCALATION", "lobe escalation remains unauthorized", group="authorization"))
    rows.append(_pass_row("no_package_promotion_drift", "RC_B04R6_COURT_VAL_ROUTE_ELIGIBLE_AUTHORIZES_PACKAGE_PROMOTION", "package promotion remains deferred", group="authorization"))
    rows.append(_pass_row("metric_widening_forbidden", "RC_B04R6_COURT_VAL_METRIC_WIDENING", "metric widening is forbidden", group="authorization"))
    rows.append(_pass_row("comparator_weakening_forbidden", "RC_B04R6_COURT_VAL_COMPARATOR_WEAKENING", "comparator weakening is forbidden", group="authorization"))
    rows.append(_pass_row("truth_engine_mutation_forbidden", "RC_B04R6_COURT_VAL_TRUTH_ENGINE_MUTATION", "truth-engine law remains unchanged", group="authorization"))
    rows.append(_pass_row("trust_zone_mutation_forbidden", "RC_B04R6_COURT_VAL_TRUST_ZONE_MUTATION", "trust-zone law remains unchanged", group="authorization"))
    return rows


def _validate_trust_zone(fresh_validation: Dict[str, Any]) -> list[Dict[str, str]]:
    if fresh_validation.get("status") != "PASS" or fresh_validation.get("failures"):
        _fail("RC_B04R6_COURT_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass with no failures")
    return [_pass_row("trust_zone_validation_passes", "RC_B04R6_COURT_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation passed with no failures", group="trust_zone")]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
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
        "court_replay_binding_head": court_replay_binding_head,
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
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_source_packet_authorized": False,
        "afsh_source_packet_finalized": False,
        "afsh_candidate_generation_authorized": False,
        "afsh_candidate_training_authorized": False,
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
        "source_packet_authorship_next_lawful": True,
        "source_packet_authority_not_finalized": True,
    }


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_source_packet_authorized_as_final": False,
        "shadow_screen_packet_authorized": False,
        "shadow_screen_execution_authorized": False,
        "activation_cutover_authorized": False,
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
    input_bindings: list[Dict[str, str]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema_id": schema_id,
        **base,
        "authorization_state": _authorization_state(),
        "validation_rows": rows,
        "pass_count": len(rows),
        "failure_count": 0,
        "validation_reason_codes": REASON_CODES,
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
        "# B04 R6 Static-Hold Abstention Route-Economics Court Validation",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "The validation court confirms STATIC_HOLD is default positive, ABSTAIN is positive success, NULL_ROUTE is anti-overrouting control, and ROUTE_ELIGIBLE is non-executing only.",
        "",
        "No AFSH candidate generation, candidate training, shadow-screen packet, shadow-screen execution, R6 opening, activation, lobe escalation, package promotion, or learned-router superiority is authorized.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 route-economics court validation freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    prep_payloads = {role: _load(root, raw, label=role) for role, raw in PREP_INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    _require_inputs(root, payloads, prep_payloads, text_payloads)

    fresh_trust_validation = validate_trust_zones(root=root)

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root)

    validation_rows: list[Dict[str, str]] = []
    validation_rows.extend(_validate_previous_state(payloads, text_payloads))
    replay_rows, court_replay_binding_head = _validate_replay_binding(payloads, current_main_head=current_main_head)
    validation_rows.extend(replay_rows)
    validation_rows.extend(_validate_verdict_modes(payloads))
    validation_rows.extend(_validate_route_value(payloads))
    validation_rows.extend(_validate_costs_and_thresholds(payloads))
    validation_rows.extend(_validate_reason_codes_and_disqualifiers(payloads))
    validation_rows.extend(_validate_prep_only(prep_payloads, payloads))
    validation_rows.extend(_validate_no_authorization_drift(payloads, prep_payloads))
    validation_rows.extend(_validate_trust_zone(fresh_trust_validation))
    validation_rows.append(
        _pass_row(
            "next_lawful_move_is_afsh_implementation_source_packet",
            "RC_B04R6_COURT_VAL_NEXT_MOVE_DRIFT",
            "the next lawful move is source-packet authorship only",
            group="next_move",
        )
    )

    generated_utc = utc_now_iso_z()
    architecture_binding_head = str(payloads["court_contract"].get("architecture_binding_head", "")).strip()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        court_replay_binding_head=court_replay_binding_head,
        architecture_binding_head=architecture_binding_head,
        current_branch=current_branch,
    )
    validated_court_binding = {
        "status": "BOUND_AND_VALIDATED",
        "court_replay_binding_head": court_replay_binding_head,
        "previous_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_validation_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    common_extra = {
        "validated_court_binding": validated_court_binding,
        "validated_blind_universe_binding": _validated_universe_binding(payloads["court_contract"]),
        "route_eligible_cannot_authorize": list(ROUTE_ELIGIBLE_FORBIDDEN_AUTHORIZATIONS),
        "route_value_terms": list(ROUTE_VALUE_TERMS),
        "authorization_boundaries_preserved": True,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["validation_contract"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.static_hold_abstention_route_economics_court_validation_contract.v1",
            rows=validation_rows,
            input_bindings=input_bindings,
            extra={
                **common_extra,
                "artifact_id": "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_VALIDATION_CONTRACT",
                "validation_object": "B04 R6 static-hold / abstention / route-economics court",
                "validation_goal": "Prove the authored court is complete, internally coherent, fail-closed, trust-zone compatible, replay-bound, and incapable of authorizing downstream execution.",
                "required_verdict_modes": ["STATIC_HOLD", "ABSTAIN", "NULL_ROUTE", "ROUTE_ELIGIBLE"],
            },
        ),
        OUTPUTS["validation_receipt"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.static_hold_abstention_route_economics_court_validation_receipt.v1",
            rows=validation_rows,
            input_bindings=input_bindings,
            extra={**common_extra, "court_validated": True, "verdict": SELECTED_OUTCOME},
        ),
        OUTPUTS["static_hold_verdict"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.static_hold_verdict_validation_receipt.v1",
            rows=_rows_for(validation_rows, "static_hold"),
            input_bindings=input_bindings,
            extra={**common_extra, "static_hold_default_positive_verdict": True},
        ),
        OUTPUTS["abstention_verdict"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.abstention_verdict_validation_receipt.v1",
            rows=_rows_for(validation_rows, "abstention"),
            input_bindings=input_bindings,
            extra={**common_extra, "abstain_positive_success_verdict": True},
        ),
        OUTPUTS["null_route_verdict"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.null_route_verdict_validation_receipt.v1",
            rows=_rows_for(validation_rows, "null_route"),
            input_bindings=input_bindings,
            extra={**common_extra, "null_route_anti_overrouting_control": True},
        ),
        OUTPUTS["route_eligible_non_execution"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.route_eligible_non_execution_validation_receipt.v1",
            rows=_rows_for(validation_rows, "route_eligible"),
            input_bindings=input_bindings,
            extra={**common_extra, "route_eligible_non_executing_only": True},
        ),
        OUTPUTS["route_value_formula"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.route_value_formula_validation_receipt.v1",
            rows=_rows_for(validation_rows, "route_value_formula"),
            input_bindings=input_bindings,
            extra={**common_extra, "route_value_formula_complete": True},
        ),
        OUTPUTS["threshold_freeze"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.route_value_threshold_freeze_validation_receipt.v1",
            rows=_rows_for(validation_rows, "threshold_freeze"),
            input_bindings=input_bindings,
            extra={**common_extra, "threshold_frozen_before_candidate_generation": True},
        ),
        OUTPUTS["wrong_route_cost"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.wrong_route_cost_validation_receipt.v1",
            rows=_rows_for(validation_rows, "wrong_route_cost"),
            input_bindings=input_bindings,
            extra={**common_extra, "wrong_route_cost_bound": True},
        ),
        OUTPUTS["wrong_static_hold_cost"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.wrong_static_hold_cost_validation_receipt.v1",
            rows=_rows_for(validation_rows, "wrong_static_hold_cost"),
            input_bindings=input_bindings,
            extra={**common_extra, "wrong_static_hold_cost_bound": True},
        ),
        OUTPUTS["proof_burden_delta"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.proof_burden_delta_validation_receipt.v1",
            rows=_rows_for(validation_rows, "proof_burden_delta"),
            input_bindings=input_bindings,
            extra={**common_extra, "proof_burden_delta_bound": True},
        ),
        OUTPUTS["reason_code"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.court_reason_code_validation_receipt.v1",
            rows=_rows_for(validation_rows, "reason_code"),
            input_bindings=input_bindings,
            extra={**common_extra, "reason_code_taxonomy_complete": True},
        ),
        OUTPUTS["disqualifier"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.court_disqualifier_validation_receipt.v1",
            rows=_rows_for(validation_rows, "disqualifier"),
            input_bindings=input_bindings,
            extra={**common_extra, "disqualifier_ledger_complete": True},
        ),
        OUTPUTS["prep_only_non_authority"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.court_prep_only_non_authority_validation_receipt.v1",
            rows=_rows_for(validation_rows, "prep_only"),
            input_bindings=input_bindings,
            extra={**common_extra, "prep_only_drafts_remain_non_authoritative": True},
        ),
        OUTPUTS["no_authorization_drift"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.court_no_authorization_drift_validation_receipt.v1",
            rows=_rows_for(validation_rows, "authorization"),
            input_bindings=input_bindings,
            extra={**common_extra, "no_downstream_authorization_drift": True},
        ),
        OUTPUTS["trust_zone"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.court_trust_zone_validation_receipt.v1",
            rows=_rows_for(validation_rows, "trust_zone"),
            input_bindings=input_bindings,
            extra={**common_extra, "fresh_trust_zone_validation": fresh_trust_validation},
        ),
        OUTPUTS["replay_binding"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.court_replay_binding_validation_receipt.v1",
            rows=_rows_for(validation_rows, "replay"),
            input_bindings=input_bindings,
            extra={**common_extra, "court_replay_binding_validated": True},
        ),
        OUTPUTS["next_lawful_move"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v7",
            rows=_rows_for(validation_rows, "next_move"),
            input_bindings=input_bindings,
            extra={**common_extra, "verdict": SELECTED_OUTCOME},
        ),
        OUTPUTS["validation_report"]: _report(validation_rows),
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "pass_count": len(validation_rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate B04 R6 static-hold / abstention / route-economics court.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
