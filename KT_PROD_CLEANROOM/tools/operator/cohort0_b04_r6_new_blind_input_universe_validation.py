from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-new-blind-input-universe-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_NEW_BLIND_INPUT_UNIVERSE_VALIDATION"
PREVIOUS_LANE = "B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT"

EXPECTED_PREVIOUS_OUTCOME = "R6_NEW_BLIND_UNIVERSE_CONTRACT_BOUND__CONTRACT_VALIDATION_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "VALIDATE_B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT"
OUTCOME_VALIDATED = "B04_R6_NEW_BLIND_UNIVERSE_VALIDATED__STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_NEXT"
OUTCOME_DEFERRED = "B04_R6_NEW_BLIND_UNIVERSE_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_NEW_BLIND_UNIVERSE_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT"

SELECTED_ARCHITECTURE_ID = "AFSH-2S-GUARD"
SELECTED_ARCHITECTURE_NAME = "Abstention-First Static-Hold Two-Stage Guarded Router"
UNIVERSE_ID = "B04_R6_AFSH_BLIND_UNIVERSE_1"
CASE_PREFIX = "B04R6-AFSH-BU1-"
EXPECTED_CASE_COUNT = 18

FORBIDDEN_CLAIMS = [
    "r6_open",
    "router_generation_authorized",
    "candidate_generation_authorized",
    "shadow_screen_authorized",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "learned_router_activated",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

FORBIDDEN_TRUE_KEYS = [
    "r6_authorized",
    "r6_open",
    "router_generation_authorized",
    "candidate_generation_authorized",
    "shadow_screen_authorized",
    "new_shadow_screen_authorized",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "learned_router_activated",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

REQUIRED_FAMILIES = frozenset(
    {
        "STATIC_HOLD_SHOULD_WIN",
        "ROUTING_PLAUSIBLY_ADDS_VALUE",
        "OVER_ROUTING_TRAP",
        "ABSTENTION_REQUIRED",
        "BOUNDARY_REJECTION",
        "MIRROR_SURFACE_VARIANT",
        "MASKED_SURFACE_VARIANT",
        "NULL_ROUTE_CONTROL",
        "PROOF_BURDEN_HEAVY",
        "PROOF_BURDEN_LIGHT",
        "ADVERSARIAL_SELECTOR_TRAP",
        "TRUST_ZONE_BOUNDARY_CASE",
        "COMPARATOR_DOMINANCE_CASE",
        "ROUTE_VALUE_CASE",
        "CALIBRATION_EDGE_CASE",
    }
)

REQUIRED_BLINDNESS_KEYS = frozenset(
    {
        "labels_hidden_from_candidate_generation",
        "outcomes_hidden_from_candidate_generation",
        "route_labels_hidden_before_screen",
        "calibration_from_screen_outcomes_forbidden",
    }
)

REQUIRED_TRACE_GROUPS = frozenset(
    {
        "route_decision_trace",
        "abstention_trace",
        "overrouting_trace",
        "static_fallback_rationale",
        "mirror_masked_trace",
        "deterministic_replay_receipt",
    }
)

OLD_CASE_PREFIXES = ("R01", "R02", "R03", "R04", "R6B")

REASON_CODES = [
    "RC_B04R6_BUV_SCHEMA_REQUIRED_FIELD_MISSING",
    "RC_B04R6_BUV_CASE_COUNT_MISMATCH",
    "RC_B04R6_BUV_CASE_ID_NAMESPACE_DRIFT",
    "RC_B04R6_BUV_DUPLICATE_CASE_ID",
    "RC_B04R6_BUV_SOURCE_HASH_MISSING",
    "RC_B04R6_BUV_MANIFEST_HASH_UNSTABLE",
    "RC_B04R6_BUV_HOLDOUT_LOCK_WEAK",
    "RC_B04R6_BUV_LABEL_LEAKAGE",
    "RC_B04R6_BUV_OUTCOME_LEAKAGE",
    "RC_B04R6_BUV_ROUTE_LABEL_LEAKAGE",
    "RC_B04R6_BUV_PRIOR_R01_R04_NOT_DIAGNOSTIC_ONLY",
    "RC_B04R6_BUV_PRIOR_V2_SIX_ROW_NOT_DIAGNOSTIC_ONLY",
    "RC_B04R6_BUV_MIRROR_SIBLING_MISSING",
    "RC_B04R6_BUV_MASKED_SIBLING_MISSING",
    "RC_B04R6_BUV_NULL_ROUTE_CONTROL_MISSING",
    "RC_B04R6_BUV_STATIC_HOLD_CONTROL_MISSING",
    "RC_B04R6_BUV_ABSTENTION_CONTROL_MISSING",
    "RC_B04R6_BUV_FAMILY_BALANCE_DEFECT",
    "RC_B04R6_BUV_TRACE_COMPATIBILITY_DEFECT",
    "RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING",
    "RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT",
    "RC_B04R6_BUV_GENERATION_AUTHORIZATION_DRIFT",
    "RC_B04R6_BUV_SCREEN_AUTHORIZATION_DRIFT",
    "RC_B04R6_BUV_R6_OPEN_DRIFT",
    "RC_B04R6_BUV_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_BUV_NEXT_MOVE_DRIFT",
    "RC_B04R6_BUV_REPLAY_BINDING_MISMATCH",
]

INPUTS = {
    "bound_contract": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_contract.json",
    "bound_contract_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_contract_receipt.json",
    "case_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_case_manifest.json",
    "mirror_masked_map": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_mirror_masked_map.json",
    "holdout_separation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_holdout_separation_receipt.json",
    "leakage_guard": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_leakage_guard.json",
    "trust_zone_report": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_trust_zone_report.json",
    "parse_sweep": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_parse_sweep_receipt.json",
    "family_balance": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_universe_case_family_balance_report.json",
    "control_sibling_map": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_universe_control_sibling_candidate_map.json",
    "static_hold_draft": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_court_contract_draft.json",
    "abstention_registry_draft": "KT_PROD_CLEANROOM/reports/b04_r6_abstention_control_registry_draft.json",
    "route_economics_draft": "KT_PROD_CLEANROOM/reports/b04_r6_route_economics_matrix_draft.json",
    "afsh_interface_draft": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_router_interface_contract_draft.json",
    "afsh_trace_schema_draft": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_trace_schema_draft.json",
    "external_research_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_external_research_non_authority_receipt.json",
    "forbidden_claims_receipt": "KT_PROD_CLEANROOM/reports/learned_router_forbidden_claims_receipt.json",
    "clean_state": "KT_PROD_CLEANROOM/reports/r6_clean_state_watchdog_receipt.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

REFERENCE_INPUTS = {
    "trust_zone_registry": "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
    "canonical_scope_manifest": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
}

OUTPUTS = {
    "validation_contract": "b04_r6_new_blind_input_universe_validation_contract.json",
    "validation_receipt": "b04_r6_new_blind_input_universe_validation_receipt.json",
    "validation_report": "b04_r6_new_blind_input_universe_validation_report.md",
    "case_manifest_validation": "b04_r6_blind_universe_case_manifest_validation_receipt.json",
    "holdout_validation": "b04_r6_blind_universe_holdout_validation_receipt.json",
    "leakage_validation": "b04_r6_blind_universe_leakage_validation_receipt.json",
    "control_sibling_validation": "b04_r6_blind_universe_control_sibling_validation_receipt.json",
    "diagnostic_only_validation": "b04_r6_blind_universe_diagnostic_only_validation_receipt.json",
    "trust_zone_validation": "b04_r6_blind_universe_trust_zone_validation_receipt.json",
    "no_authorization_drift": "b04_r6_blind_universe_no_authorization_drift_receipt.json",
    "replay_validation": "b04_r6_blind_universe_replay_validation_receipt.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


def _stable_hash(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


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
    for role, raw in sorted({**INPUTS, **REFERENCE_INPUTS}.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} drifted: {key} must remain false")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str, prep_only_allowed: bool = True) -> None:
    allowed_statuses = {"PASS", "FROZEN_PACKET"}
    if prep_only_allowed:
        allowed_statuses.add("PREP_ONLY")
    if str(payload.get("status", "")).strip() not in allowed_statuses:
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status in {sorted(allowed_statuses)}")
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _require_top_level(payload: Dict[str, Any], required: Sequence[str], *, label: str) -> None:
    missing = [field for field in required if field not in payload]
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: {label} missing required fields: {missing}")


def _cases(payload: Dict[str, Any]) -> list[Dict[str, Any]]:
    rows = payload.get("cases")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: case manifest missing cases list")
    return [dict(row) for row in rows if isinstance(row, dict)]


def _entries(payload: Dict[str, Any], *, label: str) -> list[Dict[str, Any]]:
    rows = payload.get("entries", [])
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing entries list")
    return [dict(row) for row in rows if isinstance(row, dict)]


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _pass_row(check_id: str, reason_code: str, detail: str) -> Dict[str, Any]:
    return {"check_id": check_id, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validate_previous_state(payloads: Dict[str, Dict[str, Any]], *, current_branch: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for label, payload in payloads.items():
        _ensure_common_boundary(payload, label=label)
    contract = payloads["bound_contract"]
    receipt = payloads["bound_contract_receipt"]
    next_receipt = payloads["previous_next_lawful_move"]

    if contract.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_BUV_SCHEMA_REQUIRED_FIELD_MISSING", "bound contract must select AFSH-2S-GUARD")
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_BUV_NEXT_MOVE_DRIFT", "bound contract outcome must be the validation-next outcome")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_BUV_NEXT_MOVE_DRIFT", "bound contract next move must be validation")
    if receipt.get("blind_universe_contract_bound") is not True:
        _fail("RC_B04R6_BUV_SCHEMA_REQUIRED_FIELD_MISSING", "bound contract receipt must affirm bound universe")

    acceptable_pairs = {
        (PREVIOUS_LANE, EXPECTED_PREVIOUS_NEXT_MOVE),
        (AUTHORITATIVE_LANE, NEXT_LAWFUL_MOVE),
    }
    pair = (str(next_receipt.get("authoritative_lane", "")), str(next_receipt.get("next_lawful_move", "")))
    if pair not in acceptable_pairs:
        if not (current_branch == "main" and next_receipt.get("next_lawful_move") in {EXPECTED_PREVIOUS_NEXT_MOVE, NEXT_LAWFUL_MOVE}):
            _fail("RC_B04R6_BUV_NEXT_MOVE_DRIFT", f"unexpected next-lawful-move receipt: {pair}")

    rows.append(_pass_row("previous_bound_universe_state", "RC_B04R6_BUV_NEXT_MOVE_DRIFT", "bound universe state is validation-ready"))
    return rows


def _validate_contract_schema(contract: Dict[str, Any]) -> list[Dict[str, Any]]:
    required = [
        "schema_id",
        "status",
        "current_git_head",
        "current_main_head",
        "architecture_binding_head",
        "selected_architecture_id",
        "branch_law",
        "blind_universe_identity",
        "input_source_rules",
        "input_provenance_rules",
        "blindness_rules",
        "label_access_rules",
        "outcome_access_rules",
        "no_tuning_rules",
        "prior_screen_contamination_rules",
        "stratification_axes",
        "family_balance_rules",
        "admissibility_rules",
        "exclusion_rules",
        "holdout_lock",
        "case_manifest_binding",
        "mirror_masked_sibling_map",
        "null_route_controls",
        "static_hold_controls",
        "boundary_abstention_controls",
        "static_comparator_binding",
        "route_economics_basis",
        "proof_burden_basis",
        "wrong_route_cost_basis",
        "wrong_static_hold_cost_basis",
        "calibration_basis",
        "monotonicity_basis",
        "trust_zone_bindings",
        "no_runtime_import_guards",
        "no_generation_surface_guards",
        "no_screen_execution_guards",
        "no_package_promotion_guards",
        "required_receipts",
        "validation_commands",
        "pass_conditions",
        "fail_closed_conditions",
        "allowed_outcomes",
        "next_lawful_moves",
    ]
    _require_top_level(contract, required, label="bound blind-universe contract")
    if contract["blind_universe_identity"].get("case_count") != EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_BUV_CASE_COUNT_MISMATCH", "contract must declare the 18-case universe")
    if contract["blind_universe_identity"].get("case_id_prefix") != CASE_PREFIX.rstrip("-"):
        _fail("RC_B04R6_BUV_CASE_ID_NAMESPACE_DRIFT", "contract case prefix drifted")
    if contract["static_comparator_binding"].get("static_baseline_weakening_allowed") is not False:
        _fail("RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT", "static comparator weakening is not allowed")
    if contract.get("no_generation_surface_guards", {}).get("candidate_generation_authorized") is not False:
        _fail("RC_B04R6_BUV_GENERATION_AUTHORIZATION_DRIFT", "contract may not authorize candidate generation")
    if contract.get("no_screen_execution_guards", {}).get("shadow_screen_authorized") is not False:
        _fail("RC_B04R6_BUV_SCREEN_AUTHORIZATION_DRIFT", "contract may not authorize shadow execution")
    return [
        _pass_row("contract_schema_completeness", "RC_B04R6_BUV_SCHEMA_REQUIRED_FIELD_MISSING", "contract has required validation fields"),
        _pass_row("comparator_metric_preservation", "RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT", "no comparator weakening or metric widening is authorized"),
    ]


def _validate_case_manifest(manifest: Dict[str, Any]) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    rows: list[Dict[str, Any]] = []
    cases = _cases(manifest)
    if len(cases) != EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_BUV_CASE_COUNT_MISMATCH", f"expected {EXPECTED_CASE_COUNT}; got {len(cases)}")
    manifest_hash = str(manifest.get("case_manifest_sha256", ""))
    if manifest_hash != _stable_hash(cases):
        _fail("RC_B04R6_BUV_MANIFEST_HASH_UNSTABLE", "case manifest sha256 does not match canonical case payload")
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    families: set[str] = set()
    buckets: set[str] = set()
    variants: set[str] = set()
    for row in cases:
        case_id = str(row.get("case_id", ""))
        if not case_id.startswith(CASE_PREFIX):
            _fail("RC_B04R6_BUV_CASE_ID_NAMESPACE_DRIFT", f"case ID outside namespace: {case_id}")
        if case_id in seen_ids:
            _fail("RC_B04R6_BUV_DUPLICATE_CASE_ID", f"duplicate case ID: {case_id}")
        if case_id.startswith(OLD_CASE_PREFIXES):
            _fail("RC_B04R6_BUV_PRIOR_R01_R04_NOT_DIAGNOSTIC_ONLY", f"old case reused: {case_id}")
        seen_ids.add(case_id)
        families.add(str(row.get("family_id", "")))
        buckets.add(str(row.get("balance_bucket", "")))
        variants.add(str(row.get("variant_type", "")))
        source_ref = dict(row.get("source_ref", {}))
        source_sha = str(source_ref.get("sha256", ""))
        if len(source_sha) != 64 or any(ch not in "0123456789abcdef" for ch in source_sha):
            _fail("RC_B04R6_BUV_SOURCE_HASH_MISSING", f"missing valid source sha256 for {case_id}")
        if source_sha in seen_hashes:
            _fail("RC_B04R6_BUV_SOURCE_HASH_MISSING", f"duplicate source sha256 for {case_id}")
        seen_hashes.add(source_sha)
        blindness = dict(row.get("blindness", {}))
        missing = sorted(REQUIRED_BLINDNESS_KEYS - set(blindness))
        if missing:
            _fail("RC_B04R6_BUV_LABEL_LEAKAGE", f"{case_id} missing blindness keys: {missing}")
        if blindness.get("labels_hidden_from_candidate_generation") is not True:
            _fail("RC_B04R6_BUV_LABEL_LEAKAGE", f"{case_id} labels are not hidden")
        if blindness.get("outcomes_hidden_from_candidate_generation") is not True:
            _fail("RC_B04R6_BUV_OUTCOME_LEAKAGE", f"{case_id} outcomes are not hidden")
        if blindness.get("route_labels_hidden_before_screen") is not True:
            _fail("RC_B04R6_BUV_ROUTE_LABEL_LEAKAGE", f"{case_id} route labels are not hidden")
        if blindness.get("calibration_from_screen_outcomes_forbidden") is not True:
            _fail("RC_B04R6_BUV_OUTCOME_LEAKAGE", f"{case_id} calibration from screen outcomes is not forbidden")
        if row.get("registry_compatible_zone") != "CANONICAL":
            _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", f"{case_id} is not canonical-zone compatible")
        if row.get("trust_zone") != "CANONICAL_EVAL_HOLDOUT":
            _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", f"{case_id} missing canonical eval holdout zone")
        if dict(row.get("admissibility", {})).get("admitted") is not True:
            _fail("RC_B04R6_BUV_SCHEMA_REQUIRED_FIELD_MISSING", f"{case_id} must be admitted in the manifest")
        if "proof_burden" not in row or "route_value" not in row:
            _fail("RC_B04R6_BUV_TRACE_COMPATIBILITY_DEFECT", f"{case_id} missing stratification axes")

    missing_families = sorted(REQUIRED_FAMILIES - families)
    if missing_families:
        _fail("RC_B04R6_BUV_FAMILY_BALANCE_DEFECT", f"missing required families: {missing_families}")
    for required_bucket in ("STATIC_HOLD", "ROUTE_VALUE", "OVERROUTING_TRAP", "ABSTENTION_BOUNDARY", "CONTROL_SIBLING"):
        if required_bucket not in buckets:
            _fail("RC_B04R6_BUV_FAMILY_BALANCE_DEFECT", f"missing balance bucket: {required_bucket}")
    for required_variant in ("MIRROR", "MASKED", "NULL_ROUTE"):
        if required_variant not in variants:
            _fail("RC_B04R6_BUV_FAMILY_BALANCE_DEFECT", f"missing control variant: {required_variant}")
    rows.append(_pass_row("case_manifest_identity", "RC_B04R6_BUV_CASE_COUNT_MISMATCH", "18 fresh case IDs are present"))
    rows.append(_pass_row("case_manifest_hash_stability", "RC_B04R6_BUV_MANIFEST_HASH_UNSTABLE", "case manifest hash is stable"))
    rows.append(_pass_row("case_family_balance_sanity", "RC_B04R6_BUV_FAMILY_BALANCE_DEFECT", "required families, buckets, and control variants are present"))
    return rows, cases


def _validate_holdout_and_leakage(
    *, holdout: Dict[str, Any], leakage: Dict[str, Any], contract: Dict[str, Any]
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    holdout_rows: list[Dict[str, Any]] = []
    leakage_rows: list[Dict[str, Any]] = []
    if holdout.get("holdout_status") != "LOCKED":
        _fail("RC_B04R6_BUV_HOLDOUT_LOCK_WEAK", "holdout status must be LOCKED")
    for key in (
        "case_ids_fresh",
        "old_r01_r04_cases_diagnostic_only",
        "old_six_row_v2_universe_diagnostic_only",
        "blind_outcomes_hidden_from_candidate_generation",
        "blind_route_labels_hidden_from_candidate_generation",
    ):
        if holdout.get(key) is not True:
            _fail("RC_B04R6_BUV_HOLDOUT_LOCK_WEAK", f"holdout receipt must keep {key}=true")
    if holdout.get("old_case_id_reuse_detected") is not False:
        _fail("RC_B04R6_BUV_PRIOR_R01_R04_NOT_DIAGNOSTIC_ONLY", "old case reuse must be false")
    if leakage.get("leakage_guard_status") != "PASS":
        _fail("RC_B04R6_BUV_LABEL_LEAKAGE", "leakage guard must pass")
    required_leakage_true = {
        "old_r01_r04_cases_are_diagnostic_only": "RC_B04R6_BUV_PRIOR_R01_R04_NOT_DIAGNOSTIC_ONLY",
        "old_six_row_v2_universe_is_diagnostic_only": "RC_B04R6_BUV_PRIOR_V2_SIX_ROW_NOT_DIAGNOSTIC_ONLY",
        "old_candidate_outputs_as_labels_forbidden": "RC_B04R6_BUV_LABEL_LEAKAGE",
        "old_disqualification_as_route_label_forbidden": "RC_B04R6_BUV_ROUTE_LABEL_LEAKAGE",
        "new_case_ids_are_fresh": "RC_B04R6_BUV_CASE_ID_NAMESPACE_DRIFT",
        "new_outcome_labels_inaccessible_before_screen": "RC_B04R6_BUV_OUTCOME_LEAKAGE",
        "new_route_value_labels_inaccessible_before_screen": "RC_B04R6_BUV_ROUTE_LABEL_LEAKAGE",
        "calibration_from_blind_screen_outcomes_forbidden": "RC_B04R6_BUV_OUTCOME_LEAKAGE",
    }
    for key, code in required_leakage_true.items():
        if leakage.get(key) is not True:
            _fail(code, f"leakage guard must keep {key}=true")
    prior_rules = dict(contract.get("prior_screen_contamination_rules", {}))
    if prior_rules.get("r01_r04_diagnostic_only") is not True:
        _fail("RC_B04R6_BUV_PRIOR_R01_R04_NOT_DIAGNOSTIC_ONLY", "contract must keep R01-R04 diagnostic-only")
    if prior_rules.get("six_row_v2_universe_diagnostic_only") is not True:
        _fail("RC_B04R6_BUV_PRIOR_V2_SIX_ROW_NOT_DIAGNOSTIC_ONLY", "contract must keep v2 six-row universe diagnostic-only")
    if contract.get("r01_r04_reuse_as_counted_proof_allowed") is not False:
        _fail("RC_B04R6_BUV_PRIOR_R01_R04_NOT_DIAGNOSTIC_ONLY", "R01-R04 counted reuse must remain forbidden")
    if contract.get("six_row_v2_reuse_as_counted_proof_allowed") is not False:
        _fail("RC_B04R6_BUV_PRIOR_V2_SIX_ROW_NOT_DIAGNOSTIC_ONLY", "v2 six-row counted reuse must remain forbidden")
    holdout_rows.append(_pass_row("holdout_lock", "RC_B04R6_BUV_HOLDOUT_LOCK_WEAK", "holdout lock is strong"))
    leakage_rows.append(_pass_row("leakage_absence", "RC_B04R6_BUV_LABEL_LEAKAGE", "label/outcome/route leakage is barred"))
    leakage_rows.append(_pass_row("diagnostic_only_prior_screens", "RC_B04R6_BUV_PRIOR_R01_R04_NOT_DIAGNOSTIC_ONLY", "prior screens remain diagnostic-only"))
    return holdout_rows, leakage_rows


def _validate_control_siblings(
    *, cases: list[Dict[str, Any]], mirror_map: Dict[str, Any], control_map: Dict[str, Any]
) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    by_id = {str(row["case_id"]): row for row in cases}
    expected_map_hash = _stable_hash(
        {
            "map_status": mirror_map.get("map_status"),
            "required": mirror_map.get("required"),
            "entries": mirror_map.get("entries"),
            "all_case_ids": mirror_map.get("all_case_ids"),
        }
    )
    if mirror_map.get("mirror_masked_map_sha256") != expected_map_hash:
        _fail("RC_B04R6_BUV_MANIFEST_HASH_UNSTABLE", "mirror/masked map hash is unstable")
    for payload, label in ((mirror_map, "mirror map"), (control_map, "control sibling map")):
        if payload.get("required") is not True:
            _fail("RC_B04R6_BUV_MIRROR_SIBLING_MISSING", f"{label} must be required")
        if sorted(payload.get("all_case_ids", [])) != sorted(by_id):
            _fail("RC_B04R6_BUV_CASE_COUNT_MISMATCH", f"{label} all_case_ids must match manifest")
        for entry in _entries(payload, label=label):
            primary = str(entry.get("primary_case_id", ""))
            if primary not in by_id:
                _fail("RC_B04R6_BUV_MIRROR_SIBLING_MISSING", f"{label} primary missing: {primary}")
            siblings = dict(by_id[primary].get("control_siblings", {}))
            for field, code in (
                ("mirror_case_id", "RC_B04R6_BUV_MIRROR_SIBLING_MISSING"),
                ("masked_case_id", "RC_B04R6_BUV_MASKED_SIBLING_MISSING"),
                ("null_route_case_id", "RC_B04R6_BUV_NULL_ROUTE_CONTROL_MISSING"),
            ):
                expected = str(entry.get(field, ""))
                if not expected or expected not in by_id:
                    _fail(code, f"{label} missing {field} for {primary}")
                if str(siblings.get(field, "")) != expected:
                    _fail(code, f"{label} disagrees with case manifest for {primary} {field}")
    static_controls = [row for row in cases if row.get("balance_bucket") == "STATIC_HOLD"]
    abstention_controls = [row for row in cases if row.get("balance_bucket") == "ABSTENTION_BOUNDARY"]
    if len(static_controls) < 2:
        _fail("RC_B04R6_BUV_STATIC_HOLD_CONTROL_MISSING", "at least two static-hold controls are required")
    if len(abstention_controls) < 3:
        _fail("RC_B04R6_BUV_ABSTENTION_CONTROL_MISSING", "at least three abstention/boundary controls are required")
    rows.append(_pass_row("control_sibling_completeness", "RC_B04R6_BUV_MIRROR_SIBLING_MISSING", "mirror/masked/null-route controls match manifest"))
    rows.append(_pass_row("static_abstention_controls", "RC_B04R6_BUV_STATIC_HOLD_CONTROL_MISSING", "static-hold and abstention controls are present"))
    return rows


def _validate_trace_and_prep(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    trace = payloads["afsh_trace_schema_draft"]
    groups = set(trace.get("required_trace_groups", []))
    if not REQUIRED_TRACE_GROUPS.issubset(groups):
        missing = sorted(REQUIRED_TRACE_GROUPS - groups)
        _fail("RC_B04R6_BUV_TRACE_COMPATIBILITY_DEFECT", f"AFSH trace draft missing groups: {missing}")
    prep_roles = [
        "static_hold_draft",
        "abstention_registry_draft",
        "route_economics_draft",
        "afsh_interface_draft",
        "afsh_trace_schema_draft",
        "external_research_receipt",
    ]
    for role in prep_roles:
        payload = payloads[role]
        if payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT", f"{role} must remain prep-only")
        _ensure_common_boundary(payload, label=role)
    if payloads["route_economics_draft"].get("metric_widening_allowed") is not False:
        _fail("RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT", "route economics draft may not widen metrics")
    if payloads["external_research_receipt"].get("external_research_as_authority_allowed") is not False:
        _fail("RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT", "external research may not become authority")
    rows.append(_pass_row("afsh_trace_compatibility", "RC_B04R6_BUV_TRACE_COMPATIBILITY_DEFECT", "AFSH trace shape covers required groups"))
    rows.append(_pass_row("prep_only_non_authority", "RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT", "prep artifacts remain non-authoritative"))
    return rows


def _validate_trust_zone(payloads: Dict[str, Dict[str, Any]], *, fresh_validation: Dict[str, Any]) -> list[Dict[str, Any]]:
    trust_report = payloads["trust_zone_report"]
    if trust_report.get("logical_case_zone") != "CANONICAL_EVAL_HOLDOUT":
        _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", "blind cases must bind canonical eval holdout zone")
    if trust_report.get("registry_compatible_zone") != "CANONICAL":
        _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", "blind cases must be canonical-compatible")
    if trust_report.get("case_zone_mismatches") not in ([], None):
        _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", "case zone mismatches must be empty")
    embedded = dict(trust_report.get("trust_zone_validation", {}))
    if embedded.get("status") != "PASS" or embedded.get("failures"):
        _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", "embedded trust-zone validation must pass")
    if fresh_validation.get("status") != "PASS" or fresh_validation.get("failures"):
        _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", "fresh trust-zone validation must pass")
    if fresh_validation.get("failures"):
        _fail("RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", "fresh trust-zone validation must have zero failures")
    return [_pass_row("trust_zone_binding", "RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING", "embedded and fresh trust-zone validation passed")]


def _validate_no_authorization_drift(payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for label, payload in payloads.items():
        for key in FORBIDDEN_TRUE_KEYS:
            _ensure_false_if_present(payload, key, label=label)
        if payload.get("package_promotion_remains_deferred") is not True:
            _fail("RC_B04R6_BUV_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drifted")
    clean = payloads["clean_state"]
    for key in (
        "candidate_generation_detected",
        "shadow_screen_execution_detected",
        "old_blind_universe_reuse_detected",
        "metric_widening_detected",
        "comparator_weakening_detected",
        "package_promotion_drift",
        "truth_engine_mutation_detected",
        "trust_zone_mutation_detected",
    ):
        if clean.get(key) is not False:
            _fail("RC_B04R6_BUV_GENERATION_AUTHORIZATION_DRIFT", f"clean-state watchdog drifted: {key}")
    rows.append(_pass_row("no_authorization_drift", "RC_B04R6_BUV_GENERATION_AUTHORIZATION_DRIFT", "no downstream authority drift detected"))
    return rows


def _validate_replay_binding(payloads: Dict[str, Dict[str, Any]], *, current_main_head: str) -> list[Dict[str, Any]]:
    contract = payloads["bound_contract"]
    manifest = payloads["case_manifest"]
    parse_sweep = payloads["parse_sweep"]
    if parse_sweep.get("status") != "PASS":
        _fail("RC_B04R6_BUV_REPLAY_BINDING_MISMATCH", "bound parse sweep must be PASS")
    if parse_sweep.get("artifact_count", 0) < 22:
        _fail("RC_B04R6_BUV_REPLAY_BINDING_MISMATCH", "bound parse sweep did not cover expected artifact set")
    if contract.get("subject_main_head") != manifest.get("subject_main_head"):
        _fail("RC_B04R6_BUV_REPLAY_BINDING_MISMATCH", "contract and manifest subject heads differ")
    if not current_main_head:
        _fail("RC_B04R6_BUV_REPLAY_BINDING_MISMATCH", "current main head is missing")
    return [_pass_row("replay_binding", "RC_B04R6_BUV_REPLAY_BINDING_MISMATCH", "bound universe artifacts share a stable replay subject and current main is known")]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    bound_contract_head: str,
    architecture_binding_head: str,
    status: str = "PASS",
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "subject_main_head": current_main_head,
        "bound_contract_subject_main_head": bound_contract_head,
        "architecture_binding_head": architecture_binding_head,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "current_branch": current_branch,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "shadow_screen_authorized": False,
        "new_shadow_screen_authorized": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _artifact_payload(
    *,
    base: Dict[str, Any],
    schema_id: str,
    rows: list[Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    failures = [row for row in rows if row.get("status") != "PASS"]
    payload = {
        "schema_id": schema_id,
        **base,
        "selected_outcome": SELECTED_OUTCOME,
        "allowed_outcomes": [OUTCOME_VALIDATED, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "validation_rows": rows,
        "failure_count": len(failures),
        "pass_count": len(rows) - len(failures),
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    if extra:
        payload.update(extra)
    return payload


def _report(rows: list[Dict[str, Any]]) -> str:
    lines = [
        "# B04 R6 New Blind Input Universe Validation",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "The bound B04 R6 blind universe validated without authorizing AFSH generation, a shadow screen, R6 opening, activation, lobe escalation, or package promotion.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 blind-universe validation freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    fresh_trust_validation = validate_trust_zones(root=root)
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head

    validation_rows: list[Dict[str, Any]] = []
    validation_rows.extend(_validate_previous_state(payloads, current_branch=current_branch))
    validation_rows.extend(_validate_contract_schema(payloads["bound_contract"]))
    case_rows, cases = _validate_case_manifest(payloads["case_manifest"])
    validation_rows.extend(case_rows)
    holdout_rows, leakage_rows = _validate_holdout_and_leakage(
        holdout=payloads["holdout_separation"],
        leakage=payloads["leakage_guard"],
        contract=payloads["bound_contract"],
    )
    validation_rows.extend(holdout_rows)
    validation_rows.extend(leakage_rows)
    control_rows = _validate_control_siblings(
        cases=cases,
        mirror_map=payloads["mirror_masked_map"],
        control_map=payloads["control_sibling_map"],
    )
    validation_rows.extend(control_rows)
    validation_rows.extend(_validate_trace_and_prep(payloads))
    trust_rows = _validate_trust_zone(payloads, fresh_validation=fresh_trust_validation)
    validation_rows.extend(trust_rows)
    auth_rows = _validate_no_authorization_drift(payloads)
    validation_rows.extend(auth_rows)
    replay_rows = _validate_replay_binding(payloads, current_main_head=current_main_head)
    validation_rows.extend(replay_rows)

    generated_utc = utc_now_iso_z()
    bound_contract_head = str(payloads["bound_contract"].get("subject_main_head", "")).strip()
    architecture_binding_head = str(payloads["bound_contract"].get("architecture_binding_head", "")).strip()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        bound_contract_head=bound_contract_head,
        architecture_binding_head=architecture_binding_head,
    )
    common_extra = {
        "selected_outcome": SELECTED_OUTCOME,
        "bound_universe_validated": True,
        "blind_universe_id": UNIVERSE_ID,
        "case_count": len(cases),
        "old_r01_r04_diagnostic_only": True,
        "old_v2_six_row_diagnostic_only": True,
        "candidate_generation_authorized": False,
        "shadow_screen_authorized": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["validation_contract"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_new_blind_input_universe_validation_contract.v1",
            rows=validation_rows,
            extra={
                **common_extra,
                "contract_id": "B04_R6_NEW_BLIND_INPUT_UNIVERSE_VALIDATION",
                "validation_object": "B04 R6 new blind input universe contract",
                "input_bindings": _input_hashes(root),
                "reason_code_catalog": REASON_CODES,
                "hard_prohibitions": FORBIDDEN_CLAIMS,
            },
        ),
        OUTPUTS["validation_receipt"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_new_blind_input_universe_validation_receipt.v1",
            rows=validation_rows,
            extra={**common_extra, "verdict": SELECTED_OUTCOME},
        ),
        OUTPUTS["case_manifest_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_case_manifest_validation_receipt.v1",
            rows=case_rows,
            extra={**common_extra, "case_manifest_sha256": payloads["case_manifest"].get("case_manifest_sha256")},
        ),
        OUTPUTS["holdout_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_holdout_validation_receipt.v1",
            rows=holdout_rows,
            extra={**common_extra, "holdout_status": "LOCKED"},
        ),
        OUTPUTS["leakage_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_leakage_validation_receipt.v1",
            rows=leakage_rows,
            extra={**common_extra, "leakage_guard_status": "PASS"},
        ),
        OUTPUTS["control_sibling_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_control_sibling_validation_receipt.v1",
            rows=control_rows,
            extra={**common_extra, "control_sibling_status": "PASS"},
        ),
        OUTPUTS["diagnostic_only_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_diagnostic_only_validation_receipt.v1",
            rows=leakage_rows[:1],
            extra={
                **common_extra,
                "r01_r04_reuse_as_counted_proof_allowed": False,
                "six_row_v2_reuse_as_counted_proof_allowed": False,
            },
        ),
        OUTPUTS["trust_zone_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_trust_zone_validation_receipt.v1",
            rows=trust_rows,
            extra={**common_extra, "fresh_trust_zone_validation": fresh_trust_validation},
        ),
        OUTPUTS["no_authorization_drift"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_no_authorization_drift_receipt.v1",
            rows=auth_rows,
            extra={**common_extra, "no_downstream_authority_drift": True},
        ),
        OUTPUTS["replay_validation"]: _artifact_payload(
            base=base,
            schema_id="kt.operator.b04_r6_blind_universe_replay_validation_receipt.v1",
            rows=replay_rows,
            extra={**common_extra, "replay_binding_status": "PASS"},
        ),
        OUTPUTS["next_lawful_move"]: {
            "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v5",
            **base,
            **common_extra,
            "verdict": SELECTED_OUTCOME,
            "allowed_outcomes": [OUTCOME_VALIDATED, OUTCOME_DEFERRED, OUTCOME_INVALID],
        },
        OUTPUTS["validation_report"]: _report(validation_rows),
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "case_count": len(cases)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate B04 R6 new blind input universe contract.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
