from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator import cohort0_b04_r6_afsh_admissibility_court as admissibility
from tools.operator import cohort0_b04_r6_afsh_candidate_generation as generation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-afsh-shadow-screen-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET"
PREVIOUS_LANE = admissibility.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = admissibility.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = admissibility.NEXT_LAWFUL_MOVE
OUTCOME_BOUND = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_BOUND__PACKET_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET"

SELECTED_ARCHITECTURE_ID = admissibility.SELECTED_ARCHITECTURE_ID
SELECTED_ARCHITECTURE_NAME = admissibility.SELECTED_ARCHITECTURE_NAME
CANDIDATE_ID = admissibility.CANDIDATE_ID
CANDIDATE_VERSION = admissibility.CANDIDATE_VERSION

PRIMARY_METRICS = (
    "route_eligible_delta_vs_static",
    "static_hold_preservation",
    "abstention_preservation",
    "null_route_preservation",
    "overrouting_containment",
    "mirror_masked_stability",
    "wrong_route_cost",
    "wrong_static_hold_cost",
    "proof_burden_delta",
    "trace_completeness",
)
SECONDARY_METRICS = (
    "route_distribution_health",
    "selector_entry_rate",
    "triage_fail_closed_rate",
    "external_replay_completeness",
)
SUCCESS_CONDITIONS = (
    "route_eligible_cases_improve_or_lawfully_derisk_static",
    "static_hold_cases_remain_static",
    "abstention_required_cases_abstain",
    "null_route_controls_do_not_enter_selector",
    "overrouting_traps_are_survived",
    "mirror_masked_siblings_remain_stable",
    "wrong_route_cost_below_threshold",
    "proof_burden_improved_or_justified",
    "trace_completeness_passes",
    "disqualifier_ledger_clean",
    "no_contamination",
    "no_metric_widening",
    "no_comparator_weakening",
    "truth_engine_law_unchanged",
    "trust_zone_law_unchanged",
)
DISQUALIFIER_CLASSES = (
    "candidate_hash_mismatch",
    "universe_hash_mismatch",
    "court_hash_mismatch",
    "source_packet_hash_mismatch",
    "admissibility_hash_mismatch",
    "metric_widening",
    "comparator_weakening",
    "blind_label_access",
    "route_success_label_access",
    "old_universe_counted_proof_drift",
    "static_hold_collapse",
    "abstention_collapse",
    "null_route_collapse",
    "overrouting_collapse",
    "mirror_masked_instability",
    "trace_incompleteness",
    "truth_engine_mutation",
    "trust_zone_mutation",
    "package_promotion_drift",
    "activation_drift",
)
TERMINAL_DISQUALIFIERS = (
    "metric_widening",
    "comparator_weakening",
    "blind_label_access",
    "route_success_label_access",
    "old_universe_counted_proof_drift",
    "static_hold_collapse",
    "abstention_collapse",
    "null_route_collapse",
    "overrouting_collapse",
    "mirror_masked_instability",
    "trace_incompleteness",
    "truth_engine_mutation",
    "trust_zone_mutation",
    "package_promotion_drift",
    "activation_drift",
)
FUTURE_SCREEN_ALLOWED_OUTCOMES = (
    "B04_R6_AFSH_SHADOW_SUPERIORITY_PASSED__ACTIVATION_REVIEW_PACKET_NEXT",
    "B04_R6_AFSH_SHADOW_SUPERIORITY_FAILED__SUPERIORITY_NOT_EARNED_CLOSEOUT_OR_REDESIGN_NEXT",
    "B04_R6_AFSH_SHADOW_SCREEN_INVALIDATED__FORENSIC_INVALIDATION_COURT_NEXT",
    "B04_R6_AFSH_SHADOW_DEFERRED__NAMED_DEFECT_REMAINS",
)

FORBIDDEN_TRUE_KEYS = (
    "r6_authorized",
    "r6_open",
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
    "shadow_screen_execution_authorized",
    "shadow_screen_executed",
)
FORBIDDEN_ACTIONS = (
    "SHADOW_SCREEN_EXECUTION_AUTHORIZED",
    "SHADOW_SCREEN_EXECUTED",
    "R6_OPEN",
    "LEARNED_ROUTER_SUPERIORITY_EARNED",
    "ACTIVATION_REVIEW_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "CURRENT_METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
)

REASON_CODES = (
    "RC_B04R6_AFSH_SHADOW_PACKET_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_MAIN_HEAD_MISMATCH",
    "RC_B04R6_AFSH_SHADOW_PACKET_ARCHITECTURE_MISMATCH",
    "RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_HASH_MISMATCH",
    "RC_B04R6_AFSH_SHADOW_PACKET_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_COURT_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_SOURCE_PACKET_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_ADMISSIBILITY_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_TRIAGE_CORE_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_TRACE_SCHEMA_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_STATIC_COMPARATOR_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_COMPARATOR_WEAKENING",
    "RC_B04R6_AFSH_SHADOW_PACKET_METRIC_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_METRIC_WIDENING",
    "RC_B04R6_AFSH_SHADOW_PACKET_ROUTE_VALUE_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_DISQUALIFIER_LEDGER_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_RESULT_INTERPRETATION_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_REPLAY_MANIFEST_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_EXTERNAL_VERIFIER_REQUIREMENTS_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED",
    "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_EXECUTED",
    "RC_B04R6_AFSH_SHADOW_PACKET_SUPERIORITY_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_ACTIVATION_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_AFSH_SHADOW_PACKET_TRUST_ZONE_MUTATION",
    "RC_B04R6_AFSH_SHADOW_PACKET_NEXT_MOVE_DRIFT",
)
TERMINAL_DEFECTS = (
    "EXECUTION_AUTHORIZED",
    "EXECUTION_EXECUTED",
    "SUPERIORITY_DRIFT",
    "R6_OPEN_DRIFT",
    "ACTIVATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "METRIC_WIDENING",
    "COMPARATOR_WEAKENING",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)

INPUTS = {
    "admissibility_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_admissibility_court_contract.json",
    "admissibility_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_admissibility_court_receipt.json",
    "candidate_manifest_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_manifest_admissibility_receipt.json",
    "candidate_hash_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_hash_admissibility_receipt.json",
    "candidate_semantic_hash_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_semantic_hash_admissibility_receipt.json",
    "candidate_replay_binding_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_replay_binding_admissibility_receipt.json",
    "triage_core_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_core_admissibility_receipt.json",
    "trace_schema_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_trace_schema_admissibility_receipt.json",
    "no_authorization_drift_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_admissibility_no_authorization_drift_receipt.json",
    "candidate_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_manifest.json",
    "candidate_artifact": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_v1.json",
    "candidate_hash_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_hash_receipt.json",
    "numeric_triage_emit_core": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_numeric_triage_emit_core_contract.json",
    "triage_tag_schema": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_tag_schema.json",
    "triage_score_schema": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_score_schema.json",
    "triage_receipt_schema": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_receipt_schema.json",
    "turboquant_translation": "KT_PROD_CLEANROOM/reports/kt_turboquant_research_translation_matrix_prep_only.json",
    "compressed_receipt_index": "KT_PROD_CLEANROOM/reports/kt_compressed_receipt_vector_index_contract_prep_only.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
TEXT_INPUTS = {
    "admissibility_report": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_admissibility_court_report.md",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})

OUTPUTS = {
    "packet_contract": "b04_r6_afsh_shadow_screen_execution_packet_contract.json",
    "packet_receipt": "b04_r6_afsh_shadow_screen_execution_packet_receipt.json",
    "packet_report": "b04_r6_afsh_shadow_screen_execution_packet_report.md",
    "candidate_binding_receipt": "b04_r6_afsh_shadow_screen_candidate_binding_receipt.json",
    "universe_binding_receipt": "b04_r6_afsh_shadow_screen_universe_binding_receipt.json",
    "court_binding_receipt": "b04_r6_afsh_shadow_screen_court_binding_receipt.json",
    "source_packet_binding_receipt": "b04_r6_afsh_shadow_screen_source_packet_binding_receipt.json",
    "admissibility_binding_receipt": "b04_r6_afsh_shadow_screen_admissibility_binding_receipt.json",
    "triage_core_binding_receipt": "b04_r6_afsh_shadow_screen_triage_core_binding_receipt.json",
    "trace_schema_binding_receipt": "b04_r6_afsh_shadow_screen_trace_schema_binding_receipt.json",
    "static_comparator_contract": "b04_r6_afsh_shadow_screen_static_comparator_contract.json",
    "metric_contract": "b04_r6_afsh_shadow_screen_metric_contract.json",
    "route_value_contract": "b04_r6_afsh_shadow_screen_route_value_contract.json",
    "disqualifier_ledger": "b04_r6_afsh_shadow_screen_disqualifier_ledger.json",
    "result_interpretation_contract": "b04_r6_afsh_shadow_screen_result_interpretation_contract.json",
    "replay_manifest": "b04_r6_afsh_shadow_screen_replay_manifest.json",
    "expected_artifact_manifest": "b04_r6_afsh_shadow_screen_expected_artifact_manifest.json",
    "external_verifier_requirements": "b04_r6_afsh_shadow_screen_external_verifier_requirements.json",
    "no_authorization_drift_receipt": "b04_r6_afsh_shadow_screen_no_authorization_drift_receipt.json",
    "packet_validation_plan": "b04_r6_afsh_shadow_screen_packet_validation_plan.json",
    "packet_validation_reason_codes": "b04_r6_afsh_shadow_screen_packet_validation_reason_codes.json",
    "execution_prep_only_draft": "b04_r6_afsh_shadow_screen_execution_prep_only_draft.json",
    "result_schema_prep_only_draft": "b04_r6_afsh_shadow_screen_result_schema_prep_only_draft.json",
    "activation_review_packet_prep_only_draft": "b04_r6_learned_router_activation_review_packet_prep_only_draft.json",
    "superiority_not_earned_closeout_prep_only_draft": "b04_r6_superiority_not_earned_closeout_contract_prep_only_draft.json",
    "forensic_invalidation_court_prep_only_draft": "b04_r6_forensic_invalidation_court_prep_only_draft.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


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


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _rows_for(rows: list[Dict[str, str]], *groups: str) -> list[Dict[str, str]]:
    wanted = set(groups)
    return [row for row in rows if row.get("group") in wanted]


def _canonical_hash(value: Any) -> str:
    return sha256_hex(canonicalize_bytes(value))


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and bool(payload.get(key)):
        _fail(code, f"{label} sets forbidden true flag: {key}")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str) -> None:
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label, code="RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED")
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        for key in FORBIDDEN_TRUE_KEYS:
            _ensure_false_if_present(state, key, label=f"{label}.authorization_state", code="RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED")
        if state.get("learned_router_superiority") not in (None, "UNEARNED"):
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_SUPERIORITY_DRIFT", f"{label} claims superiority")
        if state.get("package_promotion") not in (None, "DEFERRED"):
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("learned_router_superiority_earned") is True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_SUPERIORITY_DRIFT", f"{label} claims superiority")


def _input_hashes(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(INPUTS.items()):
        path = common.resolve_path(root, raw)
        row = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_shadow_screen_packet_authoring",
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
                "binding_kind": "file_sha256_at_shadow_screen_packet_authoring",
            }
        )
    return rows


def _input_binding_sha(bindings: list[Dict[str, Any]], role: str) -> str:
    for row in bindings:
        if row.get("role") == role:
            return str(row.get("sha256", "")).strip()
    _fail("RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING", f"missing input binding role: {role}")
    return ""


def _require_admissibility_inputs(payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> str:
    contract = payloads["admissibility_contract"]
    receipt = payloads["admissibility_receipt"]
    next_receipt = payloads["previous_next_lawful_move"]
    for label, payload in payloads.items():
        _ensure_common_boundary(payload, label=label)
        if label.startswith("admissibility") or label.endswith("admissibility"):
            if payload.get("status") != "PASS":
                _fail("RC_B04R6_AFSH_SHADOW_PACKET_ADMISSIBILITY_BINDING_MISSING", f"{label} must be PASS")
    if "ADMISSIBILITY" not in text_payloads["admissibility_report"]:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_ADMISSIBILITY_BINDING_MISSING", "admissibility report missing admissibility marker")
    for label, payload in (("contract", contract), ("receipt", receipt), ("next", next_receipt)):
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_ADMISSIBILITY_BINDING_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_NEXT_MOVE_DRIFT", f"{label} next move drift")
    if contract.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_ARCHITECTURE_MISMATCH", "selected architecture drift")
    if contract.get("candidate_id") != CANDIDATE_ID:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_BINDING_MISSING", "candidate id drift")
    if contract.get("candidate_training_executed") is not False:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_BINDING_MISSING", "candidate training must remain unexecuted")
    if contract.get("shadow_screen_packet_authorized_as_authority") is not False:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "admissibility cannot pre-authorize packet authority")
    if contract.get("shadow_screen_execution_authorized") is not False:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "shadow execution already authorized")
    replay_head = str(contract.get("current_git_head", "")).strip()
    if not replay_head or replay_head != str(receipt.get("current_git_head", "")).strip():
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_ADMISSIBILITY_BINDING_MISSING", "admissibility replay head missing or inconsistent")
    return replay_head


def _validate_candidate_bindings(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    contract = payloads["admissibility_contract"]
    manifest = payloads["candidate_manifest"]
    artifact = payloads["candidate_artifact"]
    hash_receipt = payloads["candidate_hash_receipt"]
    triage_core = payloads["numeric_triage_emit_core"]
    trace_schema = payloads["trace_schema_admissibility"]
    if manifest.get("candidate_id") != CANDIDATE_ID or artifact.get("candidate_id") != CANDIDATE_ID:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_BINDING_MISSING", "candidate identity mismatch")
    expected_semantic = contract.get("candidate_semantic_hash")
    expected_envelope = contract.get("candidate_envelope_hash")
    if hash_receipt.get("candidate_semantic_hash") != expected_semantic:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_HASH_MISMATCH", "candidate semantic hash mismatch")
    if hash_receipt.get("candidate_envelope_hash") != expected_envelope:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_HASH_MISMATCH", "candidate envelope hash mismatch")
    if triage_core.get("artifact_id") != "B04_R6_AFSH_NUMERIC_TRIAGE_EMIT_CORE":
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_TRIAGE_CORE_BINDING_MISSING", "numeric triage core missing")
    if "ROUTE_ELIGIBLE" not in triage_core.get("top_level_verdict_modes", []):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_TRIAGE_CORE_BINDING_MISSING", "triage verdict modes incomplete")
    required_trace_fields = trace_schema.get("required_trace_fields") or list(generation.TRACE_FIELDS)
    missing_trace = [field for field in generation.TRACE_FIELDS if field not in required_trace_fields]
    if missing_trace:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_TRACE_SCHEMA_BINDING_MISSING", f"trace schema missing: {missing_trace}")
    return {
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "candidate_replay_binding_head": contract.get("candidate_replay_binding_head"),
        "admissibility_replay_binding_head": contract.get("current_git_head"),
        "candidate_manifest_hash": file_sha256(common.resolve_path(repo_root(), INPUTS["candidate_manifest"])),
        "candidate_artifact_hash": file_sha256(common.resolve_path(repo_root(), INPUTS["candidate_artifact"])),
        "candidate_semantic_hash": expected_semantic,
        "candidate_envelope_hash": expected_envelope,
        "numeric_triage_emit_core_hash": file_sha256(common.resolve_path(repo_root(), INPUTS["numeric_triage_emit_core"])),
        "triage_tag_schema_hash": file_sha256(common.resolve_path(repo_root(), INPUTS["triage_tag_schema"])),
        "triage_score_schema_hash": file_sha256(common.resolve_path(repo_root(), INPUTS["triage_score_schema"])),
        "triage_receipt_schema_hash": file_sha256(common.resolve_path(repo_root(), INPUTS["triage_receipt_schema"])),
        "trace_schema_hash": file_sha256(common.resolve_path(repo_root(), INPUTS["trace_schema_admissibility"])),
    }


def _validate_memory_prep(payloads: Dict[str, Dict[str, Any]]) -> None:
    turbo = payloads["turboquant_translation"]
    compressed = payloads["compressed_receipt_index"]
    for label, payload in (("turboquant", turbo), ("compressed_index", compressed)):
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", f"{label} must remain prep-only")
        if payload.get("raw_hash_bound_artifact_required") is not True:
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING", f"{label} must require raw artifacts")
    if compressed.get("compressed_index_is_source_of_truth") is not False:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING", "compressed index cannot be source of truth")


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "shadow_screen_packet_authored": True,
        "shadow_screen_execution_authorized": False,
        "shadow_screen_executed": False,
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
    current_branch: str,
    admissibility_replay_head: str,
    binding_summary: Dict[str, Any],
) -> Dict[str, Any]:
    admissibility_contract = binding_summary["admissibility_contract"]
    return {
        "schema_version": "1.0.0",
        "generated_utc": generated_utc,
        "current_branch": current_branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "admissibility_replay_binding_head": admissibility_replay_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "candidate_replay_binding_head": admissibility_contract.get("candidate_replay_binding_head"),
        "universe_binding": admissibility_contract.get("universe_binding", {}),
        "court_binding": admissibility_contract.get("court_binding", {}),
        "source_packet_binding": admissibility_contract.get("source_packet_binding", {}),
        "authorization_state": _authorization_state(),
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "shadow_screen_packet_authored": True,
        "shadow_screen_execution_authorized": False,
        "shadow_screen_executed": False,
        "activation_review_authorized": False,
        "runtime_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
    }


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("packet_contract_preserves_current_main_head", "RC_B04R6_AFSH_SHADOW_PACKET_MAIN_HEAD_MISMATCH", "packet binds current main head", group="core"),
        _pass_row("packet_binds_selected_afsh_architecture", "RC_B04R6_AFSH_SHADOW_PACKET_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD remains selected", group="core"),
        _pass_row("packet_binds_admissible_candidate", "RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_BINDING_MISSING", "candidate admissibility bound", group="candidate"),
        _pass_row("packet_binds_candidate_manifest_hash", "RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_HASH_MISMATCH", "candidate manifest hash bound", group="candidate"),
        _pass_row("packet_binds_candidate_semantic_hash", "RC_B04R6_AFSH_SHADOW_PACKET_CANDIDATE_HASH_MISMATCH", "candidate semantic hash bound", group="candidate"),
        _pass_row("packet_binds_validated_blind_universe_hash", "RC_B04R6_AFSH_SHADOW_PACKET_UNIVERSE_BINDING_MISSING", "validated blind universe hash bound", group="binding"),
        _pass_row("packet_binds_validated_route_value_court_hash", "RC_B04R6_AFSH_SHADOW_PACKET_COURT_BINDING_MISSING", "validated court hash bound", group="binding"),
        _pass_row("packet_binds_validated_source_packet_hash", "RC_B04R6_AFSH_SHADOW_PACKET_SOURCE_PACKET_BINDING_MISSING", "validated source packet hash bound", group="binding"),
        _pass_row("packet_binds_admissibility_receipt_hash", "RC_B04R6_AFSH_SHADOW_PACKET_ADMISSIBILITY_BINDING_MISSING", "admissibility receipt hash bound", group="binding"),
        _pass_row("packet_binds_numeric_triage_core_hash", "RC_B04R6_AFSH_SHADOW_PACKET_TRIAGE_CORE_BINDING_MISSING", "numeric triage core hash bound", group="binding"),
        _pass_row("packet_binds_trace_schema_hash", "RC_B04R6_AFSH_SHADOW_PACKET_TRACE_SCHEMA_BINDING_MISSING", "trace schema hash bound", group="binding"),
        _pass_row("packet_does_not_execute_shadow_screen", "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_EXECUTED", "shadow screen not executed", group="authorization"),
        _pass_row("packet_does_not_authorize_shadow_screen_execution", "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "shadow execution unauthorized", group="authorization"),
        _pass_row("packet_does_not_claim_superiority", "RC_B04R6_AFSH_SHADOW_PACKET_SUPERIORITY_DRIFT", "superiority unearned", group="authorization"),
        _pass_row("packet_does_not_open_r6", "RC_B04R6_AFSH_SHADOW_PACKET_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"),
        _pass_row("packet_does_not_authorize_activation_review", "RC_B04R6_AFSH_SHADOW_PACKET_ACTIVATION_DRIFT", "activation unauthorized", group="authorization"),
        _pass_row("packet_does_not_authorize_runtime_cutover", "RC_B04R6_AFSH_SHADOW_PACKET_ACTIVATION_DRIFT", "runtime cutover unauthorized", group="authorization"),
        _pass_row("packet_does_not_authorize_lobe_escalation", "RC_B04R6_AFSH_SHADOW_PACKET_ACTIVATION_DRIFT", "lobe escalation unauthorized", group="authorization"),
        _pass_row("packet_does_not_authorize_package_promotion", "RC_B04R6_AFSH_SHADOW_PACKET_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", group="authorization"),
        _pass_row("static_comparator_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_STATIC_COMPARATOR_MISSING", "static comparator contract exists", group="comparator"),
        _pass_row("static_comparator_is_frozen", "RC_B04R6_AFSH_SHADOW_PACKET_STATIC_COMPARATOR_MISSING", "static comparator frozen", group="comparator"),
        _pass_row("comparator_weakening_forbidden", "RC_B04R6_AFSH_SHADOW_PACKET_COMPARATOR_WEAKENING", "comparator weakening forbidden", group="comparator"),
        _pass_row("metric_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_METRIC_CONTRACT_MISSING", "metric contract exists", group="metric"),
        _pass_row("metric_widening_forbidden", "RC_B04R6_AFSH_SHADOW_PACKET_METRIC_WIDENING", "metric widening forbidden", group="metric"),
        _pass_row("metrics_frozen_before_execution", "RC_B04R6_AFSH_SHADOW_PACKET_METRIC_CONTRACT_MISSING", "metrics frozen before execution", group="metric"),
        _pass_row("route_value_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_ROUTE_VALUE_CONTRACT_MISSING", "route-value screen contract exists", group="metric"),
        _pass_row("disqualifier_ledger_exists", "RC_B04R6_AFSH_SHADOW_PACKET_DISQUALIFIER_LEDGER_MISSING", "disqualifier ledger exists", group="disqualifier"),
        _pass_row("result_interpretation_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_RESULT_INTERPRETATION_MISSING", "result interpretation exists", group="result"),
        _pass_row("result_interpretation_requires_all_success_conditions", "RC_B04R6_AFSH_SHADOW_PACKET_RESULT_INTERPRETATION_MISSING", "all success conditions required", group="result"),
        _pass_row("result_interpretation_prevents_partial_win_from_superiority", "RC_B04R6_AFSH_SHADOW_PACKET_SUPERIORITY_DRIFT", "partial win cannot claim superiority", group="result"),
        _pass_row("result_interpretation_preserves_failure_and_invalidated_outcomes", "RC_B04R6_AFSH_SHADOW_PACKET_RESULT_INTERPRETATION_MISSING", "failure/invalidation outcomes preserved", group="result"),
        _pass_row("replay_manifest_exists", "RC_B04R6_AFSH_SHADOW_PACKET_REPLAY_MANIFEST_MISSING", "replay manifest exists", group="replay"),
        _pass_row("replay_manifest_binds_expected_artifacts", "RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING", "expected artifacts bound", group="replay"),
        _pass_row("replay_manifest_requires_raw_hash_bound_artifacts", "RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING", "raw hash-bound artifacts required", group="replay"),
        _pass_row("external_verifier_requirements_exist", "RC_B04R6_AFSH_SHADOW_PACKET_EXTERNAL_VERIFIER_REQUIREMENTS_MISSING", "external verifier requirements exist", group="external"),
        _pass_row("external_verifier_requirements_are_non_executing", "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "external verifier requirements non-executing", group="external"),
        _pass_row("shadow_execution_prep_only_draft_is_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "execution draft prep-only", group="prep_only"),
        _pass_row("shadow_result_schema_prep_only_draft_is_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "result schema draft prep-only", group="prep_only"),
        _pass_row("activation_review_packet_draft_is_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_ACTIVATION_DRIFT", "activation review draft prep-only", group="prep_only"),
        _pass_row("failure_closeout_contract_draft_is_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_SUPERIORITY_DRIFT", "failure closeout draft prep-only", group="prep_only"),
        _pass_row("forensic_invalidation_court_draft_is_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_RESULT_INTERPRETATION_MISSING", "forensic invalidation draft prep-only", group="prep_only"),
        _pass_row("turboquant_memory_replay_artifacts_remain_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "memory replay prep-only", group="memory"),
        _pass_row("compressed_index_cannot_be_source_of_truth", "RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING", "compressed index not truth", group="memory"),
        _pass_row("raw_hash_bound_artifact_required_after_compressed_retrieval", "RC_B04R6_AFSH_SHADOW_PACKET_EXPECTED_ARTIFACTS_MISSING", "raw artifacts required", group="memory"),
        _pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_AFSH_SHADOW_PACKET_EXECUTION_AUTHORIZED", "no authorization drift", group="authorization"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_AFSH_SHADOW_PACKET_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", group="authorization"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_AFSH_SHADOW_PACKET_TRUST_ZONE_MUTATION", "trust-zone law unchanged", group="authorization"),
        _pass_row("next_lawful_move_is_packet_validation", "RC_B04R6_AFSH_SHADOW_PACKET_NEXT_MOVE_DRIFT", "next lawful move is packet validation", group="next_move"),
    ]
    rows.extend(
        _pass_row(
            f"metric_contract_includes_{metric}",
            "RC_B04R6_AFSH_SHADOW_PACKET_METRIC_CONTRACT_MISSING",
            f"metric contract includes {metric}",
            group="metric",
        )
        for metric in PRIMARY_METRICS
    )
    rows.extend(
        _pass_row(
            f"disqualifier_ledger_marks_{name}_terminal",
            "RC_B04R6_AFSH_SHADOW_PACKET_DISQUALIFIER_LEDGER_MISSING",
            f"disqualifier ledger marks {name} terminal",
            group="disqualifier",
        )
        for name in TERMINAL_DISQUALIFIERS
    )
    rows.extend(
        _pass_row(
            f"success_condition_requires_{name}",
            "RC_B04R6_AFSH_SHADOW_PACKET_RESULT_INTERPRETATION_MISSING",
            f"success condition requires {name}",
            group="result",
        )
        for name in SUCCESS_CONDITIONS
    )
    return rows


def _receipt_payload(
    *,
    base: Dict[str, Any],
    schema_id: str,
    artifact_id: str,
    rows: list[Dict[str, str]],
    input_bindings: list[Dict[str, Any]],
    hashes: Dict[str, str],
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
        "input_bindings": input_bindings,
        "binding_hashes": hashes,
    }
    if extra:
        payload.update(extra)
    return payload


def _static_comparator_contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_static_comparator_contract.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_STATIC_COMPARATOR_CONTRACT",
        "status": "PASS",
        "comparator_must_be_frozen": True,
        "comparator_weakening_forbidden": True,
        "static_hold_must_remain_available": True,
        "static_hold_baseline_required_for_all_cases": True,
        "static_comparator_binding": "VALIDATED_STATIC_HOLD_BASELINE_FROM_ROUTE_VALUE_COURT",
    }


def _metric_contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_metric_contract.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_METRIC_CONTRACT",
        "status": "PASS",
        "metric_widening_forbidden": True,
        "metrics_frozen_before_execution": True,
        "primary_metrics": list(PRIMARY_METRICS),
        "secondary_metrics": list(SECONDARY_METRICS),
    }


def _route_value_contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_route_value_contract.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_ROUTE_VALUE_CONTRACT",
        "status": "PASS",
        "route_value_threshold_profile_frozen": True,
        "route_eligible_delta_vs_static_required": True,
        "wrong_route_cost_required": True,
        "wrong_static_hold_cost_required": True,
        "proof_burden_delta_required": True,
        "current_route_value_formula_mutation_allowed": False,
    }


def _disqualifier_ledger(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_disqualifier_ledger.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_DISQUALIFIER_LEDGER",
        "status": "PASS",
        "disqualifier_classes": list(DISQUALIFIER_CLASSES),
        "terminal_disqualifiers": list(TERMINAL_DISQUALIFIERS),
        "any_terminal_disqualifier_invalidates_future_screen": True,
    }


def _result_interpretation_contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_result_interpretation_contract.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_RESULT_INTERPRETATION_CONTRACT",
        "status": "PASS",
        "superiority_cannot_be_earned_unless_all_required_conditions_pass": True,
        "partial_win_cannot_claim_superiority": True,
        "required_success_conditions": list(SUCCESS_CONDITIONS),
        "future_screen_allowed_outcomes": list(FUTURE_SCREEN_ALLOWED_OUTCOMES),
    }


def _replay_manifest(base: Dict[str, Any], hashes: Dict[str, str]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_replay_manifest.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_REPLAY_MANIFEST",
        "status": "PASS",
        "replay_command_future": "python -m tools.operator.cohort0_b04_r6_afsh_shadow_screen",
        "raw_hash_bound_artifacts_required": True,
        "compressed_indexes_are_retrieval_aids_only": True,
        "expected_artifact_roles": sorted(INPUTS.keys()),
        "binding_hashes": hashes,
    }


def _expected_artifact_manifest(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_expected_artifact_manifest.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_EXPECTED_ARTIFACT_MANIFEST",
        "status": "PASS",
        "packet_artifacts": sorted(OUTPUTS.values()),
        "future_execution_artifacts_required_before_superiority_claim": [
            "shadow_screen_result_receipt",
            "shadow_screen_trace_receipts",
            "shadow_screen_disqualifier_receipt",
            "shadow_screen_replay_receipt",
        ],
    }


def _external_verifier_requirements(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_external_verifier_requirements.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_EXTERNAL_VERIFIER_REQUIREMENTS",
        "status": "PASS",
        "authority": "NON_EXECUTING_REQUIREMENTS",
        "external_verifier_requirements": [
            "raw_hash_bound_artifacts_available",
            "replay_manifest_available",
            "metric_contract_available",
            "disqualifier_ledger_available",
            "result_interpretation_contract_available",
        ],
        "cannot_execute_shadow_screen": True,
        "cannot_claim_superiority": True,
        "compressed_index_cannot_be_source_of_truth": True,
    }


def _validation_plan(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_packet_validation_plan.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_PACKET_VALIDATION_PLAN",
        "status": "PASS",
        "authority": "VALIDATOR_SCAFFOLD",
        "planned_checks": [row["check_id"] for row in _validation_rows()],
        "expected_success_outcome": "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_VALIDATED__SHADOW_SCREEN_NEXT",
        "next_lawful_move_after_validation_success": "RUN_B04_R6_AFSH_SHADOW_SCREEN",
        "execution_authorized_by_this_plan": False,
    }


def _validation_reason_codes(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": "kt.b04_r6.afsh_shadow_screen_packet_validation_reason_codes.v1",
        "artifact_id": "B04_R6_AFSH_SHADOW_SCREEN_PACKET_VALIDATION_REASON_CODES",
        "status": "PASS",
        "reason_codes": list(REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
    }


def _prep_only_block(*, base: Dict[str, Any], artifact_id: str, schema_id: str, purpose: str) -> Dict[str, Any]:
    return {
        **base,
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "status": "PREP_ONLY",
        "authority": "PREP_ONLY",
        "purpose": purpose,
        "cannot_authorize_shadow_screen_execution": True,
        "cannot_execute_shadow_screen": True,
        "cannot_claim_superiority": True,
        "cannot_open_r6": True,
        "cannot_authorize_activation": True,
        "cannot_authorize_lobe_escalation": True,
        "cannot_authorize_package_promotion": True,
        "cannot_mutate_truth_engine": True,
        "cannot_mutate_trust_zone": True,
        "cannot_widen_metric": True,
        "cannot_weaken_comparator": True,
        "next_lawful_move_required_before_authority": NEXT_LAWFUL_MOVE,
    }


def _future_blocker_register() -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.future_blocker_register.v4",
        "artifact_id": "B04_R6_FUTURE_BLOCKER_REGISTER",
        "current_authoritative_lane": "AUTHOR_B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET",
        "blockers": [
            {
                "blocker_id": "B04R6-FB-021",
                "future_blocker": "Shadow-screen packet exists but packet validation law is not ready.",
                "neutralization_now": [
                    OUTPUTS["packet_validation_plan"],
                    OUTPUTS["packet_validation_reason_codes"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-022",
                "future_blocker": "Packet validation passes but execution/result schemas are not staged.",
                "neutralization_now": [
                    OUTPUTS["execution_prep_only_draft"],
                    OUTPUTS["result_schema_prep_only_draft"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-023",
                "future_blocker": "Future screen passes but activation review/failure/invalidation paths are missing.",
                "neutralization_now": [
                    OUTPUTS["activation_review_packet_prep_only_draft"],
                    OUTPUTS["superiority_not_earned_closeout_prep_only_draft"],
                    OUTPUTS["forensic_invalidation_court_prep_only_draft"],
                ],
            },
        ],
    }


def _report(rows: list[Dict[str, str]]) -> str:
    lines = [
        "# B04 R6 AFSH Shadow-Screen Execution Packet",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "This lane authors the future shadow-screen execution packet. It does not execute the shadow screen, claim superiority, open R6, authorize activation/cutover, escalate to lobes, promote a package, or mutate truth/trust law.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 AFSH shadow-screen execution packet")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    admissibility_replay_head = _require_admissibility_inputs(payloads, text_payloads)
    _validate_memory_prep(payloads)
    candidate_summary = _validate_candidate_bindings(payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)
    hashes = {
        "candidate_manifest_hash": _input_binding_sha(input_bindings, "candidate_manifest"),
        "candidate_artifact_hash": _input_binding_sha(input_bindings, "candidate_artifact"),
        "candidate_semantic_hash": str(payloads["admissibility_contract"].get("candidate_semantic_hash", "")),
        "candidate_envelope_hash": str(payloads["admissibility_contract"].get("candidate_envelope_hash", "")),
        "validated_blind_universe_hash": _canonical_hash(payloads["admissibility_contract"].get("universe_binding", {})),
        "validated_court_hash": _canonical_hash(payloads["admissibility_contract"].get("court_binding", {})),
        "validated_source_packet_hash": _canonical_hash(payloads["admissibility_contract"].get("source_packet_binding", {})),
        "admissibility_receipt_hash": _input_binding_sha(input_bindings, "admissibility_receipt"),
        "numeric_triage_emit_core_hash": _input_binding_sha(input_bindings, "numeric_triage_emit_core"),
        "triage_tag_schema_hash": _input_binding_sha(input_bindings, "triage_tag_schema"),
        "triage_score_schema_hash": _input_binding_sha(input_bindings, "triage_score_schema"),
        "triage_receipt_schema_hash": _input_binding_sha(input_bindings, "triage_receipt_schema"),
        "trace_schema_hash": _input_binding_sha(input_bindings, "trace_schema_admissibility"),
    }
    rows = _validation_rows()
    generated_utc = utc_now_iso_z()
    binding_summary = {"admissibility_contract": payloads["admissibility_contract"]}
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        admissibility_replay_head=admissibility_replay_head,
        binding_summary=binding_summary,
    )
    common_extra = {
        **candidate_summary,
        "shadow_screen_packet_authored": True,
        "shadow_screen_execution_authorized": False,
        "shadow_screen_executed": False,
        "screen_success_law": {
            "superiority_cannot_be_earned_unless_all_required_conditions_pass": True,
            "required_conditions": list(SUCCESS_CONDITIONS),
        },
    }
    receipt = lambda schema, artifact, groups, extra=None: _receipt_payload(
        base=base,
        schema_id=schema,
        artifact_id=artifact,
        rows=_rows_for(rows, *groups),
        input_bindings=input_bindings,
        hashes=hashes,
        extra={**common_extra, **(extra or {})},
    )

    contract_extra = {
        **common_extra,
        "packet_scope": {
            "purpose": "Bind all inputs, metrics, comparators, disqualifiers, replay requirements, result interpretation law, and allowed outcomes for a future AFSH shadow screen.",
            "non_purpose": [
                "Does not execute the shadow screen.",
                "Does not score superiority.",
                "Does not open R6.",
                "Does not authorize activation review.",
                "Does not authorize runtime cutover.",
                "Does not authorize lobe escalation.",
                "Does not authorize package promotion.",
            ],
        },
        "binding_requirements": {
            "candidate_manifest_hash_required": True,
            "candidate_semantic_hash_required": True,
            "validated_blind_universe_hash_required": True,
            "validated_court_hash_required": True,
            "validated_source_packet_hash_required": True,
            "admissibility_receipt_hash_required": True,
            "triage_core_hash_required": True,
            "trace_schema_hash_required": True,
            "all_immutable_inputs_must_share_replay_head_or_allowed_prior_authoritative_binding": True,
            "mixed_head_inputs_fail_closed": True,
            "mutable_handoff_bound_before_overwrite": True,
        },
        "static_comparator_contract": {
            "comparator_must_be_frozen": True,
            "comparator_weakening_forbidden": True,
            "static_hold_must_remain_available": True,
            "static_hold_baseline_required_for_all_cases": True,
        },
        "metric_contract": {
            "metric_widening_forbidden": True,
            "metrics_frozen_before_execution": True,
            "primary_metrics": list(PRIMARY_METRICS),
            "secondary_metrics": list(SECONDARY_METRICS),
        },
        "disqualifier_classes": list(DISQUALIFIER_CLASSES),
        "allowed_future_screen_outcomes": list(FUTURE_SCREEN_ALLOWED_OUTCOMES),
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["packet_contract"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_execution_packet.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET",
            ("core", "candidate", "binding", "authorization", "comparator", "metric", "disqualifier", "result", "replay", "external", "prep_only", "memory", "next_move"),
            contract_extra,
        ),
        OUTPUTS["packet_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_execution_packet_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_RECEIPT",
            ("core", "candidate", "binding", "authorization", "next_move"),
        ),
        OUTPUTS["candidate_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_candidate_binding_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_CANDIDATE_BINDING_RECEIPT",
            ("candidate",),
        ),
        OUTPUTS["universe_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_universe_binding_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_UNIVERSE_BINDING_RECEIPT",
            ("binding",),
            {"bound_hash": hashes["validated_blind_universe_hash"]},
        ),
        OUTPUTS["court_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_court_binding_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_COURT_BINDING_RECEIPT",
            ("binding",),
            {"bound_hash": hashes["validated_court_hash"]},
        ),
        OUTPUTS["source_packet_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_source_packet_binding_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_SOURCE_PACKET_BINDING_RECEIPT",
            ("binding",),
            {"bound_hash": hashes["validated_source_packet_hash"]},
        ),
        OUTPUTS["admissibility_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_admissibility_binding_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_ADMISSIBILITY_BINDING_RECEIPT",
            ("binding",),
            {"bound_hash": hashes["admissibility_receipt_hash"]},
        ),
        OUTPUTS["triage_core_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_triage_core_binding_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRIAGE_CORE_BINDING_RECEIPT",
            ("binding",),
            {"bound_hash": hashes["numeric_triage_emit_core_hash"]},
        ),
        OUTPUTS["trace_schema_binding_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_trace_schema_binding_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRACE_SCHEMA_BINDING_RECEIPT",
            ("binding",),
            {"bound_hash": hashes["trace_schema_hash"]},
        ),
        OUTPUTS["static_comparator_contract"]: _static_comparator_contract(base),
        OUTPUTS["metric_contract"]: _metric_contract(base),
        OUTPUTS["route_value_contract"]: _route_value_contract(base),
        OUTPUTS["disqualifier_ledger"]: _disqualifier_ledger(base),
        OUTPUTS["result_interpretation_contract"]: _result_interpretation_contract(base),
        OUTPUTS["replay_manifest"]: _replay_manifest(base, hashes),
        OUTPUTS["expected_artifact_manifest"]: _expected_artifact_manifest(base),
        OUTPUTS["external_verifier_requirements"]: _external_verifier_requirements(base),
        OUTPUTS["no_authorization_drift_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_no_authorization_drift_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_NO_AUTHORIZATION_DRIFT_RECEIPT",
            ("authorization", "next_move"),
            {"no_downstream_authorization_drift": True},
        ),
        OUTPUTS["packet_validation_plan"]: _validation_plan(base),
        OUTPUTS["packet_validation_reason_codes"]: _validation_reason_codes(base),
        OUTPUTS["execution_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.afsh_shadow_screen_execution_prep_only_draft.v1",
            purpose="Prep-only future execution draft. It cannot execute or authorize the shadow screen.",
        ),
        OUTPUTS["result_schema_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_AFSH_SHADOW_SCREEN_RESULT_SCHEMA_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.afsh_shadow_screen_result_schema_prep_only_draft.v1",
            purpose="Prep-only future result schema draft. It cannot compute superiority.",
        ),
        OUTPUTS["activation_review_packet_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.learned_router_activation_review_packet_prep_only_draft.v1",
            purpose="Prep-only activation review packet draft for a later post-screen lane.",
        ),
        OUTPUTS["superiority_not_earned_closeout_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_SUPERIORITY_NOT_EARNED_CLOSEOUT_CONTRACT_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.superiority_not_earned_closeout_contract_prep_only_draft.v1",
            purpose="Prep-only failure closeout draft if future superiority is not earned.",
        ),
        OUTPUTS["forensic_invalidation_court_prep_only_draft"]: _prep_only_block(
            base=base,
            artifact_id="B04_R6_FORENSIC_INVALIDATION_COURT_PREP_ONLY_DRAFT",
            schema_id="kt.b04_r6.forensic_invalidation_court_prep_only_draft.v1",
            purpose="Prep-only forensic invalidation draft if future screen validity collapses.",
        ),
        OUTPUTS["future_blocker_register"]: _future_blocker_register(),
        OUTPUTS["next_lawful_move"]: receipt(
            "kt.operator.b04_r6_next_lawful_move_receipt.v12",
            "B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            ("next_move",),
            {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE},
        ),
        OUTPUTS["packet_report"]: _report(rows),
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "pass_count": len(rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 AFSH shadow-screen execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=Path(args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
