from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_learned_router_activation_review_packet as packet
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-learned-router-activation-review-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_VALIDATION"
PREVIOUS_LANE = packet.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = packet.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet.NEXT_LAWFUL_MOVE
OUTCOME_VALIDATED = "B04_R6_ACTIVATION_REVIEW_VALIDATED__LIMITED_RUNTIME_AUTHORIZATION_PACKET_NEXT"
OUTCOME_DEFERRED = "B04_R6_ACTIVATION_REVIEW_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_ACTIVATION_REVIEW_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET"

SELECTED_ARCHITECTURE_ID = packet.SELECTED_ARCHITECTURE_ID
SELECTED_ARCHITECTURE_NAME = packet.SELECTED_ARCHITECTURE_NAME
CANDIDATE_ID = packet.CANDIDATE_ID
CANDIDATE_VERSION = packet.CANDIDATE_VERSION

VALIDATION_REASON_CODES = (
    "RC_B04R6_ACT_REVIEW_VAL_CONTRACT_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_RECEIPT_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_REPORT_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_ACT_REVIEW_VAL_ARCHITECTURE_MISMATCH",
    "RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_ZERO_DISQUALIFIERS_NOT_BOUND",
    "RC_B04R6_ACT_REVIEW_VAL_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_SCREEN_PACKET_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_COURT_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_SOURCE_PACKET_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_ADMISSIBILITY_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_TRIAGE_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_COMPARATOR_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_METRIC_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_DISQUALIFIER_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_TRACE_COMPLETENESS_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_TRUST_ZONE_RECEIPT_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_NO_AUTHORIZATION_DRIFT_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES",
    "RC_B04R6_ACT_REVIEW_VAL_MUTABLE_HANDOFF_NOT_BOUND",
    "RC_B04R6_ACT_REVIEW_VAL_SCOPE_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_STATIC_FALLBACK_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_ABSTENTION_FALLBACK_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_NULL_ROUTE_PRESERVATION_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_KILL_SWITCH_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_ROLLBACK_PLAN_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_ROUTE_DISTRIBUTION_HEALTH_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_DRIFT_MONITORING_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_AUTOMATIC",
    "RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_ACT_REVIEW_VAL_SELF_VALIDATION_DRIFT",
    "RC_B04R6_ACT_REVIEW_VAL_LIMITED_RUNTIME_AUTHORIZED",
    "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_ACT_REVIEW_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_ACT_REVIEW_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_ACT_REVIEW_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_ACT_REVIEW_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_ACT_REVIEW_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_ACT_REVIEW_VAL_METRIC_MUTATION",
    "RC_B04R6_ACT_REVIEW_VAL_COMPARATOR_WEAKENING",
    "RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT",
)

TERMINAL_DEFECTS = (
    "ZERO_DISQUALIFIERS_NOT_BOUND",
    "MULTIPLE_HASH_BINDING_SOURCES",
    "MUTABLE_HANDOFF_NOT_BOUND",
    "LIMITED_RUNTIME_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "LOBE_ESCALATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "METRIC_MUTATION",
    "COMPARATOR_WEAKENING",
    "NEXT_MOVE_DRIFT",
)

PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if not filename.endswith(".md")
}
PACKET_TEXT_INPUTS = {
    "packet_report": f"KT_PROD_CLEANROOM/reports/{packet.OUTPUTS['packet_report']}",
}
MUTABLE_HANDOFF_ROLES = frozenset({"next_lawful_move"})

PREP_ONLY_ROLES = (
    "limited_runtime_authorization_prep_only_draft",
    "limited_runtime_scope_manifest_prep_only_draft",
    "limited_runtime_monitoring_prep_only_draft",
    "limited_runtime_rollback_receipt_schema_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
)

CONTROL_ROLES = (
    "scope_contract",
    "runtime_preconditions_contract",
    "static_fallback_contract",
    "operator_override_contract",
    "kill_switch_contract",
    "rollback_plan_contract",
    "route_distribution_health_contract",
    "drift_monitoring_contract",
    "runtime_receipt_schema_contract",
    "external_verifier_requirements",
    "commercial_claim_boundary",
)

REQUIRED_BINDING_HASH_KEYS = (
    "shadow_screen_result_hash",
    "shadow_screen_execution_receipt_hash",
    "shadow_screen_result_report_hash",
    "fired_disqualifier_receipt_hash",
    "candidate_hash",
    "candidate_artifact_hash",
    "candidate_manifest_hash",
    "candidate_semantic_hash",
    "candidate_hash_receipt_hash",
    "validated_shadow_screen_packet_hash",
    "validated_shadow_packet_hash",
    "validated_shadow_packet_validation_receipt_hash",
    "validated_blind_universe_hash",
    "validated_blind_universe_receipt_hash",
    "validated_route_economics_court_hash",
    "validated_route_economics_court_receipt_hash",
    "validated_source_packet_hash",
    "validated_source_packet_receipt_hash",
    "admissibility_receipt_hash",
    "numeric_triage_emit_core_hash",
    "static_comparator_contract_hash",
    "metric_contract_hash",
    "disqualifier_ledger_hash",
    "trace_completeness_receipt_hash",
    "trust_zone_validation_receipt_hash",
    "no_authorization_drift_receipt_hash",
)

HASH_TO_INPUT_ROLE = {
    "shadow_screen_result_hash": "shadow_screen_result",
    "shadow_screen_execution_receipt_hash": "shadow_execution_receipt",
    "shadow_screen_result_report_hash": "shadow_result_report",
    "fired_disqualifier_receipt_hash": "shadow_disqualifier_result_receipt",
    "candidate_artifact_hash": "candidate_artifact",
    "candidate_hash": "candidate_artifact",
    "candidate_manifest_hash": "candidate_manifest",
    "candidate_hash_receipt_hash": "candidate_hash_receipt",
    "validated_shadow_screen_packet_hash": "validated_shadow_packet_contract",
    "validated_shadow_packet_hash": "validated_shadow_packet_contract",
    "validated_shadow_packet_validation_receipt_hash": "validated_shadow_packet_validation_receipt",
    "validated_blind_universe_receipt_hash": "validated_blind_universe_receipt",
    "validated_route_economics_court_receipt_hash": "validated_route_economics_court_receipt",
    "validated_source_packet_receipt_hash": "validated_source_packet_receipt",
    "admissibility_receipt_hash": "admissibility_receipt",
    "numeric_triage_emit_core_hash": "numeric_triage_emit_core",
    "static_comparator_contract_hash": "static_comparator_contract",
    "metric_contract_hash": "metric_contract",
    "disqualifier_ledger_hash": "disqualifier_ledger",
    "trace_completeness_receipt_hash": "shadow_trace_completeness_receipt",
    "trust_zone_validation_receipt_hash": "shadow_trust_zone_receipt",
    "no_authorization_drift_receipt_hash": "shadow_no_authorization_drift_receipt",
}

OUTPUTS = {
    "validation_contract": "b04_r6_activation_review_validation_contract.json",
    "validation_receipt": "b04_r6_activation_review_validation_receipt.json",
    "validation_report": "b04_r6_activation_review_validation_report.md",
    "packet_contract_validation": "b04_r6_activation_review_packet_contract_validation_receipt.json",
    "packet_receipt_validation": "b04_r6_activation_review_packet_receipt_validation_receipt.json",
    "shadow_result_binding_validation": "b04_r6_activation_review_shadow_result_binding_validation_receipt.json",
    "candidate_binding_validation": "b04_r6_activation_review_candidate_binding_validation_receipt.json",
    "screen_packet_binding_validation": "b04_r6_activation_review_screen_packet_binding_validation_receipt.json",
    "universe_binding_validation": "b04_r6_activation_review_universe_binding_validation_receipt.json",
    "court_binding_validation": "b04_r6_activation_review_court_binding_validation_receipt.json",
    "source_packet_binding_validation": "b04_r6_activation_review_source_packet_binding_validation_receipt.json",
    "admissibility_binding_validation": "b04_r6_activation_review_admissibility_binding_validation_receipt.json",
    "triage_core_binding_validation": "b04_r6_activation_review_triage_core_binding_validation_receipt.json",
    "static_comparator_binding_validation": "b04_r6_activation_review_static_comparator_binding_validation_receipt.json",
    "metric_contract_binding_validation": "b04_r6_activation_review_metric_contract_binding_validation_receipt.json",
    "disqualifier_binding_validation": "b04_r6_activation_review_disqualifier_binding_validation_receipt.json",
    "trace_completeness_binding_validation": "b04_r6_activation_review_trace_completeness_binding_validation_receipt.json",
    "scope_validation": "b04_r6_activation_review_scope_validation_receipt.json",
    "runtime_preconditions_validation": "b04_r6_activation_review_runtime_preconditions_validation_receipt.json",
    "static_fallback_validation": "b04_r6_activation_review_static_fallback_validation_receipt.json",
    "operator_override_validation": "b04_r6_activation_review_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_activation_review_kill_switch_validation_receipt.json",
    "rollback_plan_validation": "b04_r6_activation_review_rollback_plan_validation_receipt.json",
    "route_distribution_health_validation": "b04_r6_activation_review_route_distribution_health_validation_receipt.json",
    "drift_monitoring_validation": "b04_r6_activation_review_drift_monitoring_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_activation_review_runtime_receipt_schema_validation_receipt.json",
    "external_verifier_validation": "b04_r6_activation_review_external_verifier_validation_receipt.json",
    "commercial_claim_boundary_validation": "b04_r6_activation_review_commercial_claim_boundary_validation_receipt.json",
    "prep_only_non_authority_validation": "b04_r6_activation_review_prep_only_non_authority_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_activation_review_no_authorization_drift_validation_receipt.json",
    "trust_zone_validation": "b04_r6_activation_review_trust_zone_validation_receipt.json",
    "replay_binding_validation": "b04_r6_activation_review_replay_binding_validation_receipt.json",
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


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _rows_for(rows: list[Dict[str, str]], *groups: str) -> list[Dict[str, str]]:
    wanted = set(groups)
    return [row for row in rows if row.get("group") in wanted]


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and bool(payload.get(key)):
        _fail(code, f"{label} sets forbidden true flag: {key}")


def _ensure_runtime_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, code in (
        ("r6_open", "RC_B04R6_ACT_REVIEW_VAL_R6_OPEN_DRIFT"),
        ("limited_runtime_authorized", "RC_B04R6_ACT_REVIEW_VAL_LIMITED_RUNTIME_AUTHORIZED"),
        ("runtime_cutover_authorized", "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_authorized", "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_executed", "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("lobe_escalation_authorized", "RC_B04R6_ACT_REVIEW_VAL_LOBE_ESCALATION_DRIFT"),
        ("package_promotion_authorized", "RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", "RC_B04R6_ACT_REVIEW_VAL_COMMERCIAL_CLAIM_DRIFT"),
        ("metric_contract_mutated", "RC_B04R6_ACT_REVIEW_VAL_METRIC_MUTATION"),
        ("static_comparator_weakened", "RC_B04R6_ACT_REVIEW_VAL_COMPARATOR_WEAKENING"),
    ):
        _ensure_false(payload, key, label=label, code=code)
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        _ensure_runtime_closed(state, label=f"{label}.authorization_state")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion is not deferred")
    if payload.get("truth_engine_law_changed") is True or payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_ACT_REVIEW_VAL_TRUTH_ENGINE_MUTATION", f"{label} mutates truth-engine law")
    if payload.get("trust_zone_law_changed") is True or payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_ACT_REVIEW_VAL_TRUST_ZONE_MUTATION", f"{label} mutates trust-zone law")


def _input_hashes(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(PACKET_JSON_INPUTS.items()):
        path = common.resolve_path(root, raw)
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_activation_review_validation",
        }
        if role in MUTABLE_HANDOFF_ROLES:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(PACKET_TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_activation_review_validation",
            }
        )
    return rows


def _input_binding_sha(bindings: Iterable[Dict[str, Any]], role: str) -> str:
    matches = [str(row.get("sha256", "")).strip() for row in bindings if row.get("role") == role]
    if len(matches) != 1:
        _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", f"expected one input binding for {role}")
    return matches[0]


def _validate_next_handoff(next_payload: Dict[str, Any]) -> Dict[str, bool]:
    predecessor = (
        next_payload.get("authoritative_lane") == PREVIOUS_LANE
        and next_payload.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and next_payload.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    self_replay = (
        next_payload.get("authoritative_lane") == AUTHORITATIVE_LANE
        and next_payload.get("selected_outcome") == SELECTED_OUTCOME
        and next_payload.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )
    if not (predecessor or self_replay):
        _fail("RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT", "handoff lacks valid predecessor or self-replay lane identity")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _packet_report_valid(text: str) -> None:
    lowered = text.lower()
    if "activation-review" not in lowered or "does not open r6" not in lowered:
        _fail("RC_B04R6_ACT_REVIEW_VAL_REPORT_MISSING", "packet report must describe non-activating activation-review packet")


def _ensure_packet_identity(payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> str:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    _packet_report_valid(text_payloads["packet_report"])
    for role, payload in payloads.items():
        _ensure_runtime_closed(payload, label=role)
        if role in PREP_ONLY_ROLES:
            if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
                _fail("RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} must remain PREP_ONLY")
            continue
        if role == "next_lawful_move":
            _validate_next_handoff(payload)
            continue
        if payload.get("status") not in (None, "PASS"):
            _fail("RC_B04R6_ACT_REVIEW_VAL_CONTRACT_MISSING", f"{role} must be PASS")
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_ACT_REVIEW_VAL_CONTRACT_MISSING", f"{role} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT", f"{role} selected outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT", f"{role} next lawful move drift")
    if contract.get("artifact_id") != "B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET":
        _fail("RC_B04R6_ACT_REVIEW_VAL_CONTRACT_MISSING", "activation-review packet contract artifact drift")
    if receipt.get("artifact_id") != "B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_RECEIPT":
        _fail("RC_B04R6_ACT_REVIEW_VAL_RECEIPT_MISSING", "activation-review packet receipt artifact drift")
    if contract.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_ACT_REVIEW_VAL_ARCHITECTURE_MISMATCH", "architecture drift")
    if contract.get("candidate_id") != CANDIDATE_ID:
        _fail("RC_B04R6_ACT_REVIEW_VAL_CANDIDATE_BINDING_MISSING", "candidate identity drift")
    if contract.get("activation_review_packet_authored") is not True:
        _fail("RC_B04R6_ACT_REVIEW_VAL_CONTRACT_MISSING", "packet authorship not bound")
    if contract.get("activation_review_validated") is not False:
        _fail("RC_B04R6_ACT_REVIEW_VAL_SELF_VALIDATION_DRIFT", "packet self-validates before validation lane")
    packet_replay_head = str(contract.get("current_git_head", "")).strip()
    if not packet_replay_head or packet_replay_head != str(receipt.get("current_git_head", "")).strip():
        _fail("RC_B04R6_ACT_REVIEW_VAL_MAIN_HEAD_MISMATCH", "packet replay head missing or inconsistent")
    return packet_replay_head


def _validate_binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    hashes = contract.get("binding_hashes")
    if not isinstance(hashes, dict):
        _fail("RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", "packet binding_hashes missing")
    for key in REQUIRED_BINDING_HASH_KEYS:
        if not _is_sha256(hashes.get(key)):
            _fail("RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", f"binding hash missing or invalid: {key}")
    if receipt.get("binding_hashes") != hashes:
        _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", "packet receipt binding_hashes do not match contract")
    for role, payload in payloads.items():
        if role == "next_lawful_move":
            continue
        payload_hashes = payload.get("binding_hashes")
        if payload_hashes is not None and payload_hashes != hashes:
            _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", f"{role} binding_hashes do not match contract")

    input_bindings = contract.get("input_bindings")
    if not isinstance(input_bindings, list):
        _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", "contract input_bindings missing")
    roles = [row.get("role") for row in input_bindings]
    if len(roles) != len(set(roles)):
        _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", "duplicate input binding roles")
    for hash_key, role in HASH_TO_INPUT_ROLE.items():
        if _input_binding_sha(input_bindings, role) != str(hashes[hash_key]):
            _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", f"{hash_key} does not source from input_bindings role {role}")

    for role, raw in packet.INPUTS.items():
        if role == "previous_next_lawful_move":
            continue
        actual = file_sha256(common.resolve_path(root, raw))
        expected = _input_binding_sha(input_bindings, role)
        if actual != expected:
            _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", f"{role} file hash changed after packet binding")
    for role, raw in packet.TEXT_INPUTS.items():
        actual = file_sha256(common.resolve_path(root, raw))
        expected = _input_binding_sha(input_bindings, role)
        if actual != expected:
            _fail("RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", f"{role} text hash changed after packet binding")

    handoff_rows = [row for row in input_bindings if row.get("role") == "previous_next_lawful_move"]
    if len(handoff_rows) != 1:
        _fail("RC_B04R6_ACT_REVIEW_VAL_MUTABLE_HANDOFF_NOT_BOUND", "packet mutable handoff row missing")
    if handoff_rows[0].get("binding_kind") != "git_object_before_overwrite" or not handoff_rows[0].get("git_commit"):
        _fail("RC_B04R6_ACT_REVIEW_VAL_MUTABLE_HANDOFF_NOT_BOUND", "packet handoff must be git-object-bound before overwrite")
    return {key: str(value) for key, value in hashes.items()}


def _validate_binding_receipts(payloads: Dict[str, Dict[str, Any]], hashes: Dict[str, str]) -> None:
    expected = {
        "shadow_result_binding_receipt": ("shadow_screen_result_hash", "shadow_screen_execution_receipt_hash", "shadow_screen_result_report_hash", "fired_disqualifier_receipt_hash"),
        "candidate_binding_receipt": ("candidate_hash", "candidate_manifest_hash", "candidate_semantic_hash", "candidate_hash_receipt_hash"),
        "screen_packet_binding_receipt": ("validated_shadow_screen_packet_hash", "validated_shadow_packet_validation_receipt_hash"),
        "universe_binding_receipt": ("validated_blind_universe_hash",),
        "court_binding_receipt": ("validated_route_economics_court_hash",),
        "source_packet_binding_receipt": ("validated_source_packet_hash",),
        "admissibility_binding_receipt": ("admissibility_receipt_hash",),
        "triage_core_binding_receipt": ("numeric_triage_emit_core_hash",),
        "static_comparator_binding_receipt": ("static_comparator_contract_hash",),
        "metric_contract_binding_receipt": ("metric_contract_hash",),
        "disqualifier_binding_receipt": ("disqualifier_ledger_hash", "fired_disqualifier_receipt_hash"),
        "trace_completeness_binding_receipt": ("trace_completeness_receipt_hash",),
    }
    for role, keys in expected.items():
        payload = payloads[role]
        if payload.get("binding_status") != "BOUND":
            _fail("RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", f"{role} binding status drift")
        bound = payload.get("bound_hashes")
        if not isinstance(bound, dict):
            _fail("RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", f"{role} bound_hashes missing")
        for key in keys:
            if bound.get(key) != hashes[key]:
                _fail("RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", f"{role} does not bind {key}")


def _validate_shadow_result(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    result = contract.get("shadow_screen_result", {})
    if result.get("status") != "SHADOW_SUPERIORITY_PASSED":
        _fail("RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", "shadow superiority pass not bound")
    if result.get("fired_disqualifiers") != []:
        _fail("RC_B04R6_ACT_REVIEW_VAL_ZERO_DISQUALIFIERS_NOT_BOUND", "zero fired disqualifiers not bound")
    for key in ("runtime_activation_earned", "r6_open_earned", "package_promotion_earned"):
        if result.get(key) is not False:
            _fail("RC_B04R6_ACT_REVIEW_VAL_LIMITED_RUNTIME_AUTHORIZED", f"shadow result wrongly earns {key}")


def _validate_runtime_controls(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    runtime = contract.get("runtime_preconditions")
    if not isinstance(runtime, dict):
        _fail("RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING", "runtime preconditions missing")
    for key in packet.RUNTIME_PRECONDITION_KEYS:
        if runtime.get(key) is not True:
            _fail("RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING", f"runtime precondition missing: {key}")
    for requirement in packet.ACTIVATION_SUCCESS_REQUIREMENTS:
        if requirement not in contract.get("activation_review_success_requirements", []):
            _fail("RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING", f"success requirement missing: {requirement}")

    for role in CONTROL_ROLES:
        payload = payloads[role]
        if payload.get("required_before_limited_runtime_authorization") is not True:
            _fail("RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING", f"{role} not marked required")
        if payload.get("can_authorize_limited_runtime") is not False:
            _fail("RC_B04R6_ACT_REVIEW_VAL_LIMITED_RUNTIME_AUTHORIZED", f"{role} can authorize limited runtime")
        if payload.get("can_execute_runtime") is not False:
            _fail("RC_B04R6_ACT_REVIEW_VAL_RUNTIME_CUTOVER_AUTHORIZED", f"{role} can execute runtime")
        if payload.get("can_open_r6") is not False:
            _fail("RC_B04R6_ACT_REVIEW_VAL_R6_OPEN_DRIFT", f"{role} can open R6")
    static_requirements = set(payloads["static_fallback_contract"].get("requirements") or [])
    for requirement, code in (
        ("static_fallback_required", "RC_B04R6_ACT_REVIEW_VAL_STATIC_FALLBACK_MISSING"),
        ("abstention_fallback_required", "RC_B04R6_ACT_REVIEW_VAL_ABSTENTION_FALLBACK_MISSING"),
        ("null_route_preservation_required", "RC_B04R6_ACT_REVIEW_VAL_NULL_ROUTE_PRESERVATION_MISSING"),
    ):
        if requirement not in static_requirements:
            _fail(code, f"static fallback contract missing {requirement}")
    if "human_operator_override_required" not in set(payloads["operator_override_contract"].get("requirements") or []):
        _fail("RC_B04R6_ACT_REVIEW_VAL_OPERATOR_OVERRIDE_MISSING", "operator override requirement missing")
    if "kill_switch_required" not in set(payloads["kill_switch_contract"].get("requirements") or []):
        _fail("RC_B04R6_ACT_REVIEW_VAL_KILL_SWITCH_MISSING", "kill switch requirement missing")
    if "rollback_plan_required" not in set(payloads["rollback_plan_contract"].get("requirements") or []):
        _fail("RC_B04R6_ACT_REVIEW_VAL_ROLLBACK_PLAN_MISSING", "rollback plan requirement missing")
    if "selector_entry_rate_monitored" not in set(payloads["route_distribution_health_contract"].get("requirements") or []):
        _fail("RC_B04R6_ACT_REVIEW_VAL_ROUTE_DISTRIBUTION_HEALTH_MISSING", "route distribution monitoring missing")
    if "metric_drift_freezes_runtime_consideration" not in set(payloads["drift_monitoring_contract"].get("requirements") or []):
        _fail("RC_B04R6_ACT_REVIEW_VAL_DRIFT_MONITORING_MISSING", "drift monitoring freeze missing")
    if "verdict_mode_required" not in set(payloads["runtime_receipt_schema_contract"].get("requirements") or []):
        _fail("RC_B04R6_ACT_REVIEW_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING", "runtime receipt schema verdict requirement missing")
    if "external_verifier_non_executing" not in set(payloads["external_verifier_requirements"].get("requirements") or []):
        _fail("RC_B04R6_ACT_REVIEW_VAL_EXTERNAL_VERIFIER_MISSING", "external verifier non-executing requirement missing")
    commercial_requirements = set(payloads["commercial_claim_boundary"].get("requirements") or [])
    if "commercial_activation_claims_unauthorized" not in commercial_requirements:
        _fail("RC_B04R6_ACT_REVIEW_VAL_COMMERCIAL_BOUNDARY_MISSING", "commercial claim boundary missing")
    if "package_promotion_prohibited" not in commercial_requirements:
        _fail("RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_AUTOMATIC", "package promotion prohibition missing")


def _validate_scaffold_and_prep(payloads: Dict[str, Dict[str, Any]]) -> None:
    plan = payloads["validation_plan"]
    if plan.get("expected_successful_validation_outcome") != SELECTED_OUTCOME:
        _fail("RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT", "validation plan expected outcome drift")
    if plan.get("expected_next_lawful_move_after_validation") != NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT", "validation plan expected next move drift")
    reason = payloads["validation_reason_codes"]
    for code in packet.REASON_CODES:
        if code not in reason.get("reason_codes", []):
            _fail("RC_B04R6_ACT_REVIEW_VAL_CONTRACT_MISSING", f"authored reason code missing: {code}")
    for role in PREP_ONLY_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} authority drift")
        for key, code in (
            ("limited_runtime_authorized", "RC_B04R6_ACT_REVIEW_VAL_LIMITED_RUNTIME_AUTHORIZED"),
            ("runtime_cutover_authorized", "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
            ("package_promotion_authorized", "RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_DRIFT"),
            ("r6_open", "RC_B04R6_ACT_REVIEW_VAL_R6_OPEN_DRIFT"),
        ):
            _ensure_false(payload, key, label=role, code=code)


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("activation_review_validation_contract_preserves_current_main_head", "RC_B04R6_ACT_REVIEW_VAL_MAIN_HEAD_MISMATCH", "validation binds current main head", group="core"),
        _pass_row("activation_review_validation_binds_selected_architecture", "RC_B04R6_ACT_REVIEW_VAL_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD selected", group="core"),
        _pass_row("activation_review_packet_contract_exists", "RC_B04R6_ACT_REVIEW_VAL_CONTRACT_MISSING", "activation-review packet contract bound", group="packet"),
        _pass_row("activation_review_packet_receipt_exists", "RC_B04R6_ACT_REVIEW_VAL_RECEIPT_MISSING", "activation-review packet receipt bound", group="packet"),
        _pass_row("activation_review_packet_report_exists", "RC_B04R6_ACT_REVIEW_VAL_REPORT_MISSING", "activation-review packet report bound", group="packet"),
        _pass_row("shadow_superiority_result_bound", "RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", "shadow superiority result bound", group="shadow_result"),
        _pass_row("zero_fired_disqualifiers_bound", "RC_B04R6_ACT_REVIEW_VAL_ZERO_DISQUALIFIERS_NOT_BOUND", "zero fired disqualifiers bound", group="shadow_result"),
        _pass_row("shadow_execution_receipt_bound", "RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", "shadow execution receipt bound", group="shadow_result"),
        _pass_row("shadow_result_report_bound", "RC_B04R6_ACT_REVIEW_VAL_SHADOW_RESULT_BINDING_MISSING", "shadow result report bound", group="shadow_result"),
        _pass_row("candidate_hash_bound", "RC_B04R6_ACT_REVIEW_VAL_CANDIDATE_BINDING_MISSING", "candidate hash bound", group="binding"),
        _pass_row("candidate_manifest_hash_bound", "RC_B04R6_ACT_REVIEW_VAL_CANDIDATE_BINDING_MISSING", "candidate manifest hash bound", group="binding"),
        _pass_row("candidate_semantic_hash_bound", "RC_B04R6_ACT_REVIEW_VAL_CANDIDATE_BINDING_MISSING", "candidate semantic hash bound", group="binding"),
        _pass_row("validated_shadow_packet_bound", "RC_B04R6_ACT_REVIEW_VAL_SCREEN_PACKET_BINDING_MISSING", "validated shadow packet bound", group="binding"),
        _pass_row("validated_blind_universe_bound", "RC_B04R6_ACT_REVIEW_VAL_UNIVERSE_BINDING_MISSING", "validated universe bound", group="binding"),
        _pass_row("validated_route_value_court_bound", "RC_B04R6_ACT_REVIEW_VAL_COURT_BINDING_MISSING", "validated court bound", group="binding"),
        _pass_row("validated_source_packet_bound", "RC_B04R6_ACT_REVIEW_VAL_SOURCE_PACKET_BINDING_MISSING", "validated source packet bound", group="binding"),
        _pass_row("admissibility_receipt_bound", "RC_B04R6_ACT_REVIEW_VAL_ADMISSIBILITY_BINDING_MISSING", "admissibility receipt bound", group="binding"),
        _pass_row("numeric_triage_core_bound", "RC_B04R6_ACT_REVIEW_VAL_TRIAGE_BINDING_MISSING", "numeric triage core bound", group="binding"),
        _pass_row("static_comparator_bound", "RC_B04R6_ACT_REVIEW_VAL_COMPARATOR_BINDING_MISSING", "static comparator bound", group="binding"),
        _pass_row("metric_contract_bound", "RC_B04R6_ACT_REVIEW_VAL_METRIC_BINDING_MISSING", "metric contract bound", group="binding"),
        _pass_row("disqualifier_ledger_bound", "RC_B04R6_ACT_REVIEW_VAL_DISQUALIFIER_BINDING_MISSING", "disqualifier ledger bound", group="binding"),
        _pass_row("trace_completeness_bound", "RC_B04R6_ACT_REVIEW_VAL_TRACE_COMPLETENESS_BINDING_MISSING", "trace completeness receipt bound", group="binding"),
        _pass_row("trust_zone_receipt_bound", "RC_B04R6_ACT_REVIEW_VAL_TRUST_ZONE_RECEIPT_MISSING", "trust-zone receipt bound", group="binding"),
        _pass_row("no_authorization_drift_receipt_bound", "RC_B04R6_ACT_REVIEW_VAL_NO_AUTHORIZATION_DRIFT_MISSING", "no authorization drift receipt bound", group="binding"),
        _pass_row("bound_hashes_source_from_single_input_bindings_path", "RC_B04R6_ACT_REVIEW_VAL_MULTIPLE_HASH_BINDING_SOURCES", "bound hashes source from input_bindings", group="replay"),
        _pass_row("mutable_handoff_bound_before_overwrite", "RC_B04R6_ACT_REVIEW_VAL_MUTABLE_HANDOFF_NOT_BOUND", "mutable handoff git-object-bound", group="replay"),
        _pass_row("activation_review_self_replay_handoff_allowed", "RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT", "self replay handoff accepted", group="replay"),
        _pass_row("activation_review_scope_contract_exists", "RC_B04R6_ACT_REVIEW_VAL_SCOPE_MISSING", "scope contract exists", group="controls"),
        _pass_row("runtime_preconditions_contract_exists", "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING", "runtime preconditions exist", group="controls"),
        _pass_row("static_fallback_exists", "RC_B04R6_ACT_REVIEW_VAL_STATIC_FALLBACK_MISSING", "static fallback exists", group="controls"),
        _pass_row("abstention_fallback_exists", "RC_B04R6_ACT_REVIEW_VAL_ABSTENTION_FALLBACK_MISSING", "abstention fallback exists", group="controls"),
        _pass_row("null_route_preservation_exists", "RC_B04R6_ACT_REVIEW_VAL_NULL_ROUTE_PRESERVATION_MISSING", "null-route preservation exists", group="controls"),
        _pass_row("operator_override_exists", "RC_B04R6_ACT_REVIEW_VAL_OPERATOR_OVERRIDE_MISSING", "operator override exists", group="controls"),
        _pass_row("kill_switch_exists", "RC_B04R6_ACT_REVIEW_VAL_KILL_SWITCH_MISSING", "kill switch exists", group="controls"),
        _pass_row("rollback_plan_exists", "RC_B04R6_ACT_REVIEW_VAL_ROLLBACK_PLAN_MISSING", "rollback plan exists", group="controls"),
        _pass_row("route_distribution_health_exists", "RC_B04R6_ACT_REVIEW_VAL_ROUTE_DISTRIBUTION_HEALTH_MISSING", "route distribution health exists", group="controls"),
        _pass_row("drift_monitoring_exists", "RC_B04R6_ACT_REVIEW_VAL_DRIFT_MONITORING_MISSING", "drift monitoring exists", group="controls"),
        _pass_row("runtime_receipt_schema_exists", "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING", "runtime receipt schema exists", group="controls"),
        _pass_row("external_verifier_requirements_exist", "RC_B04R6_ACT_REVIEW_VAL_EXTERNAL_VERIFIER_MISSING", "external verifier requirements exist", group="controls"),
        _pass_row("commercial_claim_boundary_exists", "RC_B04R6_ACT_REVIEW_VAL_COMMERCIAL_BOUNDARY_MISSING", "commercial claim boundary exists", group="controls"),
        _pass_row("package_promotion_not_automatic", "RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_AUTOMATIC", "package promotion is not automatic", group="controls"),
        _pass_row("limited_runtime_authorization_draft_remains_prep_only", "RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", "limited runtime draft prep-only", group="prep_only"),
        _pass_row("limited_runtime_scope_manifest_draft_remains_prep_only", "RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", "limited runtime scope draft prep-only", group="prep_only"),
        _pass_row("limited_runtime_monitoring_draft_remains_prep_only", "RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", "limited runtime monitoring draft prep-only", group="prep_only"),
        _pass_row("limited_runtime_rollback_schema_draft_remains_prep_only", "RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", "limited runtime rollback draft prep-only", group="prep_only"),
        _pass_row("package_promotion_review_preconditions_draft_remains_prep_only", "RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", "package promotion draft prep-only", group="prep_only"),
        _pass_row("external_audit_delta_manifest_draft_remains_prep_only", "RC_B04R6_ACT_REVIEW_VAL_PREP_ONLY_AUTHORITY_DRIFT", "external audit draft prep-only", group="prep_only"),
        _pass_row("validation_does_not_authorize_limited_runtime", "RC_B04R6_ACT_REVIEW_VAL_LIMITED_RUNTIME_AUTHORIZED", "limited runtime unauthorized", group="authorization"),
        _pass_row("validation_does_not_authorize_runtime_cutover", "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_CUTOVER_AUTHORIZED", "runtime cutover unauthorized", group="authorization"),
        _pass_row("validation_does_not_open_r6", "RC_B04R6_ACT_REVIEW_VAL_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"),
        _pass_row("validation_does_not_authorize_lobe_escalation", "RC_B04R6_ACT_REVIEW_VAL_LOBE_ESCALATION_DRIFT", "lobe escalation unauthorized", group="authorization"),
        _pass_row("validation_does_not_authorize_package_promotion", "RC_B04R6_ACT_REVIEW_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", group="authorization"),
        _pass_row("validation_does_not_authorize_commercial_claims", "RC_B04R6_ACT_REVIEW_VAL_COMMERCIAL_CLAIM_DRIFT", "commercial activation claims unauthorized", group="authorization"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_ACT_REVIEW_VAL_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", group="authorization"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_ACT_REVIEW_VAL_TRUST_ZONE_MUTATION", "trust-zone law unchanged", group="authorization"),
        _pass_row("metric_contract_not_mutated", "RC_B04R6_ACT_REVIEW_VAL_METRIC_MUTATION", "metric contract not mutated", group="authorization"),
        _pass_row("static_comparator_not_weakened", "RC_B04R6_ACT_REVIEW_VAL_COMPARATOR_WEAKENING", "static comparator not weakened", group="authorization"),
        _pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_ACT_REVIEW_VAL_NO_AUTHORIZATION_DRIFT_MISSING", "no authorization drift passes", group="authorization"),
        _pass_row("next_lawful_move_is_limited_runtime_authorization_packet", "RC_B04R6_ACT_REVIEW_VAL_NEXT_MOVE_DRIFT", "next move is limited runtime authorization packet authorship", group="next_move"),
    ]
    rows.extend(
        _pass_row(
            f"runtime_precondition_requires_{key}",
            "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING",
            f"runtime precondition requires {key}",
            group="controls",
        )
        for key in packet.RUNTIME_PRECONDITION_KEYS
    )
    rows.extend(
        _pass_row(
            f"activation_review_success_requires_{requirement}",
            "RC_B04R6_ACT_REVIEW_VAL_RUNTIME_PRECONDITIONS_MISSING",
            f"activation review success requires {requirement}",
            group="controls",
        )
        for requirement in packet.ACTIVATION_SUCCESS_REQUIREMENTS
    )
    return rows


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_packet_authored": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_next": True,
        "limited_runtime_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    packet_replay_head: str,
    hashes: Dict[str, str],
    handoff_state: Dict[str, bool],
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_utc": generated_utc,
        "current_branch": current_branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "packet_replay_binding_head": packet_replay_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "binding_hashes": hashes,
        "handoff_state": handoff_state,
        "authorization_state": _authorization_state(),
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_packet_authored": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_next": True,
        "limited_runtime_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "allowed_outcomes": [OUTCOME_VALIDATED, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": list(packet.FORBIDDEN_ACTIONS),
        "reason_codes": list(VALIDATION_REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
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
    payload = {
        **base,
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "status": "PASS",
        "pass_count": len(rows),
        "failure_count": 0,
        "validation_rows": rows,
        "input_bindings": input_bindings,
    }
    if extra:
        payload.update(extra)
    return payload


def _report(rows: list[Dict[str, str]]) -> str:
    lines = [
        "# B04 R6 Learned-Router Activation-Review Packet Validation",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "This validator reads and hashes the authored activation-review packet as frozen input. It validates the shadow-result binding, zero-fired-disqualifier state, runtime preconditions, fallback controls, operator override, kill switch, rollback law, monitoring, receipt schema, external verifier requirements, commercial claim boundary, prep-only non-authority, and no-authorization drift.",
        "",
        "It does not authorize limited runtime, execute activation/cutover, open R6, escalate to lobes, promote a package, mutate truth/trust law, widen metrics, weaken the static comparator, or authorize commercial activation claims.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 activation-review packet validation")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in PACKET_JSON_INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in PACKET_TEXT_INPUTS.items()}

    packet_replay_head = _ensure_packet_identity(payloads, text_payloads)
    handoff_state = _validate_next_handoff(payloads["next_lawful_move"])
    hashes = _validate_binding_hashes(root, payloads)
    _validate_binding_receipts(payloads, hashes)
    _validate_shadow_result(payloads)
    _validate_runtime_controls(payloads)
    _validate_scaffold_and_prep(payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_ACT_REVIEW_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)
    handoff_input = [row for row in input_bindings if row.get("role") == "next_lawful_move"]
    if len(handoff_input) != 1 or handoff_input[0].get("binding_kind") != "git_object_before_overwrite":
        _fail("RC_B04R6_ACT_REVIEW_VAL_MUTABLE_HANDOFF_NOT_BOUND", "validation handoff must be git-object-bound before overwrite")

    rows = _validation_rows()
    generated_utc = utc_now_iso_z()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        packet_replay_head=packet_replay_head,
        hashes=hashes,
        handoff_state=handoff_state,
    )
    common_extra = {
        "packet_contract_hash": file_sha256(common.resolve_path(root, PACKET_JSON_INPUTS["packet_contract"])),
        "packet_receipt_hash": file_sha256(common.resolve_path(root, PACKET_JSON_INPUTS["packet_receipt"])),
        "packet_report_hash": file_sha256(common.resolve_path(root, PACKET_TEXT_INPUTS["packet_report"])),
        "fresh_trust_zone_validation": fresh_trust_validation,
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
        OUTPUTS["validation_contract"]: receipt(
            "kt.b04_r6.activation_review.validation_contract.v1",
            "B04_R6_ACTIVATION_REVIEW_VALIDATION_CONTRACT",
            ("core", "packet", "shadow_result", "binding", "replay", "controls", "prep_only", "authorization", "next_move"),
            {
                "validator_role": "READ_HASH_ATTACK_AUTHORED_ACTIVATION_REVIEW_PACKET",
                "packet_state_before_validation": "BOUND_NOT_VALIDATED",
                "packet_state_after_validation": "BOUND_AND_VALIDATED",
                "limited_runtime_authorized_by_this_validation_lane": False,
                "limited_runtime_authorization_packet_next": True,
            },
        ),
        OUTPUTS["validation_receipt"]: receipt(
            "kt.b04_r6.activation_review.validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_VALIDATION_RECEIPT",
            ("core", "packet", "shadow_result", "binding", "replay", "controls", "prep_only", "authorization", "next_move"),
        ),
        OUTPUTS["packet_contract_validation"]: receipt(
            "kt.b04_r6.activation_review.packet_contract_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_PACKET_CONTRACT_VALIDATION_RECEIPT",
            ("core", "packet"),
        ),
        OUTPUTS["packet_receipt_validation"]: receipt(
            "kt.b04_r6.activation_review.packet_receipt_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_PACKET_RECEIPT_VALIDATION_RECEIPT",
            ("packet",),
        ),
        OUTPUTS["shadow_result_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.shadow_result_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_SHADOW_RESULT_BINDING_VALIDATION_RECEIPT",
            ("shadow_result",),
            {
                "shadow_screen_result_hash": hashes["shadow_screen_result_hash"],
                "shadow_screen_execution_receipt_hash": hashes["shadow_screen_execution_receipt_hash"],
                "shadow_screen_result_report_hash": hashes["shadow_screen_result_report_hash"],
                "fired_disqualifiers": [],
            },
        ),
        OUTPUTS["candidate_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.candidate_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_CANDIDATE_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {
                "candidate_hash": hashes["candidate_hash"],
                "candidate_manifest_hash": hashes["candidate_manifest_hash"],
                "candidate_semantic_hash": hashes["candidate_semantic_hash"],
            },
        ),
        OUTPUTS["screen_packet_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.screen_packet_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_SCREEN_PACKET_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"validated_shadow_screen_packet_hash": hashes["validated_shadow_screen_packet_hash"]},
        ),
        OUTPUTS["universe_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.universe_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_UNIVERSE_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"validated_blind_universe_hash": hashes["validated_blind_universe_hash"]},
        ),
        OUTPUTS["court_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.court_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_COURT_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"validated_route_economics_court_hash": hashes["validated_route_economics_court_hash"]},
        ),
        OUTPUTS["source_packet_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.source_packet_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_SOURCE_PACKET_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"validated_source_packet_hash": hashes["validated_source_packet_hash"]},
        ),
        OUTPUTS["admissibility_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.admissibility_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_ADMISSIBILITY_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"admissibility_receipt_hash": hashes["admissibility_receipt_hash"]},
        ),
        OUTPUTS["triage_core_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.triage_core_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_TRIAGE_CORE_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"numeric_triage_emit_core_hash": hashes["numeric_triage_emit_core_hash"]},
        ),
        OUTPUTS["static_comparator_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.static_comparator_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_STATIC_COMPARATOR_BINDING_VALIDATION_RECEIPT",
            ("binding", "authorization"),
            {"static_comparator_contract_hash": hashes["static_comparator_contract_hash"]},
        ),
        OUTPUTS["metric_contract_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.metric_contract_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_METRIC_CONTRACT_BINDING_VALIDATION_RECEIPT",
            ("binding", "authorization"),
            {"metric_contract_hash": hashes["metric_contract_hash"]},
        ),
        OUTPUTS["disqualifier_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.disqualifier_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_DISQUALIFIER_BINDING_VALIDATION_RECEIPT",
            ("binding", "shadow_result"),
            {"disqualifier_ledger_hash": hashes["disqualifier_ledger_hash"], "fired_disqualifier_receipt_hash": hashes["fired_disqualifier_receipt_hash"]},
        ),
        OUTPUTS["trace_completeness_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.trace_completeness_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_TRACE_COMPLETENESS_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"trace_completeness_receipt_hash": hashes["trace_completeness_receipt_hash"]},
        ),
        OUTPUTS["scope_validation"]: receipt("kt.b04_r6.activation_review.scope_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_SCOPE_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["runtime_preconditions_validation"]: receipt("kt.b04_r6.activation_review.runtime_preconditions_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_RUNTIME_PRECONDITIONS_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["static_fallback_validation"]: receipt("kt.b04_r6.activation_review.static_fallback_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_STATIC_FALLBACK_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["operator_override_validation"]: receipt("kt.b04_r6.activation_review.operator_override_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_OPERATOR_OVERRIDE_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["kill_switch_validation"]: receipt("kt.b04_r6.activation_review.kill_switch_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_KILL_SWITCH_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["rollback_plan_validation"]: receipt("kt.b04_r6.activation_review.rollback_plan_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_ROLLBACK_PLAN_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["route_distribution_health_validation"]: receipt("kt.b04_r6.activation_review.route_distribution_health_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_ROUTE_DISTRIBUTION_HEALTH_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["drift_monitoring_validation"]: receipt("kt.b04_r6.activation_review.drift_monitoring_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_DRIFT_MONITORING_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["runtime_receipt_schema_validation"]: receipt("kt.b04_r6.activation_review.runtime_receipt_schema_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_RUNTIME_RECEIPT_SCHEMA_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["external_verifier_validation"]: receipt("kt.b04_r6.activation_review.external_verifier_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_EXTERNAL_VERIFIER_VALIDATION_RECEIPT", ("controls",)),
        OUTPUTS["commercial_claim_boundary_validation"]: receipt("kt.b04_r6.activation_review.commercial_claim_boundary_validation_receipt.v1", "B04_R6_ACTIVATION_REVIEW_COMMERCIAL_CLAIM_BOUNDARY_VALIDATION_RECEIPT", ("controls", "authorization")),
        OUTPUTS["prep_only_non_authority_validation"]: receipt(
            "kt.b04_r6.activation_review.prep_only_non_authority_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_PREP_ONLY_NON_AUTHORITY_VALIDATION_RECEIPT",
            ("prep_only",),
        ),
        OUTPUTS["no_authorization_drift_validation"]: receipt(
            "kt.b04_r6.activation_review.no_authorization_drift_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            ("authorization", "next_move"),
            {"no_downstream_authorization_drift": True},
        ),
        OUTPUTS["trust_zone_validation"]: receipt(
            "kt.b04_r6.activation_review.trust_zone_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_TRUST_ZONE_VALIDATION_RECEIPT",
            ("authorization",),
        ),
        OUTPUTS["replay_binding_validation"]: receipt(
            "kt.b04_r6.activation_review.replay_binding_validation_receipt.v1",
            "B04_R6_ACTIVATION_REVIEW_REPLAY_BINDING_VALIDATION_RECEIPT",
            ("replay",),
            {"packet_replay_binding_head": packet_replay_head, "mutable_handoff_bound_before_overwrite": True},
        ),
        OUTPUTS["next_lawful_move"]: receipt(
            "kt.operator.b04_r6_next_lawful_move_receipt.v16",
            "B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            ("next_move",),
            {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE},
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
    parser = argparse.ArgumentParser(description="Validate B04 R6 learned-router activation-review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
