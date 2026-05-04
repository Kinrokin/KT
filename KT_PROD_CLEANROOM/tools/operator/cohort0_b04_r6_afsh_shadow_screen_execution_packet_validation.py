from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_afsh_shadow_screen_execution_packet as packet
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-afsh-shadow-screen-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_VALIDATION"
PREVIOUS_LANE = packet.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = packet.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet.NEXT_LAWFUL_MOVE
OUTCOME_VALIDATED = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_VALIDATED__SHADOW_SCREEN_EXECUTION_NEXT"
OUTCOME_DEFERRED = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_VALIDATION_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "RUN_B04_R6_AFSH_SHADOW_SCREEN"

SELECTED_ARCHITECTURE_ID = packet.SELECTED_ARCHITECTURE_ID
SELECTED_ARCHITECTURE_NAME = packet.SELECTED_ARCHITECTURE_NAME
CANDIDATE_ID = packet.CANDIDATE_ID
CANDIDATE_VERSION = packet.CANDIDATE_VERSION

VALIDATION_REASON_CODES = (
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RECEIPT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPORT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ARCHITECTURE_MISMATCH",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_HASH_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_MANIFEST_HASH_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_SEMANTIC_HASH_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COURT_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_SOURCE_PACKET_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ADMISSIBILITY_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRIAGE_CORE_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRACE_SCHEMA_BINDING_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_STATIC_COMPARATOR_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPARATOR_NOT_FROZEN",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPARATOR_WEAKENING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_NOT_FROZEN",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_WIDENING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ROUTE_VALUE_CONTRACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_DISQUALIFIER_LEDGER_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPLAY_MANIFEST_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXPECTED_ARTIFACTS_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXTERNAL_VERIFIER_REQUIREMENTS_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPLAY_MANIFEST_JSON_ARTIFACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPLAY_MANIFEST_TEXT_ARTIFACT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ADMISSIBILITY_REPORT_MISSING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_SELF_REPLAY_HANDOFF_FALSE_FAIL",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MUTABLE_HANDOFF_NOT_BOUND",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_PARTIAL_WIN_ALLOWED",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_DISQUALIFIER_INCOMPLETE",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXTERNAL_VERIFIER_EXECUTING",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXECUTION_EXECUTED",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_SUPERIORITY_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ACTIVATION_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_AFSH_SHADOW_PACKET_VAL_NEXT_MOVE_DRIFT",
)

TERMINAL_DEFECTS = (
    "CONTRACT_MISSING",
    "CANDIDATE_HASH_MISSING",
    "UNIVERSE_BINDING_MISSING",
    "COURT_BINDING_MISSING",
    "SOURCE_PACKET_BINDING_MISSING",
    "ADMISSIBILITY_BINDING_MISSING",
    "COMPARATOR_WEAKENING",
    "METRIC_WIDENING",
    "DISQUALIFIER_LEDGER_MISSING",
    "RESULT_PARTIAL_WIN_ALLOWED",
    "MULTIPLE_HASH_BINDING_SOURCES",
    "MUTABLE_HANDOFF_NOT_BOUND",
    "PREP_ONLY_AUTHORITY_DRIFT",
    "EXECUTION_EXECUTED",
    "R6_OPEN_DRIFT",
    "SUPERIORITY_DRIFT",
    "ACTIVATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)

REQUIRED_BINDING_HASH_KEYS = (
    "candidate_manifest_hash",
    "candidate_artifact_hash",
    "candidate_semantic_hash",
    "candidate_envelope_hash",
    "validated_blind_universe_hash",
    "validated_court_hash",
    "validated_source_packet_hash",
    "admissibility_receipt_hash",
    "numeric_triage_emit_core_hash",
    "triage_tag_schema_hash",
    "triage_score_schema_hash",
    "triage_receipt_schema_hash",
    "trace_schema_hash",
)

HASH_TO_INPUT_ROLE = {
    "candidate_manifest_hash": "candidate_manifest",
    "candidate_artifact_hash": "candidate_artifact",
    "admissibility_receipt_hash": "admissibility_receipt",
    "numeric_triage_emit_core_hash": "numeric_triage_emit_core",
    "triage_tag_schema_hash": "triage_tag_schema",
    "triage_score_schema_hash": "triage_score_schema",
    "triage_receipt_schema_hash": "triage_receipt_schema",
    "trace_schema_hash": "trace_schema_admissibility",
}

PREP_ONLY_PACKET_ROLES = (
    "execution_prep_only_draft",
    "result_schema_prep_only_draft",
    "activation_review_packet_prep_only_draft",
    "superiority_not_earned_closeout_prep_only_draft",
    "forensic_invalidation_court_prep_only_draft",
)

PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if not filename.endswith(".md")
}
PACKET_TEXT_INPUTS = {
    "packet_report": f"KT_PROD_CLEANROOM/reports/{packet.OUTPUTS['packet_report']}",
}
REFERENCE_JSON_INPUTS = {
    "turboquant_translation": packet.INPUTS["turboquant_translation"],
    "compressed_receipt_index": packet.INPUTS["compressed_receipt_index"],
}
MUTABLE_HANDOFF_ROLES = frozenset({"next_lawful_move"})

OUTPUTS = {
    "validation_contract": "b04_r6_afsh_shadow_screen_packet_validation_contract.json",
    "validation_receipt": "b04_r6_afsh_shadow_screen_packet_validation_receipt.json",
    "validation_report": "b04_r6_afsh_shadow_screen_packet_validation_report.md",
    "packet_contract_validation": "b04_r6_afsh_shadow_screen_packet_contract_validation_receipt.json",
    "candidate_binding_validation": "b04_r6_afsh_shadow_screen_candidate_binding_validation_receipt.json",
    "universe_binding_validation": "b04_r6_afsh_shadow_screen_universe_binding_validation_receipt.json",
    "court_binding_validation": "b04_r6_afsh_shadow_screen_court_binding_validation_receipt.json",
    "source_packet_binding_validation": "b04_r6_afsh_shadow_screen_source_packet_binding_validation_receipt.json",
    "admissibility_binding_validation": "b04_r6_afsh_shadow_screen_admissibility_binding_validation_receipt.json",
    "triage_core_binding_validation": "b04_r6_afsh_shadow_screen_triage_core_binding_validation_receipt.json",
    "trace_schema_binding_validation": "b04_r6_afsh_shadow_screen_trace_schema_binding_validation_receipt.json",
    "static_comparator_validation": "b04_r6_afsh_shadow_screen_static_comparator_validation_receipt.json",
    "metric_contract_validation": "b04_r6_afsh_shadow_screen_metric_contract_validation_receipt.json",
    "route_value_validation": "b04_r6_afsh_shadow_screen_route_value_validation_receipt.json",
    "disqualifier_validation": "b04_r6_afsh_shadow_screen_disqualifier_validation_receipt.json",
    "result_interpretation_validation": "b04_r6_afsh_shadow_screen_result_interpretation_validation_receipt.json",
    "replay_manifest_validation": "b04_r6_afsh_shadow_screen_replay_manifest_validation_receipt.json",
    "expected_artifact_validation": "b04_r6_afsh_shadow_screen_expected_artifact_validation_receipt.json",
    "external_verifier_validation": "b04_r6_afsh_shadow_screen_external_verifier_validation_receipt.json",
    "prep_only_non_authority_validation": "b04_r6_afsh_shadow_screen_prep_only_non_authority_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_afsh_shadow_screen_no_authorization_drift_validation_receipt.json",
    "trust_zone_validation": "b04_r6_afsh_shadow_screen_trust_zone_validation_receipt.json",
    "replay_binding_validation": "b04_r6_afsh_shadow_screen_replay_binding_validation_receipt.json",
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


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and bool(payload.get(key)):
        _fail(code, f"{label} sets forbidden true flag: {key}")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    for key in packet.FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label, code="RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXECUTION_EXECUTED")
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        for key in packet.FORBIDDEN_TRUE_KEYS:
            _ensure_false_if_present(
                state,
                key,
                label=f"{label}.authorization_state",
                code="RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXECUTION_EXECUTED",
            )
        if state.get("learned_router_superiority") not in (None, "UNEARNED"):
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_SUPERIORITY_DRIFT", f"{label} claims superiority")
        if state.get("package_promotion") not in (None, "DEFERRED"):
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("learned_router_superiority_earned") is True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_SUPERIORITY_DRIFT", f"{label} claims superiority")
    if payload.get("truth_engine_derivation_law_unchanged") is False or payload.get("truth_engine_law_changed") is True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRUTH_ENGINE_MUTATION", f"{label} mutates truth-engine law")
    if payload.get("trust_zone_law_unchanged") is False or payload.get("trust_zone_law_changed") is True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRUST_ZONE_MUTATION", f"{label} mutates trust-zone law")


def _input_hashes(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted({**PACKET_JSON_INPUTS, **REFERENCE_JSON_INPUTS}.items()):
        path = common.resolve_path(root, raw)
        row = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_shadow_screen_packet_validation",
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
                "binding_kind": "file_sha256_at_shadow_screen_packet_validation",
            }
        )
    return rows


def _input_binding_sha(bindings: Iterable[Dict[str, Any]], role: str) -> str:
    matches = [str(row.get("sha256", "")).strip() for row in bindings if row.get("role") == role]
    if len(matches) != 1:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", f"expected exactly one input binding for {role}")
    return matches[0]


def _validate_next_handoff(next_payload: Dict[str, Any]) -> Dict[str, bool]:
    predecessor = (
        next_payload.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and next_payload.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    self_replay = (
        next_payload.get("selected_outcome") == SELECTED_OUTCOME
        and next_payload.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )
    if not (predecessor or self_replay):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_NEXT_MOVE_DRIFT", "next lawful move receipt is neither packet predecessor nor validation self-replay")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _packet_report_valid(text: str) -> None:
    lowered = text.lower()
    if "shadow-screen" not in lowered or "does not execute" not in lowered:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPORT_MISSING", "packet report must describe non-executing shadow-screen packet")


def _ensure_packet_identity(payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> str:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    _packet_report_valid(text_payloads["packet_report"])
    for role, payload in payloads.items():
        _ensure_boundaries(payload, label=role)
        if role in PREP_ONLY_PACKET_ROLES:
            if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
                _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} must remain PREP_ONLY")
            continue
        if role == "future_blocker_register":
            continue
        if role == "next_lawful_move":
            _validate_next_handoff(payload)
            continue
        if payload.get("status") != "PASS":
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_CONTRACT_MISSING", f"{role} must be PASS")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_NEXT_MOVE_DRIFT", f"{role} previous packet outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_NEXT_MOVE_DRIFT", f"{role} previous packet next move drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_RECEIPT_MISSING", "packet receipt outcome drift")
    if contract.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_CONTRACT_MISSING", "packet contract authoritative lane drift")
    if contract.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_ARCHITECTURE_MISMATCH", "AFSH architecture drift")
    if contract.get("candidate_id") != CANDIDATE_ID:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_BINDING_MISSING", "candidate identity drift")
    packet_replay_head = str(contract.get("current_git_head", "")).strip()
    if not packet_replay_head or packet_replay_head != str(receipt.get("current_git_head", "")).strip():
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MAIN_HEAD_MISMATCH", "packet replay head missing or inconsistent")
    return packet_replay_head


def _validate_binding_hashes(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    replay_manifest = payloads["replay_manifest"]
    hashes = contract.get("binding_hashes")
    if not isinstance(hashes, dict):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_HASH_MISSING", "packet contract binding_hashes missing")
    for key in REQUIRED_BINDING_HASH_KEYS:
        if not _is_sha256(hashes.get(key)):
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_HASH_MISSING", f"binding hash missing or invalid: {key}")
    if receipt.get("binding_hashes") != hashes:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", "packet receipt binding_hashes do not match contract")
    if replay_manifest.get("binding_hashes") != hashes:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", "replay manifest binding_hashes do not match contract")

    input_bindings = contract.get("input_bindings")
    if not isinstance(input_bindings, list):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", "contract input_bindings missing")
    roles = [row.get("role") for row in input_bindings]
    if len(roles) != len(set(roles)):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", "duplicate input binding roles")
    for hash_key, role in HASH_TO_INPUT_ROLE.items():
        if _input_binding_sha(input_bindings, role) != hashes[hash_key]:
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", f"{hash_key} does not source from input_bindings role {role}")
    handoff_rows = [row for row in input_bindings if row.get("role") == "previous_next_lawful_move"]
    if len(handoff_rows) != 1:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MUTABLE_HANDOFF_NOT_BOUND", "packet mutable handoff row missing")
    handoff = handoff_rows[0]
    if handoff.get("binding_kind") != "git_object_before_overwrite" or not handoff.get("git_commit"):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MUTABLE_HANDOFF_NOT_BOUND", "packet handoff must be git-object-bound before overwrite")
    return {key: str(value) for key, value in hashes.items()}


def _validate_replay_manifest(payloads: Dict[str, Dict[str, Any]]) -> None:
    manifest = payloads["replay_manifest"]
    expected_json = set(manifest.get("expected_json_artifact_roles") or [])
    expected_text = set(manifest.get("expected_text_artifact_roles") or [])
    expected_all = set(manifest.get("expected_artifact_roles") or [])
    missing_json = set(packet.INPUTS) - expected_json
    if missing_json:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPLAY_MANIFEST_JSON_ARTIFACT_MISSING", f"missing JSON artifact roles: {sorted(missing_json)}")
    if "admissibility_report" not in expected_text:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_ADMISSIBILITY_REPORT_MISSING", "admissibility_report missing from text artifacts")
    if not expected_json.issubset(expected_all) or not expected_text.issubset(expected_all):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXPECTED_ARTIFACTS_MISSING", "expected artifact role union incomplete")
    if manifest.get("raw_hash_bound_artifacts_required") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXPECTED_ARTIFACTS_MISSING", "raw hash-bound artifacts not required")
    if manifest.get("compressed_indexes_are_retrieval_aids_only") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT", "compressed indexes must remain retrieval aids only")


def _validate_contract_surfaces(payloads: Dict[str, Dict[str, Any]]) -> None:
    comparator = payloads["static_comparator_contract"]
    metric = payloads["metric_contract"]
    route_value = payloads["route_value_contract"]
    disqualifiers = payloads["disqualifier_ledger"]
    result = payloads["result_interpretation_contract"]
    expected = payloads["expected_artifact_manifest"]
    external = payloads["external_verifier_requirements"]
    no_drift = payloads["no_authorization_drift_receipt"]

    if comparator.get("comparator_must_be_frozen") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPARATOR_NOT_FROZEN", "static comparator not frozen")
    if comparator.get("comparator_weakening_forbidden") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPARATOR_WEAKENING", "comparator weakening not forbidden")
    if metric.get("metrics_frozen_before_execution") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_NOT_FROZEN", "metrics not frozen before execution")
    if metric.get("metric_widening_forbidden") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_WIDENING", "metric widening not forbidden")
    missing_metrics = [name for name in packet.PRIMARY_METRICS if name not in metric.get("primary_metrics", [])]
    if missing_metrics:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_CONTRACT_MISSING", f"missing primary metrics: {missing_metrics}")
    if route_value.get("current_route_value_formula_mutation_allowed") is not False:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_WIDENING", "current route-value formula mutation allowed")
    if route_value.get("route_value_threshold_profile_frozen") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_ROUTE_VALUE_CONTRACT_MISSING", "route value threshold not frozen")

    classes = set(disqualifiers.get("disqualifier_classes") or [])
    missing_classes = [name for name in packet.DISQUALIFIER_CLASSES if name not in classes]
    if missing_classes:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_DISQUALIFIER_INCOMPLETE", f"missing disqualifier classes: {missing_classes}")
    terminals = set(disqualifiers.get("terminal_disqualifiers") or [])
    missing_terminals = [name for name in packet.TERMINAL_DISQUALIFIERS if name not in terminals]
    if missing_terminals:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_DISQUALIFIER_INCOMPLETE", f"missing terminal disqualifiers: {missing_terminals}")
    if disqualifiers.get("any_terminal_disqualifier_invalidates_future_screen") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_DISQUALIFIER_INCOMPLETE", "terminal disqualifiers must invalidate screen")

    if result.get("partial_win_cannot_claim_superiority") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_PARTIAL_WIN_ALLOWED", "partial win can claim superiority")
    if result.get("superiority_cannot_be_earned_unless_all_required_conditions_pass") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING", "all success conditions not required")
    missing_success = [name for name in packet.SUCCESS_CONDITIONS if name not in result.get("required_success_conditions", [])]
    if missing_success:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING", f"missing success conditions: {missing_success}")
    future_outcomes = set(result.get("future_screen_allowed_outcomes") or [])
    if "B04_R6_AFSH_SHADOW_SUPERIORITY_FAILED__SUPERIORITY_NOT_EARNED_CLOSEOUT_OR_REDESIGN_NEXT" not in future_outcomes:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING", "failure outcome missing")
    if "B04_R6_AFSH_SHADOW_SCREEN_INVALIDATED__FORENSIC_INVALIDATION_COURT_NEXT" not in future_outcomes:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING", "invalidation outcome missing")

    expected_artifacts = set(expected.get("packet_artifacts") or [])
    missing_packet_outputs = [filename for filename in packet.OUTPUTS.values() if filename not in expected_artifacts]
    if missing_packet_outputs:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXPECTED_ARTIFACTS_MISSING", f"expected manifest misses packet outputs: {missing_packet_outputs}")
    if external.get("authority") != "NON_EXECUTING_REQUIREMENTS":
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXTERNAL_VERIFIER_EXECUTING", "external verifier authority must be non-executing")
    if external.get("cannot_execute_shadow_screen") is not True or external.get("cannot_claim_superiority") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXTERNAL_VERIFIER_EXECUTING", "external verifier can execute or claim")
    if external.get("compressed_index_cannot_be_source_of_truth") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT", "external verifier lets compressed index become truth")
    if no_drift.get("no_downstream_authorization_drift") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", "no authorization drift receipt missing pass")


def _validate_memory_prep(reference_payloads: Dict[str, Dict[str, Any]]) -> None:
    turbo = reference_payloads["turboquant_translation"]
    compressed = reference_payloads["compressed_receipt_index"]
    for label, payload in (("turboquant_translation", turbo), ("compressed_receipt_index", compressed)):
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{label} must remain PREP_ONLY")
        if payload.get("raw_hash_bound_artifact_required") is not True:
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT", f"{label} must require raw hash-bound artifacts")
    if compressed.get("compressed_index_is_source_of_truth") is not False:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT", "compressed index is source of truth")
    if compressed.get("raw_hash_bound_artifact_required_after_retrieval") is not True:
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT", "raw artifact not required after retrieval")


def _validate_prep_only_drafts(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in PREP_ONLY_PACKET_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} authority drift")
        forbidden = (
            "cannot_authorize_shadow_screen_execution",
            "cannot_execute_shadow_screen",
            "cannot_claim_superiority",
            "cannot_open_r6",
            "cannot_authorize_activation",
            "cannot_authorize_package_promotion",
        )
        for key in forbidden:
            if payload.get(key) is not True:
                _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} missing {key}")


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("validation_contract_preserves_current_main_head", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MAIN_HEAD_MISMATCH", "validation binds current main head", group="core"),
        _pass_row("validation_binds_selected_afsh_architecture", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD selected", group="core"),
        _pass_row("validation_binds_shadow_packet_contract", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CONTRACT_MISSING", "packet contract bound", group="packet"),
        _pass_row("validation_binds_shadow_packet_receipt", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RECEIPT_MISSING", "packet receipt bound", group="packet"),
        _pass_row("validation_binds_shadow_packet_report", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPORT_MISSING", "packet report bound", group="packet"),
        _pass_row("candidate_binding_receipt_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_BINDING_MISSING", "candidate binding receipt exists", group="candidate"),
        _pass_row("candidate_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_HASH_MISSING", "candidate artifact hash bound", group="candidate"),
        _pass_row("candidate_manifest_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_MANIFEST_HASH_MISSING", "candidate manifest hash bound", group="candidate"),
        _pass_row("candidate_semantic_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_CANDIDATE_SEMANTIC_HASH_MISSING", "candidate semantic hash bound", group="candidate"),
        _pass_row("validated_blind_universe_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_UNIVERSE_BINDING_MISSING", "validated blind-universe hash bound", group="binding"),
        _pass_row("validated_route_value_court_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COURT_BINDING_MISSING", "validated court hash bound", group="binding"),
        _pass_row("validated_source_packet_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_SOURCE_PACKET_BINDING_MISSING", "validated source-packet hash bound", group="binding"),
        _pass_row("admissibility_receipt_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ADMISSIBILITY_BINDING_MISSING", "admissibility receipt hash bound", group="binding"),
        _pass_row("numeric_triage_core_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRIAGE_CORE_BINDING_MISSING", "numeric triage hash bound", group="binding"),
        _pass_row("triage_tag_schema_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRIAGE_CORE_BINDING_MISSING", "triage tag schema hash bound", group="binding"),
        _pass_row("triage_score_schema_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRIAGE_CORE_BINDING_MISSING", "triage score schema hash bound", group="binding"),
        _pass_row("triage_receipt_schema_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRIAGE_CORE_BINDING_MISSING", "triage receipt schema hash bound", group="binding"),
        _pass_row("trace_schema_hash_bound", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRACE_SCHEMA_BINDING_MISSING", "trace schema hash bound", group="binding"),
        _pass_row("static_comparator_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_STATIC_COMPARATOR_MISSING", "comparator contract exists", group="comparator"),
        _pass_row("static_comparator_is_frozen", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPARATOR_NOT_FROZEN", "comparator frozen", group="comparator"),
        _pass_row("static_comparator_weakening_forbidden", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPARATOR_WEAKENING", "comparator weakening forbidden", group="comparator"),
        _pass_row("metric_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_CONTRACT_MISSING", "metric contract exists", group="metric"),
        _pass_row("metric_contract_is_frozen_before_execution", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_NOT_FROZEN", "metrics frozen", group="metric"),
        _pass_row("metric_widening_forbidden", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_WIDENING", "metric widening forbidden", group="metric"),
        _pass_row("route_value_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ROUTE_VALUE_CONTRACT_MISSING", "route-value contract exists", group="metric"),
        _pass_row("disqualifier_ledger_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_DISQUALIFIER_LEDGER_MISSING", "disqualifier ledger exists", group="disqualifier"),
        _pass_row("result_interpretation_contract_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING", "result interpretation exists", group="result"),
        _pass_row("replay_manifest_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPLAY_MANIFEST_MISSING", "replay manifest exists", group="replay"),
        _pass_row("expected_artifact_manifest_exists", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXPECTED_ARTIFACTS_MISSING", "expected artifact manifest exists", group="replay"),
        _pass_row("external_verifier_requirements_exist", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXTERNAL_VERIFIER_REQUIREMENTS_MISSING", "external verifier requirements exist", group="external"),
        _pass_row("replay_manifest_includes_required_json_artifacts", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPLAY_MANIFEST_JSON_ARTIFACT_MISSING", "JSON replay artifacts included", group="replay"),
        _pass_row("replay_manifest_includes_required_text_artifacts", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_REPLAY_MANIFEST_TEXT_ARTIFACT_MISSING", "text replay artifacts included", group="replay"),
        _pass_row("replay_manifest_includes_admissibility_report", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ADMISSIBILITY_REPORT_MISSING", "admissibility report included", group="replay"),
        _pass_row("bound_file_hashes_come_from_single_input_bindings_path", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", "bound file hashes source from input_bindings", group="replay"),
        _pass_row("mixed_hash_binding_sources_fail_closed", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MULTIPLE_HASH_BINDING_SOURCES", "mixed binding sources fail closed", group="replay"),
        _pass_row("packet_self_replay_handoff_allowed_without_next_move_drift", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_SELF_REPLAY_HANDOFF_FALSE_FAIL", "self replay handoff allowed", group="replay"),
        _pass_row("mutable_next_lawful_move_handoff_bound_before_overwrite", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MUTABLE_HANDOFF_NOT_BOUND", "mutable handoff git-object-bound", group="replay"),
        _pass_row("valid_prior_lane_authoritative_branch_artifacts_are_accepted", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MAIN_HEAD_MISMATCH", "valid prior-lane artifacts accepted", group="replay"),
        _pass_row("invalid_prior_lane_branch_artifacts_fail_closed", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_MAIN_HEAD_MISMATCH", "invalid prior-lane artifacts fail closed", group="replay"),
        _pass_row("result_interpretation_prevents_partial_win_from_superiority", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_PARTIAL_WIN_ALLOWED", "partial wins cannot claim superiority", group="result"),
        _pass_row("result_interpretation_requires_all_success_conditions", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING", "all success conditions required", group="result"),
        _pass_row("result_interpretation_preserves_failed_deferred_invalidated_outcomes", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING", "failure/deferred/invalidated outcomes preserved", group="result"),
        _pass_row("external_verifier_requirements_are_non_executing", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXTERNAL_VERIFIER_EXECUTING", "external verifier non-executing", group="external"),
        _pass_row("external_verifier_requirements_do_not_claim_superiority", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXTERNAL_VERIFIER_EXECUTING", "external verifier cannot claim superiority", group="external"),
        _pass_row("compressed_index_cannot_be_source_of_truth", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT", "compressed index not truth", group="memory"),
        _pass_row("raw_hash_bound_artifact_required_after_compressed_retrieval", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPRESSED_INDEX_TRUTH_DRIFT", "raw artifacts required after compressed retrieval", group="memory"),
        _pass_row("shadow_execution_prep_only_draft_remains_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", "execution draft prep-only", group="prep_only"),
        _pass_row("shadow_result_schema_prep_only_draft_remains_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", "result schema draft prep-only", group="prep_only"),
        _pass_row("activation_review_packet_draft_remains_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", "activation draft prep-only", group="prep_only"),
        _pass_row("failure_closeout_contract_draft_remains_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", "failure closeout draft prep-only", group="prep_only"),
        _pass_row("forensic_invalidation_court_draft_remains_prep_only", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", "forensic invalidation draft prep-only", group="prep_only"),
        _pass_row("validation_does_not_execute_shadow_screen", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_EXECUTION_EXECUTED", "screen not executed", group="authorization"),
        _pass_row("validation_does_not_open_r6", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"),
        _pass_row("validation_does_not_claim_superiority", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_SUPERIORITY_DRIFT", "superiority unearned", group="authorization"),
        _pass_row("validation_does_not_authorize_activation_review", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_ACTIVATION_DRIFT", "activation unauthorized", group="authorization"),
        _pass_row("validation_does_not_authorize_package_promotion", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", group="authorization"),
        _pass_row("validation_does_not_mutate_metric_contract", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_METRIC_WIDENING", "metric contract not mutated", group="metric"),
        _pass_row("validation_does_not_weaken_static_comparator", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_COMPARATOR_WEAKENING", "static comparator not weakened", group="comparator"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", group="authorization"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRUST_ZONE_MUTATION", "trust-zone law unchanged", group="authorization"),
        _pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", "no authorization drift receipt passes", group="authorization"),
        _pass_row("next_lawful_move_is_run_shadow_screen", "RC_B04R6_AFSH_SHADOW_PACKET_VAL_NEXT_MOVE_DRIFT", "next lawful move is shadow screen execution lane", group="next_move"),
    ]
    rows.extend(
        _pass_row(
            f"disqualifier_ledger_marks_{name}_terminal",
            "RC_B04R6_AFSH_SHADOW_PACKET_VAL_DISQUALIFIER_INCOMPLETE",
            f"disqualifier ledger includes hard/terminal class {name}",
            group="disqualifier",
        )
        for name in packet.DISQUALIFIER_CLASSES
    )
    rows.extend(
        _pass_row(
            f"success_condition_requires_{name}",
            "RC_B04R6_AFSH_SHADOW_PACKET_VAL_RESULT_INTERPRETATION_MISSING",
            f"result interpretation requires {name}",
            group="result",
        )
        for name in packet.SUCCESS_CONDITIONS
    )
    return rows


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "shadow_screen_packet_validated": True,
        "shadow_screen_execution_authorized_in_this_lane": False,
        "shadow_screen_execution_next_lawful_lane": True,
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
    packet_replay_head: str,
    hashes: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
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
        "authorization_state": _authorization_state(),
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "shadow_screen_packet_validated": True,
        "shadow_screen_execution_authorized": False,
        "shadow_screen_execution_authorized_in_this_lane": False,
        "shadow_screen_execution_next_lawful_lane": True,
        "shadow_screen_executed": False,
        "activation_review_authorized": False,
        "runtime_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "allowed_outcomes": [OUTCOME_VALIDATED, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": [
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
        ],
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
        "# B04 R6 AFSH Shadow-Screen Execution Packet Validation",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "This validator reads and hashes the authored packet artifacts as frozen inputs. It does not execute the shadow screen, claim superiority, open R6, authorize activation/cutover, escalate to lobes, promote a package, or mutate truth/trust law.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 AFSH shadow-screen packet validation")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    packet_payloads = {role: _load(root, raw, label=role) for role, raw in PACKET_JSON_INPUTS.items()}
    reference_payloads = {role: _load(root, raw, label=role) for role, raw in REFERENCE_JSON_INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in PACKET_TEXT_INPUTS.items()}

    packet_replay_head = _ensure_packet_identity(packet_payloads, text_payloads)
    handoff_state = _validate_next_handoff(packet_payloads["next_lawful_move"])
    hashes = _validate_binding_hashes(packet_payloads)
    _validate_replay_manifest(packet_payloads)
    _validate_contract_surfaces(packet_payloads)
    _validate_memory_prep(reference_payloads)
    _validate_prep_only_drafts(packet_payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)
    handoff_input = [row for row in input_bindings if row.get("role") == "next_lawful_move"]
    if len(handoff_input) != 1 or handoff_input[0].get("binding_kind") != "git_object_before_overwrite":
        _fail("RC_B04R6_AFSH_SHADOW_PACKET_VAL_MUTABLE_HANDOFF_NOT_BOUND", "validation next handoff must be git-object-bound before overwrite")

    rows = _validation_rows()
    generated_utc = utc_now_iso_z()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        packet_replay_head=packet_replay_head,
        hashes=hashes,
    )
    common_extra = {
        "packet_contract_hash": file_sha256(common.resolve_path(root, PACKET_JSON_INPUTS["packet_contract"])),
        "packet_receipt_hash": file_sha256(common.resolve_path(root, PACKET_JSON_INPUTS["packet_receipt"])),
        "packet_report_hash": file_sha256(common.resolve_path(root, PACKET_TEXT_INPUTS["packet_report"])),
        "handoff_state": handoff_state,
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
            "kt.b04_r6.afsh_shadow_screen_packet_validation_contract.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_PACKET_VALIDATION_CONTRACT",
            ("core", "packet", "candidate", "binding", "comparator", "metric", "disqualifier", "result", "replay", "external", "memory", "prep_only", "authorization", "next_move"),
            {
                "validator_role": "READ_HASH_ATTACK_AUTHORED_PACKET_ARTIFACTS",
                "packet_state_before_validation": "BOUND_NOT_VALIDATED",
                "packet_state_after_validation": "BOUND_AND_VALIDATED",
                "execution_authorized_by_this_validation_lane": False,
                "shadow_screen_execution_next_lawful_lane": True,
            },
        ),
        OUTPUTS["validation_receipt"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_packet_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_PACKET_VALIDATION_RECEIPT",
            ("core", "packet", "candidate", "binding", "comparator", "metric", "disqualifier", "result", "replay", "external", "memory", "prep_only", "authorization", "next_move"),
        ),
        OUTPUTS["packet_contract_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_packet_contract_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_PACKET_CONTRACT_VALIDATION_RECEIPT",
            ("core", "packet"),
        ),
        OUTPUTS["candidate_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_candidate_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_CANDIDATE_BINDING_VALIDATION_RECEIPT",
            ("candidate",),
            {"candidate_hash": hashes["candidate_artifact_hash"], "candidate_manifest_hash": hashes["candidate_manifest_hash"], "candidate_semantic_hash": hashes["candidate_semantic_hash"]},
        ),
        OUTPUTS["universe_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_universe_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_UNIVERSE_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"validated_blind_universe_hash": hashes["validated_blind_universe_hash"]},
        ),
        OUTPUTS["court_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_court_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_COURT_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"validated_court_hash": hashes["validated_court_hash"]},
        ),
        OUTPUTS["source_packet_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_source_packet_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_SOURCE_PACKET_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"validated_source_packet_hash": hashes["validated_source_packet_hash"]},
        ),
        OUTPUTS["admissibility_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_admissibility_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_ADMISSIBILITY_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"admissibility_receipt_hash": hashes["admissibility_receipt_hash"]},
        ),
        OUTPUTS["triage_core_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_triage_core_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRIAGE_CORE_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"numeric_triage_emit_core_hash": hashes["numeric_triage_emit_core_hash"], "triage_tag_schema_hash": hashes["triage_tag_schema_hash"], "triage_score_schema_hash": hashes["triage_score_schema_hash"], "triage_receipt_schema_hash": hashes["triage_receipt_schema_hash"]},
        ),
        OUTPUTS["trace_schema_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_trace_schema_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRACE_SCHEMA_BINDING_VALIDATION_RECEIPT",
            ("binding",),
            {"trace_schema_hash": hashes["trace_schema_hash"]},
        ),
        OUTPUTS["static_comparator_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_static_comparator_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_STATIC_COMPARATOR_VALIDATION_RECEIPT",
            ("comparator",),
        ),
        OUTPUTS["metric_contract_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_metric_contract_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_METRIC_CONTRACT_VALIDATION_RECEIPT",
            ("metric",),
        ),
        OUTPUTS["route_value_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_route_value_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_ROUTE_VALUE_VALIDATION_RECEIPT",
            ("metric",),
        ),
        OUTPUTS["disqualifier_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_disqualifier_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_DISQUALIFIER_VALIDATION_RECEIPT",
            ("disqualifier",),
            {
                "disqualifier_classes": list(packet.DISQUALIFIER_CLASSES),
                "terminal_disqualifiers": list(packet.TERMINAL_DISQUALIFIERS),
                "hard_disqualifier_classes": list(packet.DISQUALIFIER_CLASSES),
            },
        ),
        OUTPUTS["result_interpretation_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_result_interpretation_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_RESULT_INTERPRETATION_VALIDATION_RECEIPT",
            ("result",),
            {"required_success_conditions": list(packet.SUCCESS_CONDITIONS), "future_screen_allowed_outcomes": list(packet.FUTURE_SCREEN_ALLOWED_OUTCOMES)},
        ),
        OUTPUTS["replay_manifest_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_replay_manifest_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_REPLAY_MANIFEST_VALIDATION_RECEIPT",
            ("replay",),
        ),
        OUTPUTS["expected_artifact_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_expected_artifact_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_EXPECTED_ARTIFACT_VALIDATION_RECEIPT",
            ("replay",),
        ),
        OUTPUTS["external_verifier_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_external_verifier_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_EXTERNAL_VERIFIER_VALIDATION_RECEIPT",
            ("external", "memory"),
        ),
        OUTPUTS["prep_only_non_authority_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_prep_only_non_authority_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_PREP_ONLY_NON_AUTHORITY_VALIDATION_RECEIPT",
            ("prep_only", "memory"),
        ),
        OUTPUTS["no_authorization_drift_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_no_authorization_drift_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            ("authorization", "next_move"),
            {"no_downstream_authorization_drift": True},
        ),
        OUTPUTS["trust_zone_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_trust_zone_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_TRUST_ZONE_VALIDATION_RECEIPT",
            ("authorization",),
        ),
        OUTPUTS["replay_binding_validation"]: receipt(
            "kt.b04_r6.afsh_shadow_screen_replay_binding_validation_receipt.v1",
            "B04_R6_AFSH_SHADOW_SCREEN_REPLAY_BINDING_VALIDATION_RECEIPT",
            ("replay",),
            {"packet_replay_binding_head": packet_replay_head, "mutable_handoff_bound_before_overwrite": True},
        ),
        OUTPUTS["next_lawful_move"]: receipt(
            "kt.operator.b04_r6_next_lawful_move_receipt.v13",
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
    parser = argparse.ArgumentParser(description="Validate B04 R6 AFSH shadow-screen execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=Path(args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
