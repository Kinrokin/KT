from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from tools.operator import cohort0_b04_r6_runtime_cutover_execution_packet as packet
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/b04-r6-runtime-cutover-execution-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-runtime-cutover-execution-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_VALIDATION"
PREVIOUS_LANE = packet.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = packet.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = packet.VALIDATION_SUCCESS_OUTCOME
NEXT_LAWFUL_MOVE = packet.VALIDATION_SUCCESS_NEXT_MOVE
OUTCOME_DEFERRED = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_REJECTED__CUTOVER_EXECUTION_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_INVALID__FORENSIC_CUTOVER_EXECUTION_REVIEW_NEXT"

FORBIDDEN_ACTIONS = (
    "RUNTIME_CUTOVER_EXECUTED",
    "ACTIVATION_CUTOVER_EXECUTED",
    "R6_OPEN",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED",
)
TEXT_FORBIDDEN_CLAIMS = {
    "RUNTIME CUTOVER EXECUTED": "RC_B04R6_CUTOVER_EXEC_VAL_RUNTIME_CUTOVER_EXECUTED",
    "RUNTIME_CUTOVER_EXECUTED": "RC_B04R6_CUTOVER_EXEC_VAL_RUNTIME_CUTOVER_EXECUTED",
    "ACTIVATION CUTOVER EXECUTED": "RC_B04R6_CUTOVER_EXEC_VAL_ACTIVATION_CUTOVER_EXECUTED",
    "ACTIVATION_CUTOVER_EXECUTED": "RC_B04R6_CUTOVER_EXEC_VAL_ACTIVATION_CUTOVER_EXECUTED",
    "R6 OPEN": "RC_B04R6_CUTOVER_EXEC_VAL_R6_OPEN_DRIFT",
    "R6_OPEN": "RC_B04R6_CUTOVER_EXEC_VAL_R6_OPEN_DRIFT",
    "PACKAGE PROMOTION AUTHORIZED": "RC_B04R6_CUTOVER_EXEC_VAL_PACKAGE_PROMOTION_DRIFT",
    "PACKAGE_PROMOTION_AUTHORIZED": "RC_B04R6_CUTOVER_EXEC_VAL_PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL ACTIVATION CLAIM AUTHORIZED": "RC_B04R6_CUTOVER_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED": "RC_B04R6_CUTOVER_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT",
    "GLOBAL RUNTIME SURFACE AUTHORIZED": "RC_B04R6_CUTOVER_EXEC_VAL_GLOBAL_SURFACE_DRIFT",
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED": "RC_B04R6_CUTOVER_EXEC_VAL_GLOBAL_SURFACE_DRIFT",
}

AUTHORITY_DRIFT_KEYS = {
    "runtime_cutover_authorized": "RC_B04R6_CUTOVER_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "runtime_cutover_executed": "RC_B04R6_CUTOVER_EXEC_VAL_RUNTIME_CUTOVER_EXECUTED",
    "activation_cutover_executed": "RC_B04R6_CUTOVER_EXEC_VAL_ACTIVATION_CUTOVER_EXECUTED",
    "r6_open": "RC_B04R6_CUTOVER_EXEC_VAL_R6_OPEN_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_CUTOVER_EXEC_VAL_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_CUTOVER_EXEC_VAL_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_CUTOVER_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_CUTOVER_EXEC_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_CUTOVER_EXEC_VAL_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_CUTOVER_EXEC_VAL_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_CUTOVER_EXEC_VAL_COMPARATOR_WEAKENED",
    "global_runtime_surface_authorized": "RC_B04R6_CUTOVER_EXEC_VAL_GLOBAL_SURFACE_DRIFT",
}

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_CUTOVER_EXEC_VAL_PACKET_MISSING",
            "RC_B04R6_CUTOVER_EXEC_VAL_PACKET_OUTCOME_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_VAL_NEXT_MOVE_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_VAL_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_CUTOVER_EXEC_VAL_CONTROL_CONTRACT_MISSING",
            "RC_B04R6_CUTOVER_EXEC_VAL_PREP_ONLY_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_VAL_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_VAL_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}" for role, filename in packet.OUTPUTS.items() if filename.endswith(".json")
}
PACKET_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if not filename.endswith(".json")
}

VALIDATION_RECEIPT_ROLES = (
    "packet_binding_validation",
    "mode_validation",
    "scope_validation",
    "allowed_case_class_validation",
    "excluded_case_class_validation",
    "traffic_limit_validation",
    "static_fallback_validation",
    "abstention_fallback_validation",
    "null_route_preservation_validation",
    "operator_override_validation",
    "kill_switch_validation",
    "rollback_validation",
    "route_distribution_threshold_validation",
    "drift_threshold_validation",
    "incident_freeze_validation",
    "runtime_receipt_schema_validation",
    "replay_manifest_validation",
    "expected_artifact_manifest_validation",
    "external_verifier_validation",
    "result_interpretation_validation",
    "commercial_claim_boundary_validation",
    "package_promotion_prohibition_validation",
)

PREP_ONLY_OUTPUT_ROLES = (
    "runtime_cutover_run_prep_only_draft",
    "post_cutover_evidence_review_packet_prep_only_draft",
    "rollback_freeze_incident_path_prep_only",
)

OUTPUTS = {
    "validation_contract": "b04_r6_runtime_cutover_execution_packet_validation_contract.json",
    "validation_receipt": "b04_r6_runtime_cutover_execution_packet_validation_receipt.json",
    "validation_report": "b04_r6_runtime_cutover_execution_packet_validation_report.md",
    "packet_binding_validation": "b04_r6_runtime_cutover_execution_packet_binding_validation_receipt.json",
    "mode_validation": "b04_r6_runtime_cutover_execution_mode_validation_receipt.json",
    "scope_validation": "b04_r6_runtime_cutover_execution_scope_validation_receipt.json",
    "allowed_case_class_validation": "b04_r6_runtime_cutover_execution_allowed_case_class_validation_receipt.json",
    "excluded_case_class_validation": "b04_r6_runtime_cutover_execution_excluded_case_class_validation_receipt.json",
    "traffic_limit_validation": "b04_r6_runtime_cutover_execution_traffic_limit_validation_receipt.json",
    "static_fallback_validation": "b04_r6_runtime_cutover_execution_static_fallback_validation_receipt.json",
    "abstention_fallback_validation": "b04_r6_runtime_cutover_execution_abstention_fallback_validation_receipt.json",
    "null_route_preservation_validation": "b04_r6_runtime_cutover_execution_null_route_validation_receipt.json",
    "operator_override_validation": "b04_r6_runtime_cutover_execution_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_runtime_cutover_execution_kill_switch_validation_receipt.json",
    "rollback_validation": "b04_r6_runtime_cutover_execution_rollback_validation_receipt.json",
    "route_distribution_threshold_validation": (
        "b04_r6_runtime_cutover_execution_route_distribution_threshold_validation_receipt.json"
    ),
    "drift_threshold_validation": "b04_r6_runtime_cutover_execution_drift_threshold_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_runtime_cutover_execution_incident_freeze_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_runtime_cutover_execution_runtime_receipt_schema_validation_receipt.json",
    "replay_manifest_validation": "b04_r6_runtime_cutover_execution_replay_manifest_validation_receipt.json",
    "expected_artifact_manifest_validation": (
        "b04_r6_runtime_cutover_execution_expected_artifact_manifest_validation_receipt.json"
    ),
    "external_verifier_validation": "b04_r6_runtime_cutover_execution_external_verifier_validation_receipt.json",
    "result_interpretation_validation": "b04_r6_runtime_cutover_execution_result_interpretation_validation_receipt.json",
    "commercial_claim_boundary_validation": (
        "b04_r6_runtime_cutover_execution_commercial_claim_boundary_validation_receipt.json"
    ),
    "package_promotion_prohibition_validation": (
        "b04_r6_runtime_cutover_execution_package_promotion_prohibition_validation_receipt.json"
    ),
    "prep_only_boundary_validation": "b04_r6_runtime_cutover_execution_prep_only_boundary_validation_receipt.json",
    "no_authorization_drift_validation": (
        "b04_r6_runtime_cutover_execution_no_authorization_drift_validation_receipt.json"
    ),
    "runtime_cutover_run_prep_only_draft": "b04_r6_runtime_cutover_run_prep_only_draft.json",
    "post_cutover_evidence_review_packet_prep_only_draft": (
        "b04_r6_post_cutover_evidence_review_after_execution_validation_prep_only_draft.json"
    ),
    "rollback_freeze_incident_path_prep_only": (
        "b04_r6_runtime_cutover_execution_validation_rollback_freeze_incident_path_prep_only.json"
    ),
    "next_lawful_move": "b04_r6_runtime_cutover_execution_packet_validation_next_lawful_move_receipt.json",
}


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_CUTOVER_EXEC_VAL_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_CUTOVER_EXEC_VAL_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKET_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if key in AUTHORITY_DRIFT_KEYS and value is not False:
            _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted to {value!r}")
        if key == "r6" and isinstance(value, str) and value.upper() == "OPEN":
            _fail("RC_B04R6_CUTOVER_EXEC_VAL_R6_OPEN_DRIFT", f"{label}.{key} contains OPEN")
    if payload.get("package_promotion") not in (None, "DEFERRED", "BLOCKED"):
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _ensure_claim_boundary(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if not isinstance(value, str):
            continue
        key_lower = str(key).lower()
        if not any(marker in key_lower for marker in packet.CLAIM_BEARING_FIELD_MARKERS):
            continue
        upper = value.upper()
        if not any(token in upper for token in packet.POSITIVE_AUTHORITY_TOKENS):
            continue
        if any(qualifier in upper for qualifier in packet.NEGATIVE_AUTHORITY_QUALIFIERS):
            continue
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_CLAIM_TOKEN_DRIFT", f"{label}.{key} contains {value!r}")


def _load_packet_payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in PACKET_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in PACKET_TEXT_INPUTS.items()}
    return payloads, texts


def _validate_packet_payloads(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads.get("packet_contract")
    receipt = payloads.get("packet_receipt")
    next_move = payloads.get("next_lawful_move")
    if not contract or not receipt or not next_move:
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKET_MISSING", "execution packet core artifacts missing")
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKET_OUTCOME_DRIFT", "execution packet outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKET_OUTCOME_DRIFT", "execution receipt outcome drifted")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_NEXT_MOVE_DRIFT", "execution packet next move drifted")
    if not contract.get("input_bindings"):
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_INPUT_BINDINGS_EMPTY", "execution packet input_bindings empty")
    if contract.get("runtime_cutover_execution_packet_authored") is not True:
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKET_MISSING", "execution packet was not authored")
    if contract.get("runtime_cutover_execution_packet_validated") is not False:
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKET_OUTCOME_DRIFT", "input already claims validation")
    for role in packet.CONTROL_CONTRACT_ROLES:
        payload = payloads.get(role)
        if not payload or payload.get("control_status") != "DEFINED_FOR_VALIDATION":
            _fail("RC_B04R6_CUTOVER_EXEC_VAL_CONTROL_CONTRACT_MISSING", f"{role} missing or unbound")
    for role in packet.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads.get(role)
        if not payload or payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_CUTOVER_EXEC_VAL_PREP_ONLY_DRIFT", f"{role} not prep-only")
    report = texts.get("packet_report", "").lower()
    for phrase in ("does not execute runtime cutover", "does not open r6", "does not promote package"):
        if phrase not in report:
            _fail("RC_B04R6_CUTOVER_EXEC_VAL_PACKET_MISSING", f"packet report missing {phrase!r}")
    for role, payload in payloads.items():
        _ensure_authority_closed(payload, label=role)
        _ensure_claim_boundary(payload, label=role)
    for role, text in texts.items():
        upper = text.upper()
        for token, reason in TEXT_FORBIDDEN_CLAIMS.items():
            if token in upper:
                _fail(reason, f"{role} contains forbidden claim token {token!r}")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    bindings: list[Dict[str, str]] = []
    for role, raw in {**PACKET_JSON_INPUTS, **PACKET_TEXT_INPUTS}.items():
        bindings.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(root / raw),
                "binding_kind": "file_sha256_at_runtime_cutover_execution_packet_validation",
            }
        )
    return sorted(bindings, key=lambda item: item["role"])


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
) -> Dict[str, Any]:
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "current_branch": branch,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_REJECTED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "input_bindings": input_bindings,
        "binding_hashes": {f"{binding['role']}_hash": binding["sha256"] for binding in input_bindings},
        "runtime_cutover_review_validated": True,
        "runtime_cutover_authorization_packet_authored": True,
        "runtime_cutover_authorization_validated": True,
        "runtime_cutover_execution_packet_authored": True,
        "runtime_cutover_execution_packet_validated": True,
        "runtime_cutover_authorized": False,
        "runtime_cutover_executed": False,
        "activation_cutover_executed": False,
        "r6_open": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "global_runtime_surface_authorized": False,
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id})
    payload.update(extra)
    return payload


def _validation_receipt(base: Dict[str, Any], *, role: str, validated_role: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_execution_packet_validation.{role}.receipt.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_{role.upper()}",
        validation_status="PASS",
        validated_role=validated_role,
        validated_hash=base["binding_hashes"][f"{validated_role}_hash"],
        reason_code=None,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_execution_packet_validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_VALIDATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_runtime_cutover=True,
        cannot_execute_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
        cannot_authorize_global_runtime_surface=True,
    )


def _payloads(base: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {
        "validation_contract": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet_validation.contract.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_VALIDATION_CONTRACT",
            validation_scope="VALIDATE_RUNTIME_CUTOVER_EXECUTION_PACKET_ONLY",
            validation_success_next_authority=NEXT_LAWFUL_MOVE,
            does_not_execute_runtime_cutover=True,
        ),
        "validation_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet_validation.receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_VALIDATION_RECEIPT",
            verdict="VALIDATED_FOR_RUNTIME_CUTOVER_RUN_ONLY",
        ),
        "prep_only_boundary_validation": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet_validation.prep_only_boundary.receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_PREP_ONLY_BOUNDARY_VALIDATION_RECEIPT",
            validation_status="PASS",
            prep_only_boundary_preserved=True,
        ),
        "no_authorization_drift_validation": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet_validation.no_authorization_drift.receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            validation_status="PASS",
            drift_detected=False,
        ),
        "runtime_cutover_run_prep_only_draft": _prep_only(
            base,
            role="runtime_cutover_run_prep_only_draft",
            purpose="Prepare future runtime cutover run lane after validation replay.",
        ),
        "post_cutover_evidence_review_packet_prep_only_draft": _prep_only(
            base,
            role="post_cutover_evidence_review_packet_prep_only_draft",
            purpose="Prepare post-cutover evidence review packet structure.",
        ),
        "rollback_freeze_incident_path_prep_only": _prep_only(
            base,
            role="rollback_freeze_incident_path_prep_only",
            purpose="Prepare rollback, freeze, incident, and forensic paths.",
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet_validation.next_lawful_move.receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
        ),
    }
    validation_map = {
        "packet_binding_validation": "packet_contract",
        "mode_validation": "mode_contract",
        "scope_validation": "scope_manifest",
        "allowed_case_class_validation": "allowed_case_class_contract",
        "excluded_case_class_validation": "excluded_case_class_contract",
        "traffic_limit_validation": "traffic_limit_contract",
        "static_fallback_validation": "static_fallback_contract",
        "abstention_fallback_validation": "abstention_fallback_contract",
        "null_route_preservation_validation": "null_route_preservation_contract",
        "operator_override_validation": "operator_override_contract",
        "kill_switch_validation": "kill_switch_contract",
        "rollback_validation": "rollback_contract",
        "route_distribution_threshold_validation": "route_distribution_thresholds",
        "drift_threshold_validation": "drift_thresholds",
        "incident_freeze_validation": "incident_freeze_contract",
        "runtime_receipt_schema_validation": "runtime_receipt_schema",
        "replay_manifest_validation": "replay_manifest",
        "expected_artifact_manifest_validation": "expected_artifact_manifest",
        "external_verifier_validation": "external_verifier_requirements",
        "result_interpretation_validation": "result_interpretation_contract",
        "commercial_claim_boundary_validation": "commercial_claim_boundary",
        "package_promotion_prohibition_validation": "package_promotion_prohibition_receipt",
    }
    for role, validated_role in validation_map.items():
        output[role] = _validation_receipt(base, role=role, validated_role=validated_role)
    return output


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Runtime Cutover Execution Packet Validation",
            "",
            f"Outcome: `{contract['selected_outcome']}`",
            f"Next lawful move: `{contract['next_lawful_move']}`",
            "",
            "This validates the runtime cutover execution packet for a future runtime cutover run only.",
            "It does not execute runtime cutover, does not open R6, does not promote package, and does not authorize commercial activation claims.",
            "",
        ]
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 runtime cutover execution packet validation")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    packet_head = current_main_head if branch != "main" else head
    payloads, texts = _load_packet_payloads(root)
    _validate_packet_payloads(payloads, texts)
    trust = validate_trust_zones(root=root)
    if trust.get("status") != "PASS":
        _fail("RC_B04R6_CUTOVER_EXEC_VAL_TRUST_ZONE_FAILED", str(trust.get("failures", [])))
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=packet_head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
    )
    output_payloads = _payloads(base)
    contract = output_payloads["validation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
