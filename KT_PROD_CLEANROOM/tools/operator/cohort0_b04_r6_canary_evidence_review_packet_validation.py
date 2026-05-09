from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_canary_evidence_review_packet as review
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-canary-evidence-review-packet-validation"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-canary-evidence-review-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_CANARY_EVIDENCE_REVIEW_PACKET_VALIDATION"
PREVIOUS_LANE = review.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = review.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = review.NEXT_LAWFUL_MOVE
OUTCOME_VALIDATED_EXPANDED_CANARY = "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
OUTCOME_VALIDATED_CUTOVER_REVIEW = "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__RUNTIME_CUTOVER_REVIEW_PACKET_NEXT"
OUTCOME_VALIDATED_SECOND_CANARY = "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__SECOND_CANARY_AUTHORIZATION_PACKET_NEXT"
OUTCOME_VALIDATED_EXTERNAL_AUDIT = "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
OUTCOME_DEFERRED = "B04_R6_CANARY_EVIDENCE_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_CANARY_EVIDENCE_REVIEW_INVALID__FORENSIC_CANARY_EVIDENCE_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_VALIDATED_EXPANDED_CANARY
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"

MAY_AUTHORIZE = ("CANARY_EVIDENCE_REVIEW_PACKET_VALIDATED",)
FORBIDDEN_ACTIONS = (
    "EXPANDED_CANARY_AUTHORIZED",
    "EXPANDED_CANARY_EXECUTED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "ACTIVATION_CUTOVER_EXECUTED",
    "R6_OPEN",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "CANARY_EVIDENCE_TREATED_AS_PACKAGE_PROMOTION",
)
TERMINAL_DEFECTS = (
    "CANARY_EVIDENCE_REVIEW_PACKET_MISSING",
    "CANARY_EVIDENCE_INVENTORY_MISSING",
    "CANARY_EVIDENCE_SCORECARD_MISSING",
    "POST_CANARY_DECISION_MATRIX_MISSING",
    "POST_CANARY_DECISION_MATRIX_UNJUSTIFIED",
    "POST_CANARY_BLOCKER_LEDGER_MISSING",
    "CANARY_REVIEW_CONTRACT_MISSING",
    "CAMPAIGN_BOARD_MISSING",
    "VALIDATION_SIGNED_INPUT_HASH_MISSING",
    "VALIDATION_SIGNED_INPUT_HASH_MALFORMED",
    "PREP_ONLY_AUTHORITY_DRIFT",
    "EXPANDED_CANARY_AUTHORIZED",
    "EXPANDED_CANARY_EXECUTED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "LOBE_ESCALATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)
REASON_CODES = (
    "RC_B04R6_CANARY_EVIDENCE_VAL_CONTRACT_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_INVENTORY_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_SCORECARD_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED",
    "RC_B04R6_CANARY_EVIDENCE_VAL_BLOCKER_LEDGER_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_REVIEW_CONTRACT_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_READINESS_MATRIX_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_CAMPAIGN_BOARD_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_PIPELINE_BOARD_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MALFORMED",
    "RC_B04R6_CANARY_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_VAL_EXPANDED_CANARY_AUTHORIZED",
    "RC_B04R6_CANARY_EVIDENCE_VAL_EXPANDED_CANARY_EXECUTED",
    "RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_CANARY_EVIDENCE_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_CANARY_EVIDENCE_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_CANARY_EVIDENCE_VAL_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT",
)

REVIEW_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review.OUTPUTS.items()
    if filename.endswith(".json")
}
REVIEW_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review.OUTPUTS.items()
    if not filename.endswith(".json")
}
REVIEW_CONTRACT_ROLES = (
    "route_distribution_review_contract",
    "fallback_behavior_review_contract",
    "static_fallback_review_contract",
    "abstention_fallback_review_contract",
    "null_route_review_contract",
    "operator_override_review_contract",
    "kill_switch_review_contract",
    "rollback_review_contract",
    "drift_monitoring_review_contract",
    "incident_freeze_review_contract",
    "trace_completeness_review_contract",
    "replay_readiness_review_contract",
    "external_verifier_readiness_review_contract",
    "commercial_claim_boundary_review_contract",
    "package_promotion_blocker_review_contract",
)
VALIDATION_RECEIPT_ROLES = (
    "evidence_inventory_validation",
    "evidence_scorecard_validation",
    "post_run_decision_matrix_validation",
    "post_canary_blocker_ledger_validation",
    "runtime_cutover_readiness_validation",
    "expanded_canary_readiness_validation",
    "second_canary_readiness_validation",
    "route_distribution_review_validation",
    "fallback_behavior_review_validation",
    "static_fallback_review_validation",
    "abstention_fallback_review_validation",
    "null_route_review_validation",
    "operator_override_review_validation",
    "kill_switch_review_validation",
    "rollback_review_validation",
    "drift_monitoring_review_validation",
    "incident_freeze_review_validation",
    "trace_completeness_review_validation",
    "replay_readiness_review_validation",
    "external_verifier_readiness_validation",
    "commercial_claim_boundary_validation",
    "package_promotion_blocker_validation",
    "campaign_board_validation",
    "pipeline_board_validation",
    "prep_only_boundary_validation",
)
PREP_ONLY_OUTPUT_ROLES = (
    "expanded_canary_authorization_validation_plan_prep_only",
    "expanded_canary_execution_packet_prep_only_draft",
    "expanded_canary_evidence_review_packet_prep_only_draft",
    "runtime_cutover_review_packet_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
)
OUTPUTS = {
    "validation_contract": "b04_r6_canary_evidence_review_validation_contract.json",
    "validation_receipt": "b04_r6_canary_evidence_review_validation_receipt.json",
    "validation_report": "b04_r6_canary_evidence_review_validation_report.md",
    "evidence_inventory_validation": "b04_r6_canary_evidence_inventory_validation_receipt.json",
    "evidence_scorecard_validation": "b04_r6_canary_evidence_scorecard_validation_receipt.json",
    "post_run_decision_matrix_validation": "b04_r6_canary_post_run_decision_matrix_validation_receipt.json",
    "post_canary_blocker_ledger_validation": "b04_r6_post_canary_blocker_ledger_validation_receipt.json",
    "runtime_cutover_readiness_validation": "b04_r6_runtime_cutover_readiness_matrix_validation_receipt.json",
    "expanded_canary_readiness_validation": "b04_r6_expanded_canary_readiness_matrix_validation_receipt.json",
    "second_canary_readiness_validation": "b04_r6_second_canary_readiness_matrix_validation_receipt.json",
    "route_distribution_review_validation": "b04_r6_canary_route_distribution_review_validation_receipt.json",
    "fallback_behavior_review_validation": "b04_r6_canary_fallback_behavior_review_validation_receipt.json",
    "static_fallback_review_validation": "b04_r6_canary_static_fallback_review_validation_receipt.json",
    "abstention_fallback_review_validation": "b04_r6_canary_abstention_fallback_review_validation_receipt.json",
    "null_route_review_validation": "b04_r6_canary_null_route_review_validation_receipt.json",
    "operator_override_review_validation": "b04_r6_canary_operator_override_review_validation_receipt.json",
    "kill_switch_review_validation": "b04_r6_canary_kill_switch_review_validation_receipt.json",
    "rollback_review_validation": "b04_r6_canary_rollback_review_validation_receipt.json",
    "drift_monitoring_review_validation": "b04_r6_canary_drift_monitoring_review_validation_receipt.json",
    "incident_freeze_review_validation": "b04_r6_canary_incident_freeze_review_validation_receipt.json",
    "trace_completeness_review_validation": "b04_r6_canary_trace_completeness_review_validation_receipt.json",
    "replay_readiness_review_validation": "b04_r6_canary_replay_readiness_review_validation_receipt.json",
    "external_verifier_readiness_validation": "b04_r6_canary_external_verifier_readiness_validation_receipt.json",
    "commercial_claim_boundary_validation": "b04_r6_canary_commercial_claim_boundary_validation_receipt.json",
    "package_promotion_blocker_validation": "b04_r6_canary_package_promotion_blocker_validation_receipt.json",
    "campaign_board_validation": "kt_e2e_closure_campaign_board_validation_receipt.json",
    "pipeline_board_validation": "b04_r6_canary_evidence_pipeline_board_validation_receipt.json",
    "prep_only_boundary_validation": "b04_r6_canary_evidence_prep_only_boundary_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_canary_evidence_no_authorization_drift_validation_receipt.json",
    "lane_compiler_scaffold_receipt": "b04_r6_canary_evidence_review_validation_lane_compiler_scaffold_receipt.json",
    "expanded_canary_authorization_validation_plan_prep_only": "b04_r6_expanded_canary_authorization_validation_plan_prep_only.json",
    "expanded_canary_execution_packet_prep_only_draft": "b04_r6_expanded_canary_execution_packet_prep_only_draft.json",
    "expanded_canary_evidence_review_packet_prep_only_draft": "b04_r6_expanded_canary_evidence_review_packet_prep_only_draft.json",
    "runtime_cutover_review_packet_prep_only_draft": "b04_r6_runtime_cutover_review_packet_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "campaign_board": "kt_e2e_closure_campaign_board.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}

PREP_ONLY_INVARIANTS = {
    "authority": "PREP_ONLY",
    "status": "PREP_ONLY",
    "cannot_authorize_runtime_cutover": True,
    "cannot_open_r6": True,
    "cannot_authorize_lobe_escalation": True,
    "cannot_authorize_package_promotion": True,
    "cannot_authorize_commercial_activation_claims": True,
    "cannot_mutate_truth_engine_law": True,
    "cannot_mutate_trust_zone_law": True,
}
CLAIM_BEARING_FIELD_MARKERS = (
    "authorization_state",
    "authority_state",
    "claim",
    "commercial",
    "cutover",
    "package_promotion",
    "r6_status",
)
POSITIVE_AUTHORITY_TOKENS = (
    "AUTHORIZED",
    "ACTIVE",
    "ENABLED",
    "OPEN",
    "PROMOTED",
    "CUTOVER",
    "PRODUCTION",
    "COMMERCIAL_ACTIVATION",
    "PACKAGE_PROMOTION",
    "R6_OPEN",
)
NEGATIVE_AUTHORITY_QUALIFIERS = (
    "BLOCKED",
    "BOUNDARY_ONLY",
    "CANNOT_AUTHORIZE",
    "CLOSED",
    "DEFERRED",
    "DOES_NOT_AUTHORIZE",
    "FORBIDDEN",
    "NO_COMMERCIAL",
    "NO_CUTOVER",
    "NO_PACKAGE_PROMOTION",
    "NO_PROMOTION",
    "NOT_AUTHORIZED",
    "NOT_OPEN",
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS_CLOSED",
    "STILL_BLOCKED",
    "UNAUTHORIZED",
)


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES and not current_branch.startswith(REPLAY_BRANCH_PREFIX):
        allowed = ", ".join(sorted([*ALLOWED_BRANCHES, f"{REPLAY_BRANCH_PREFIX}*"]))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {current_branch}")
    if current_branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError("FAIL_CLOSED: main replay requires local main converged with origin/main")
    return current_branch


def _git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
    blob_ref = f"{commit}:{raw.replace(chr(92), '/')}"
    result = subprocess.run(["git", "show", blob_ref], cwd=root, capture_output=True, check=True)
    return result.stdout


def _git_blob_sha256(root: Path, commit: str, raw: str) -> str:
    return hashlib.sha256(_git_blob_bytes(root, commit, raw)).hexdigest()


def _commit_has_previous_handoff(root: Path, commit: str) -> bool:
    raw = f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['next_lawful_move']}"
    try:
        blob = _git_blob_bytes(root, commit, raw)
    except subprocess.CalledProcessError:
        return False
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(
            "RC_B04R6_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT",
            f"malformed prior handoff candidate at {commit}: {exc}",
        )
    return (
        payload.get("authoritative_lane") == PREVIOUS_LANE
        and payload.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and payload.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )


def _first_parent_chain(root: Path, start_ref: str, *, max_depth: int = 512) -> Iterable[str]:
    try:
        current = common.git_rev_parse(root, start_ref)
    except Exception:
        return
    for _ in range(max_depth):
        yield current
        try:
            current = common.git_rev_parse(root, f"{current}^1")
        except Exception:
            break


def _select_handoff_git_commit(root: Path, *, current_main_head: str) -> str:
    for commit in _first_parent_chain(root, current_main_head):
        if _commit_has_previous_handoff(root, commit):
            return commit
    _fail(
        "RC_B04R6_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT",
        f"could not find predecessor handoff in first-parent chain from {current_main_head}",
    )


def _commit_has_review_source_handoff(root: Path, commit: str) -> bool:
    raw = f"KT_PROD_CLEANROOM/reports/{review.canary.OUTPUTS['next_lawful_move']}"
    try:
        blob = _git_blob_bytes(root, commit, raw)
    except subprocess.CalledProcessError:
        return False
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(
            "RC_B04R6_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT",
            f"malformed review-source handoff candidate at {commit}: {exc}",
        )
    return (
        payload.get("authoritative_lane") == review.PREVIOUS_LANE
        and payload.get("selected_outcome") == review.EXPECTED_PREVIOUS_OUTCOME
        and payload.get("next_lawful_move") == review.EXPECTED_PREVIOUS_NEXT_MOVE
    )


def _select_review_source_handoff_git_commit(root: Path, *, review_main_head: str) -> str:
    for commit in _first_parent_chain(root, review_main_head):
        if _commit_has_review_source_handoff(root, commit):
            return commit
    _fail(
        "RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING",
        f"could not find canary handoff for review packet source chain from {review_main_head}",
    )


def _is_sha256(value: Any) -> bool:
    text = str(value)
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _load_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> Dict[str, Any]:
    if Path(raw).name in output_names:
        try:
            return json.loads(_git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8"))
        except Exception as exc:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"git-bound input {label} missing: {exc}")
    return common.load_json_required(root, raw, label=label)


def _read_text_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        try:
            return _git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8")
        except Exception as exc:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"git-bound text input {label} missing: {exc}")
    return common.read_text_required(root, raw, label=label)


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _is_claim_bearing_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in CLAIM_BEARING_FIELD_MARKERS)


def _contains_positive_authority_token(value: str) -> bool:
    for segment in [part.strip().upper() for part in value.replace("\n", ";").replace("|", ";").replace(",", ";").split(";")]:
        if not segment:
            continue
        if not any(token in segment for token in POSITIVE_AUTHORITY_TOKENS):
            continue
        if any(qualifier in segment for qualifier in NEGATIVE_AUTHORITY_QUALIFIERS):
            continue
        return True
    return False


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    forbidden_truths = {
        "expanded_canary_authorized": "RC_B04R6_CANARY_EVIDENCE_VAL_EXPANDED_CANARY_AUTHORIZED",
        "expanded_canary_executed": "RC_B04R6_CANARY_EVIDENCE_VAL_EXPANDED_CANARY_EXECUTED",
        "runtime_cutover_authorized": "RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
        "activation_cutover_executed": "RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
        "r6_open": "RC_B04R6_CANARY_EVIDENCE_VAL_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_CANARY_EVIDENCE_VAL_LOBE_ESCALATION_DRIFT",
        "package_promotion_authorized": "RC_B04R6_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_CANARY_EVIDENCE_VAL_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_CANARY_EVIDENCE_VAL_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_CANARY_EVIDENCE_VAL_TRUTH_ENGINE_MUTATION",
        "static_comparator_weakened": "RC_B04R6_CANARY_EVIDENCE_VAL_TRUTH_ENGINE_MUTATION",
        "canary_evidence_treated_as_package_promotion": "RC_B04R6_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT",
    }
    for key, value in _walk_items(payload):
        if key in forbidden_truths and value is True:
            _fail(forbidden_truths[key], f"{label}.{key} drifted true")
        if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT", f"{label}.{key} carries authority token {value!r}")
    package_state = payload.get("package_promotion")
    nested_state = payload.get("authorization_state", {}).get("package_promotion")
    for value in (package_state, nested_state):
        if value not in (None, "DEFERRED"):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _input_hash(root: Path, raw: str, *, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        return _git_blob_sha256(root, handoff_git_commit, raw)
    return file_sha256(common.resolve_path(root, raw))


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(REVIEW_JSON_INPUTS.items()):
        is_overwritten = Path(raw).name in output_names
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names),
            "binding_kind": "file_sha256_at_canary_evidence_review_validation",
        }
        if is_overwritten:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(REVIEW_TEXT_INPUTS.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_canary_evidence_review_validation",
            }
        )
    return rows


def _binding_hashes(root: Path, *, handoff_git_commit: str) -> Dict[str, str]:
    output_names = set(OUTPUTS.values())
    hashes = {
        f"{role}_hash": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in sorted(REVIEW_JSON_INPUTS.items())
    }
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(REVIEW_TEXT_INPUTS.items())})
    return hashes


def _valid_handoff(next_move: Dict[str, Any]) -> bool:
    predecessor = (
        next_move.get("authoritative_lane") == PREVIOUS_LANE
        and next_move.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and next_move.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    self_replay = (
        next_move.get("authoritative_lane") == AUTHORITATIVE_LANE
        and next_move.get("predecessor_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and next_move.get("previous_next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
        and next_move.get("selected_outcome") == SELECTED_OUTCOME
        and next_move.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )
    return predecessor or self_replay


def _review_packet_expected_hashes(root: Path, contract: Dict[str, Any], *, validation_handoff_git_commit: str) -> Dict[str, str]:
    review_output_names = set(review.OUTPUTS.values())
    validation_output_names = set(OUTPUTS.values())
    review_main_head = str(contract.get("current_main_head", ""))
    source_handoff = _select_review_source_handoff_git_commit(root, review_main_head=review_main_head)
    expected: Dict[str, str] = {}
    for role, raw in sorted(review.ALL_JSON_INPUTS.items()):
        filename = Path(raw).name
        if filename in review_output_names:
            expected[f"{role}_hash"] = _git_blob_sha256(root, source_handoff, raw)
        elif filename in validation_output_names:
            expected[f"{role}_hash"] = _git_blob_sha256(root, validation_handoff_git_commit, raw)
        else:
            expected[f"{role}_hash"] = file_sha256(common.resolve_path(root, raw))
    for role, raw in sorted(review.ALL_TEXT_INPUTS.items()):
        filename = Path(raw).name
        if filename in review_output_names:
            expected[f"{role}_hash"] = _git_blob_sha256(root, source_handoff, raw)
        elif filename in validation_output_names:
            expected[f"{role}_hash"] = _git_blob_sha256(root, validation_handoff_git_commit, raw)
        else:
            expected[f"{role}_hash"] = file_sha256(common.resolve_path(root, raw))
    return expected


def _validate_hash_map(root: Path, contract: Dict[str, Any], *, validation_handoff_git_commit: str) -> None:
    input_bindings = contract.get("input_bindings", {})
    binding_hashes = contract.get("binding_hashes", {})
    if not isinstance(input_bindings, dict) or not input_bindings:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING", "packet input bindings missing")
    expected_hashes = _review_packet_expected_hashes(root, contract, validation_handoff_git_commit=validation_handoff_git_commit)
    for key, expected_hash in expected_hashes.items():
        if key not in input_bindings or key not in binding_hashes:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING", f"{key} missing from packet hash map")
        if not _is_sha256(input_bindings.get(key)) or not _is_sha256(binding_hashes.get(key)):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MALFORMED", f"{key} malformed")
        if input_bindings.get(key) != expected_hash or binding_hashes.get(key) != expected_hash:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING", f"{key} missing or mismatched against source evidence")
    for key, value in input_bindings.items():
        if not _is_sha256(value):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MALFORMED", f"{key} malformed")
        if binding_hashes.get(key) != value:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING", f"{key} missing from binding_hashes")
    for key, value in binding_hashes.items():
        if key.endswith("_hash") and not _is_sha256(value):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INPUT_HASH_MALFORMED", f"{key} malformed in binding_hashes")


def _validate_scorecard(scorecard: Dict[str, Any]) -> None:
    categories = {row.get("category"): row.get("status") for row in scorecard.get("categories", [])}
    for category in review.REVIEW_CATEGORIES:
        if category not in categories:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", f"missing scorecard category {category}")
    required_values = {
        "canary_result": review.EXPECTED_PREVIOUS_OUTCOME,
        "overall_grade": "B_GOOD_BUT_MORE_CANARY_RECOMMENDED",
        "runtime_cutover_review_ready": False,
        "expanded_canary_ready": True,
        "second_canary_ready": True,
        "external_audit_delta_ready": "PARTIAL",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
    }
    for key, expected in required_values.items():
        if scorecard.get(key) != expected:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", f"scorecard {key} drifted")
    if scorecard.get("total_cases", 0) <= 0:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", "scorecard total cases missing")
    if scorecard.get("trace_complete_cases") != scorecard.get("total_cases"):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", "trace completeness does not cover all cases")
    if categories.get("expanded_canary_readiness") != "READY_FOR_PACKET":
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", "expanded canary readiness not packet-ready")
    if categories.get("runtime_cutover_readiness") != "BLOCKED":
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", "cutover readiness not blocked")
    if categories.get("package_promotion_readiness") != "BLOCKED":
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion readiness not blocked")


def _validate_decision_matrix(matrix: Dict[str, Any], scorecard: Dict[str, Any]) -> None:
    if matrix.get("recommended_next_path") != review.RECOMMENDED_NEXT_PATH:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", "unexpected recommended next path")
    if matrix.get("recommended_next_path") not in review.ALLOWED_RECOMMENDED_NEXT_PATHS:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_MISSING", "recommended path not allowed")
    if matrix.get("overall_grade") != scorecard.get("overall_grade"):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_MISSING", "decision grade does not match scorecard")
    expected = {
        "canary_result": "PASSED",
        "runtime_cutover_review_ready": False,
        "expanded_canary_ready": True,
        "second_canary_ready": True,
        "external_audit_delta_ready": "PARTIAL",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
    }
    for key, value in expected.items():
        if matrix.get(key) != value:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", f"decision {key} drifted")
    supporting = set(matrix.get("supporting_evidence", []))
    required_supporting = {"canary_runtime_result", "canary_case_manifest", "route_distribution_receipt", "fallback_behavior_receipt", "trace_completeness_receipt", "replay_receipt"}
    if not required_supporting.issubset(supporting):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", "expanded canary recommendation lacks supporting evidence")
    blockers = " ".join(matrix.get("blocking_reasons", []))
    if "runtime_cutover_requires_dedicated_cutover_review_packet" not in blockers:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", "cutover blocker missing")
    if "commercial_activation_claims_remain_forbidden" not in blockers:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT", "commercial claim blocker missing")


def _validate_readiness(payloads: Dict[str, Dict[str, Any]]) -> None:
    cutover = payloads["runtime_cutover_readiness_matrix"].get("readiness", {})
    expanded = payloads["expanded_canary_readiness_matrix"].get("readiness", {})
    second = payloads["second_canary_readiness_matrix"].get("readiness", {})
    if cutover.get("ready") is not False or cutover.get("runtime_cutover_authorized") is not False:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", "cutover readiness not blocked")
    if expanded.get("ready") is not True or expanded.get("recommendation") != "READY_FOR_AUTHORIZATION_PACKET_IF_VALIDATED":
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_READINESS_MATRIX_MISSING", "expanded canary readiness is not packet-ready")
    if second.get("ready") is not True:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_READINESS_MATRIX_MISSING", "second canary readiness missing")
    for label, readiness in (("expanded", expanded), ("second", second), ("cutover", cutover)):
        if readiness.get("runtime_cutover_authorized") is not False:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", f"{label} readiness authorized cutover")
        if readiness.get("package_promotion_authorized") is not False:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT", f"{label} readiness authorized package")
        if readiness.get("commercial_activation_claim_authorized") is not False:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT", f"{label} readiness authorized commercial claim")
        if readiness.get("r6_open") is not False:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_R6_OPEN_DRIFT", f"{label} readiness opened R6")


def _validate_blockers(blocker_payload: Dict[str, Any]) -> None:
    rows = blocker_payload.get("blockers", [])
    categories = {row.get("category") for row in rows}
    required = {
        "runtime_cutover",
        "expanded_canary",
        "second_canary",
        "package_promotion",
        "external_audit",
        "public_verifier",
        "commercial_claims",
        "operator_readiness",
        "deployment_profile",
        "rollback_proof",
        "data_governance",
        "secret_distributable_hygiene",
        "benchmark_reaudit_readiness",
    }
    if not required.issubset(categories):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_BLOCKER_LEDGER_MISSING", "post-canary blocker ledger categories incomplete")
    for row in rows:
        if row.get("status") != "OPEN" or not row.get("blocks") or not row.get("required_repair_or_next_artifact"):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_BLOCKER_LEDGER_MISSING", "blocker row malformed")


def _validate_boards(payloads: Dict[str, Dict[str, Any]]) -> None:
    pipeline = payloads["pipeline_board"]
    lanes = {row.get("lane"): row for row in pipeline.get("lanes", [])}
    if lanes.get("VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", {}).get("status") not in {"NEXT", "CURRENT_VALIDATED"}:
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PIPELINE_BOARD_MISSING", "pipeline board does not point to validation")
    if lanes.get("RUNTIME_CUTOVER", {}).get("status") != "BLOCKED":
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", "pipeline board cutover not blocked")
    if lanes.get("PACKAGE_PROMOTION", {}).get("status") != "BLOCKED":
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT", "pipeline board package not blocked")

    campaign = payloads["e2e_closure_campaign_board"]
    corridors = {row.get("corridor"): row for row in campaign.get("corridors", [])}
    required_corridors = {
        "R6 proof corridor",
        "canary corridor",
        "runtime cutover corridor",
        "package promotion corridor",
        "external audit corridor",
        "public verifier corridor",
        "claim compiler corridor",
        "proof factory corridor",
        "promotion engine corridor",
        "lobe ratification corridor",
        "adapter / tournament / academy corridor",
        "benchmark / re-audit corridor",
        "commercial truth plane corridor",
    }
    if not required_corridors.issubset(corridors):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_CAMPAIGN_BOARD_MISSING", "campaign board corridors incomplete")
    for corridor in corridors.values():
        blocked = set(corridor.get("blocked_authorities", []))
        if not {"RUNTIME_CUTOVER_AUTHORIZED", "R6_OPEN", "PACKAGE_PROMOTION_AUTHORIZED", "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED"}.issubset(blocked):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_CAMPAIGN_BOARD_MISSING", "campaign board authority ceiling incomplete")


def _validate_review_payloads(
    root: Path,
    payloads: Dict[str, Dict[str, Any]],
    texts: Dict[str, str],
    *,
    validation_handoff_git_commit: str,
) -> None:
    for label, payload in payloads.items():
        _ensure_authority_closed(payload, label=label)
    for role in review.PREP_ONLY_OUTPUT_ROLES:
        filename = review.OUTPUTS[role]
        if filename.endswith(".json"):
            payload = payloads[role]
            if payload.get("status") != "PREP_ONLY" or payload.get("authority") != "PREP_ONLY":
                _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} is not prep-only")
            for key, value in review.PREP_ONLY_INVARIANTS.items():
                if payload.get(key) != value:
                    _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role}.{key} drifted")
        elif "PREP_ONLY" not in texts.get(role, ""):
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} text is not prep-only")

    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    inventory = payloads["evidence_inventory"]
    scorecard_payload = payloads["evidence_scorecard"]
    decision_payload = payloads["post_run_decision_matrix"]
    next_move = payloads["next_lawful_move"]

    for role, payload in (("packet_contract", contract), ("packet_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT", f"{role} next move drift")
        if payload.get("canary_evidence_review_packet_authored") is not True:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} missing authored flag")
        if payload.get("canary_evidence_review_validated") is not False:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} self-validates prematurely")
        if payload.get("canary_runtime_executed") is not True:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} does not bind canary pass")
    if not _valid_handoff(next_move):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT", "next move handoff lacks valid lane identity")

    _validate_hash_map(root, contract, validation_handoff_git_commit=validation_handoff_git_commit)
    if set(inventory.get("evidence_inputs", [])) != set(review.ALL_JSON_INPUTS):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INVENTORY_MISSING", "inventory does not enumerate canary JSON evidence inputs")
    if set(inventory.get("text_inputs", [])) != set(review.ALL_TEXT_INPUTS):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_INVENTORY_MISSING", "inventory does not enumerate text evidence inputs")

    _validate_scorecard(scorecard_payload.get("scorecard", {}))
    _validate_scorecard(contract.get("scorecard", {}))
    _validate_decision_matrix(decision_payload.get("decision_matrix", {}), scorecard_payload.get("scorecard", {}))
    _validate_decision_matrix(contract.get("decision_matrix", {}), contract.get("scorecard", {}))
    _validate_readiness(payloads)
    _validate_blockers(payloads["post_canary_blocker_ledger"])
    _validate_boards(payloads)

    for role in REVIEW_CONTRACT_ROLES:
        payload = payloads[role]
        expected_status = {
            "external_verifier_readiness_review_contract": "PARTIAL",
            "package_promotion_blocker_review_contract": "BLOCKED",
        }.get(role, "PASS")
        if payload.get("review_status") != expected_status:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_REVIEW_CONTRACT_MISSING", f"{role} did not match {expected_status}")

    report_text = texts["packet_report"].lower()
    for phrase in ("expanded-canary authorization packet authorship after validation", "does not authorize runtime", "package promotion"):
        if phrase not in report_text:
            _fail("RC_B04R6_CANARY_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"packet report missing {phrase}")


def _compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    spec = {
        "lane_id": "VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET",
        "lane_name": "B04 R6 canary evidence review packet validation",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only compiler scaffold for validating the canary evidence review packet.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_canary_evidence_review_packet_validation.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_canary_evidence_review_packet_validation.py",
        "artifacts": sorted(OUTPUTS.values()),
        "json_parse_inputs": sorted(filename for filename in OUTPUTS.values() if filename.endswith(".json")),
        "no_authorization_drift_checks": [
            "Validation accepts the evidence review recommendation without authorizing expanded canary execution.",
            "Runtime cutover, R6 open, package promotion, lobe escalation, and commercial activation remain blocked.",
            "All factory, audit, commercial, benchmark, and lobe/adaptive outputs remain prep-only.",
        ],
        "future_blockers": [
            "Expanded canary authorization packet must be authored before expanded canary validation or execution.",
            "Runtime cutover requires a separate cutover review packet and validation.",
            "Package promotion requires future external audit and package promotion review lanes.",
        ],
        "reason_codes": list(REASON_CODES),
        "lane_kind": "VALIDATION",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(REVIEW_JSON_INPUTS),
        "prep_only_outputs": sorted(PREP_ONLY_OUTPUT_ROLES),
    }
    contract = kt_lane_compiler.build_lane_contract(spec)
    rendered = json.dumps(contract, sort_keys=True, ensure_ascii=True)
    return {
        "compiler_id": kt_lane_compiler.COMPILER_ID,
        "authority": kt_lane_compiler.AUTHORITY,
        "status": "PREP_ONLY_TOOLING_USED_AS_SCAFFOLD",
        "contract_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "generated_artifacts": contract["generated_artifacts"],
        "lane_law_metadata": contract["lane_law_metadata"],
        "non_authorization_guards": contract["non_authorization_guards"],
    }


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "canary_evidence_review_packet_bound",
        "canary_evidence_inventory_bound",
        "canary_evidence_scorecard_bound",
        "post_canary_decision_matrix_bound",
        "post_canary_decision_matrix_lawful",
        "expanded_canary_recommendation_supported",
        "runtime_cutover_readiness_blocked",
        "expanded_canary_readiness_packet_ready",
        "second_canary_readiness_packet_ready",
        "post_canary_blocker_ledger_complete",
        "direct_review_contracts_bound",
        "campaign_board_bound",
        "pipeline_board_bound",
        "validation_signed_input_hashes_complete",
        "prep_only_factories_remain_prep_only",
        "expanded_canary_not_authorized",
        "expanded_canary_not_executed",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "lobe_escalation_unauthorized",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_expanded_canary_authorization_packet",
    ]
    return [
        {
            "check_id": f"B04R6-CANARY-EVIDENCE-VALIDATION-{index:03d}",
            "name": check,
            "status": "PASS",
            "terminal_if_fail": check
            in {
                "canary_evidence_review_packet_bound",
                "canary_evidence_inventory_bound",
                "canary_evidence_scorecard_bound",
                "post_canary_decision_matrix_lawful",
                "expanded_canary_recommendation_supported",
                "validation_signed_input_hashes_complete",
                "prep_only_factories_remain_prep_only",
                "runtime_cutover_not_authorized",
                "r6_remains_closed",
                "package_promotion_blocked",
                "commercial_claims_blocked",
                "truth_engine_law_unchanged",
                "trust_zone_law_unchanged",
                "next_lawful_move_expanded_canary_authorization_packet",
            },
        }
        for index, check in enumerate(checks, start=1)
    ]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    input_bindings: list[Dict[str, Any]],
    binding_hashes: Dict[str, str],
    validation_rows: list[Dict[str, Any]],
    compiler_scaffold: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "current_branch": current_branch,
        "schema_version": "v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "recommended_next_path_validated": review.RECOMMENDED_NEXT_PATH,
        "canary_evidence_review_packet_authored": True,
        "canary_evidence_review_validated": True,
        "expanded_canary_authorization_packet_next": True,
        "expanded_canary_authorized": False,
        "expanded_canary_executed": False,
        "canary_runtime_executed": True,
        "runtime_cutover_authorized": False,
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
        "canary_evidence_treated_as_package_promotion": False,
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [
            OUTCOME_VALIDATED_CUTOVER_REVIEW,
            OUTCOME_VALIDATED_EXPANDED_CANARY,
            OUTCOME_VALIDATED_SECOND_CANARY,
            OUTCOME_VALIDATED_EXTERNAL_AUDIT,
            OUTCOME_DEFERRED,
            OUTCOME_INVALID,
        ],
        "outcome_routing": {
            OUTCOME_VALIDATED_EXPANDED_CANARY: NEXT_LAWFUL_MOVE,
            OUTCOME_VALIDATED_CUTOVER_REVIEW: "AUTHOR_B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET",
            OUTCOME_VALIDATED_SECOND_CANARY: "AUTHOR_B04_R6_SECOND_CANARY_AUTHORIZATION_PACKET",
            OUTCOME_VALIDATED_EXTERNAL_AUDIT: "AUTHOR_B04_R6_EXTERNAL_AUDIT_DELTA_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATION_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_CANARY_EVIDENCE_REVIEW_PACKET",
        },
        "terminal_defects": list(TERMINAL_DEFECTS),
        "reason_codes": list(REASON_CODES),
        "lane_compiler_scaffold": compiler_scaffold,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _validation_receipt(
    base: Dict[str, Any],
    *,
    role: str,
    schema_slug: str,
    artifact_id: str,
    subject: str,
    source_roles: Sequence[str],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = _with_artifact(
        base,
        schema_id=f"kt.b04_r6.canary_evidence.review_validation.{schema_slug}.v1",
        artifact_id=artifact_id,
        validation_role=role,
        validation_subject=subject,
        validated_hashes={f"{source_role}_hash": base["binding_hashes"][f"{source_role}_hash"] for source_role in source_roles},
        validation_status="PASS",
    )
    if extra:
        payload.update(extra)
    return payload


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.canary_evidence.review_validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        **PREP_ONLY_INVARIANTS,
        prep_only=True,
        purpose=purpose,
        expanded_canary_authorized=False,
        expanded_canary_executed=False,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    lanes = [
        ("AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "BOUND_AND_VALIDATED", False, EXPECTED_PREVIOUS_OUTCOME, "VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"),
        ("VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "CURRENT_VALIDATED", True, SELECTED_OUTCOME, NEXT_LAWFUL_MOVE),
        ("AUTHOR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET", "NEXT", True, "B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET_BOUND__EXPANDED_CANARY_AUTHORIZATION_VALIDATION_NEXT", "VALIDATE_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"),
        ("RUN_B04_R6_EXPANDED_CANARY", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
        ("RUNTIME_CUTOVER", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
        ("PACKAGE_PROMOTION", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v4",
        artifact_id="B04_R6_PIPELINE_BOARD",
        **PREP_ONLY_INVARIANTS,
        board_status="EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
        lanes=[
            {
                "lane": lane,
                "status": status,
                "authoritative": authoritative,
                "expected_outcome": outcome,
                "next_lane": next_lane,
                "forbidden": list(FORBIDDEN_ACTIONS),
            }
            for lane, status, authoritative, outcome, next_lane in lanes
        ],
    )


def _campaign_board(base: Dict[str, Any]) -> Dict[str, Any]:
    corridors = [
        ("R6 proof corridor", "CANARY_EVIDENCE_REVIEW_VALIDATED__EXPANDED_CANARY_AUTHORIZATION_NEXT", NEXT_LAWFUL_MOVE, "CANARY_EVIDENCE_VALIDATED_ONLY"),
        ("canary corridor", "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT", NEXT_LAWFUL_MOVE, "EXPANDED_CANARY_PACKET_AUTHORING_ONLY"),
        ("runtime cutover corridor", "BLOCKED", "AUTHOR_B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET", "NO_CUTOVER_CLAIM"),
        ("package promotion corridor", "BLOCKED", "AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "NO_PROMOTION_CLAIM"),
        ("external audit corridor", "PREP_ONLY", "AUTHOR_B04_R6_EXTERNAL_AUDIT_DELTA_PACKET", "AUDIT_PREP_ONLY"),
        ("public verifier corridor", "PREP_ONLY", "AUTHOR_B04_R6_PUBLIC_VERIFIER_DELTA_PACKET", "VERIFIER_PREP_ONLY"),
        ("claim compiler corridor", "PREP_ONLY", "AUTHOR_KT_CLAIM_COMPILER_PACKET", "BOUNDARY_ONLY"),
        ("proof factory corridor", "PREP_ONLY", "AUTHOR_KT_PROOF_FACTORY_PACKET", "TOOLING_PREP_ONLY"),
        ("promotion engine corridor", "PREP_ONLY", "AUTHOR_KT_PROMOTION_ENGINE_PACKET", "NO_PROMOTION_AUTHORITY"),
        ("lobe ratification corridor", "PREP_ONLY", "AUTHOR_KT_LOBE_RATIFICATION_FACTORY_PACKET", "NO_LOBE_ESCALATION"),
        ("adapter / tournament / academy corridor", "PREP_ONLY", "AUTHOR_KT_ADAPTIVE_CIVILIZATION_FACTORY_PACKET", "NO_ADAPTER_PROMOTION"),
        ("benchmark / re-audit corridor", "PREP_ONLY", "AUTHOR_KT_BENCHMARK_CONSTITUTION_PACKET", "BENCHMARK_PREP_ONLY"),
        ("commercial truth plane corridor", "PREP_ONLY", "AUTHOR_KT_COMMERCIAL_TRUTH_PLANE_PACKET", "NO_COMMERCIAL_ACTIVATION"),
    ]
    return _with_artifact(
        base,
        schema_id="kt.e2e_closure.campaign_board.v2",
        artifact_id="KT_E2E_CLOSURE_CAMPAIGN_BOARD",
        **PREP_ONLY_INVARIANTS,
        corridors=[
            {
                "corridor": corridor,
                "status": status,
                "authoritative_next": authoritative_next,
                "blocked_authorities": [
                    "RUNTIME_CUTOVER_AUTHORIZED",
                    "R6_OPEN",
                    "LOBE_ESCALATION_AUTHORIZED",
                    "PACKAGE_PROMOTION_AUTHORIZED",
                    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
                ],
                "claim_ceiling": claim_ceiling,
                "prep_only_tracks": sorted(PREP_ONLY_OUTPUT_ROLES),
                "blockers": list(TERMINAL_DEFECTS),
                "receipts": sorted(OUTPUTS.values()),
            }
            for corridor, status, authoritative_next, claim_ceiling in corridors
        ],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v36",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane=AUTHORITATIVE_LANE,
        blockers=[
            {
                "blocker_id": "B04R6-FB-101",
                "status": "OPEN",
                "description": "Expanded canary authorization packet is next but not yet authored.",
                "blocked_until": NEXT_LAWFUL_MOVE,
            },
            {
                "blocker_id": "B04R6-FB-102",
                "status": "OPEN",
                "description": "Expanded canary runtime remains blocked until authorization, execution packet authoring, and validation.",
                "blocked_until": "RUN_B04_R6_EXPANDED_CANARY",
            },
            {
                "blocker_id": "B04R6-FB-103",
                "status": "OPEN",
                "description": "Runtime cutover, package promotion, and commercial activation remain blocked by future review lanes.",
                "blocked_until": "VALIDATE_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET",
            },
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Canary Evidence Review Packet Validation\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The canary evidence review packet is validated as evidence-bound, replay-safe, campaign-complete, "
        "and sufficient only to advance to expanded canary authorization packet authorship.\n\n"
        "This validation accepts the decision-matrix recommendation but does not authorize expanded canary execution, "
        "does not authorize runtime cutover, does not open R6, does not escalate lobes, does not promote package, "
        "does not authorize commercial activation claims, and does not mutate truth/trust law.\n"
    )


def _outputs(base: Dict[str, Any], compiler_scaffold: Dict[str, Any]) -> Dict[str, Any]:
    output_payloads: Dict[str, Any] = {
        "validation_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_evidence_review_validation_contract.v1",
            artifact_id="B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATION_CONTRACT",
            validation_scope={
                "purpose": "Validate the canary evidence review packet, scorecard, decision matrix, campaign board, and prep-only boundaries.",
                "non_purpose": [
                    "Does not authorize expanded canary execution.",
                    "Does not authorize runtime cutover.",
                    "Does not open R6.",
                    "Does not promote package.",
                    "Does not authorize commercial activation claims.",
                ],
            },
            validation_result={
                "canary_evidence_review_packet_complete": True,
                "decision_matrix_lawful": True,
                "expanded_canary_recommendation_supported": True,
                "campaign_prep_only_boundaries_preserved": True,
                "expanded_canary_authorization_packet_next": True,
            },
        ),
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_evidence_review_validation_receipt.v1",
            artifact_id="B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATION_RECEIPT",
            verdict="CANARY_EVIDENCE_REVIEW_PACKET_VALIDATED_EXPANDED_CANARY_PACKET_NEXT",
            no_downstream_authorization_drift=True,
        ),
        "evidence_inventory_validation": _validation_receipt(
            base,
            role="evidence_inventory_validation",
            schema_slug="inventory",
            artifact_id="B04_R6_CANARY_EVIDENCE_INVENTORY_VALIDATION_RECEIPT",
            subject="canary evidence inventory",
            source_roles=("evidence_inventory",),
        ),
        "evidence_scorecard_validation": _validation_receipt(
            base,
            role="evidence_scorecard_validation",
            schema_slug="scorecard",
            artifact_id="B04_R6_CANARY_EVIDENCE_SCORECARD_VALIDATION_RECEIPT",
            subject="canary evidence scorecard",
            source_roles=("evidence_scorecard",),
            extra={"required_categories": sorted(review.REVIEW_CATEGORIES)},
        ),
        "post_run_decision_matrix_validation": _validation_receipt(
            base,
            role="post_run_decision_matrix_validation",
            schema_slug="decision_matrix",
            artifact_id="B04_R6_CANARY_POST_RUN_DECISION_MATRIX_VALIDATION_RECEIPT",
            subject="post-canary decision matrix",
            source_roles=("post_run_decision_matrix", "evidence_scorecard"),
            extra={"recommended_next_path_validated": review.RECOMMENDED_NEXT_PATH},
        ),
        "post_canary_blocker_ledger_validation": _validation_receipt(
            base,
            role="post_canary_blocker_ledger_validation",
            schema_slug="blocker_ledger",
            artifact_id="B04_R6_POST_CANARY_BLOCKER_LEDGER_VALIDATION_RECEIPT",
            subject="post-canary blocker ledger",
            source_roles=("post_canary_blocker_ledger",),
        ),
        "runtime_cutover_readiness_validation": _validation_receipt(
            base,
            role="runtime_cutover_readiness_validation",
            schema_slug="runtime_cutover_readiness",
            artifact_id="B04_R6_RUNTIME_CUTOVER_READINESS_MATRIX_VALIDATION_RECEIPT",
            subject="runtime cutover readiness matrix",
            source_roles=("runtime_cutover_readiness_matrix",),
            extra={"runtime_cutover_authorized": False},
        ),
        "expanded_canary_readiness_validation": _validation_receipt(
            base,
            role="expanded_canary_readiness_validation",
            schema_slug="expanded_canary_readiness",
            artifact_id="B04_R6_EXPANDED_CANARY_READINESS_MATRIX_VALIDATION_RECEIPT",
            subject="expanded canary readiness matrix",
            source_roles=("expanded_canary_readiness_matrix",),
            extra={"expanded_canary_authorization_packet_next": True, "expanded_canary_authorized": False},
        ),
        "second_canary_readiness_validation": _validation_receipt(
            base,
            role="second_canary_readiness_validation",
            schema_slug="second_canary_readiness",
            artifact_id="B04_R6_SECOND_CANARY_READINESS_MATRIX_VALIDATION_RECEIPT",
            subject="second canary readiness matrix",
            source_roles=("second_canary_readiness_matrix",),
        ),
        "campaign_board_validation": _validation_receipt(
            base,
            role="campaign_board_validation",
            schema_slug="campaign_board",
            artifact_id="KT_E2E_CLOSURE_CAMPAIGN_BOARD_VALIDATION_RECEIPT",
            subject="E2E closure campaign board",
            source_roles=("e2e_closure_campaign_board",),
        ),
        "pipeline_board_validation": _validation_receipt(
            base,
            role="pipeline_board_validation",
            schema_slug="pipeline_board",
            artifact_id="B04_R6_CANARY_EVIDENCE_PIPELINE_BOARD_VALIDATION_RECEIPT",
            subject="B04 R6 pipeline board",
            source_roles=("pipeline_board",),
        ),
        "prep_only_boundary_validation": _validation_receipt(
            base,
            role="prep_only_boundary_validation",
            schema_slug="prep_only_boundary",
            artifact_id="B04_R6_CANARY_EVIDENCE_PREP_ONLY_BOUNDARY_VALIDATION_RECEIPT",
            subject="campaign prep-only boundaries",
            source_roles=tuple(review.PREP_ONLY_OUTPUT_ROLES),
            extra={"prep_only_artifacts_validated": sorted(review.PREP_ONLY_OUTPUT_ROLES)},
        ),
        "no_authorization_drift_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_evidence.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_CANARY_EVIDENCE_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_downstream_authorization_drift=True,
            expanded_canary_authorized=False,
            expanded_canary_executed=False,
            runtime_cutover_authorized=False,
            r6_open=False,
            lobe_escalation_authorized=False,
            package_promotion_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_evidence.review_validation_lane_compiler_scaffold_receipt.v1",
            artifact_id="B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATION_LANE_COMPILER_SCAFFOLD_RECEIPT",
            scaffold=compiler_scaffold,
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "campaign_board": _campaign_board(base),
        "pipeline_board": _pipeline_board(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v36",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }
    receipt_specs = {
        "route_distribution_review_validation": ("route_distribution_review_contract", "Route-distribution review"),
        "fallback_behavior_review_validation": ("fallback_behavior_review_contract", "Fallback behavior review"),
        "static_fallback_review_validation": ("static_fallback_review_contract", "Static fallback review"),
        "abstention_fallback_review_validation": ("abstention_fallback_review_contract", "Abstention fallback review"),
        "null_route_review_validation": ("null_route_review_contract", "Null-route review"),
        "operator_override_review_validation": ("operator_override_review_contract", "Operator override review"),
        "kill_switch_review_validation": ("kill_switch_review_contract", "Kill-switch review"),
        "rollback_review_validation": ("rollback_review_contract", "Rollback review"),
        "drift_monitoring_review_validation": ("drift_monitoring_review_contract", "Drift monitoring review"),
        "incident_freeze_review_validation": ("incident_freeze_review_contract", "Incident/freeze review"),
        "trace_completeness_review_validation": ("trace_completeness_review_contract", "Trace completeness review"),
        "replay_readiness_review_validation": ("replay_readiness_review_contract", "Replay readiness review"),
        "external_verifier_readiness_validation": ("external_verifier_readiness_review_contract", "External verifier readiness review"),
        "commercial_claim_boundary_validation": ("commercial_claim_boundary_review_contract", "Commercial claim boundary review"),
        "package_promotion_blocker_validation": ("package_promotion_blocker_review_contract", "Package promotion blocker review"),
    }
    for role, (source_role, subject) in receipt_specs.items():
        output_payloads[role] = _validation_receipt(
            base,
            role=role,
            schema_slug=role,
            artifact_id=f"B04_R6_{role.upper()}_RECEIPT",
            subject=subject,
            source_roles=(source_role,),
        )
    output_payloads.update(
        {
            role: _prep_only(base, role=role, purpose=f"Prep-only continuation scaffold for {role.replace('_', ' ')}.")
            for role in PREP_ONLY_OUTPUT_ROLES
        }
    )
    return output_payloads


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 canary evidence review validation")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    handoff_git_commit = _select_handoff_git_commit(root, current_main_head=current_main_head)
    output_names = set(OUTPUTS.values())
    payloads = {
        role: _load_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in REVIEW_JSON_INPUTS.items()
    }
    texts = {
        role: _read_text_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in REVIEW_TEXT_INPUTS.items()
    }
    _validate_review_payloads(root, payloads, texts, validation_handoff_git_commit=handoff_git_commit)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    compiler_scaffold = _compiler_scaffold(current_main_head)
    if compiler_scaffold.get("authority") != "PREP_ONLY_TOOLING":
        _fail("RC_B04R6_CANARY_EVIDENCE_VAL_COMPILER_SCAFFOLD_MISSING", "compiler scaffold authority drift")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=handoff_git_commit),
        binding_hashes=_binding_hashes(root, handoff_git_commit=handoff_git_commit),
        validation_rows=_validation_rows(),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
    )
    output_payloads = _outputs(base, compiler_scaffold)
    contract = output_payloads["validation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate B04 R6 canary evidence review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
