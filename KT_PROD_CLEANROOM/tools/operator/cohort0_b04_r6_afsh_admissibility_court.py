from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator import cohort0_b04_r6_afsh_candidate_generation as generation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-afsh-admissibility-court"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_AFSH_ADMISSIBILITY_COURT"
PREVIOUS_LANE = generation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = generation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = generation.NEXT_LAWFUL_MOVE
OUTCOME_ADMISSIBLE = "B04_R6_AFSH_CANDIDATE_ADMISSIBLE__SHADOW_SCREEN_PACKET_NEXT"
OUTCOME_DEFERRED = "B04_R6_AFSH_CANDIDATE_DEFERRED__NAMED_ADMISSIBILITY_DEFECT_REMAINS"
OUTCOME_BLOCKED = "B04_R6_AFSH_CANDIDATE_BLOCKED__NO_LAWFUL_ADMISSIBLE_CANDIDATE"
OUTCOME_INVALID = "B04_R6_AFSH_CANDIDATE_INVALID__FORENSIC_INVALIDATION_COURT_NEXT"
SELECTED_OUTCOME = OUTCOME_ADMISSIBLE
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET"

SELECTED_ARCHITECTURE_ID = generation.SELECTED_ARCHITECTURE_ID
SELECTED_ARCHITECTURE_NAME = generation.SELECTED_ARCHITECTURE_NAME
CANDIDATE_ID = generation.CANDIDATE_ID
CANDIDATE_VERSION = generation.CANDIDATE_VERSION
TOP_LEVEL_VERDICTS = generation.TOP_LEVEL_VERDICTS
TRIAGE_SUBTYPES = generation.TRIAGE_SUBTYPES
NUMERIC_SCORE_FIELDS = generation.NUMERIC_SCORE_FIELDS
FORBIDDEN_ACCESS_FIELDS = generation.FORBIDDEN_ACCESS_FIELDS
FORBIDDEN_FEATURE_FAMILIES = generation.FORBIDDEN_FEATURE_FAMILIES
TRACE_FIELDS = generation.TRACE_FIELDS

FORBIDDEN_TRUE_KEYS = (
    "r6_authorized",
    "r6_open",
    "router_generation_authorized",
    "candidate_training_authorized",
    "candidate_training_executed",
    "afsh_candidate_training_authorized",
    "afsh_candidate_training_executed",
    "shadow_screen_authorized",
    "new_shadow_screen_authorized",
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
    "SHADOW_SCREEN_EXECUTION_AUTHORIZED",
    "R6_OPEN",
    "LEARNED_ROUTER_SUPERIORITY_EARNED",
    "ACTIVATION_REVIEW_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
)

ADMISSIBILITY_REASON_CODES = (
    "RC_B04R6_AFSH_ADM_CONTRACT_MISSING",
    "RC_B04R6_AFSH_ADM_MAIN_HEAD_MISMATCH",
    "RC_B04R6_AFSH_ADM_CANDIDATE_REPLAY_HEAD_MISMATCH",
    "RC_B04R6_AFSH_ADM_ARCHITECTURE_MISMATCH",
    "RC_B04R6_AFSH_ADM_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_AFSH_ADM_COURT_BINDING_MISSING",
    "RC_B04R6_AFSH_ADM_SOURCE_PACKET_BINDING_MISSING",
    "RC_B04R6_AFSH_ADM_CANDIDATE_MANIFEST_MISSING",
    "RC_B04R6_AFSH_ADM_CANDIDATE_ARTIFACT_MISSING",
    "RC_B04R6_AFSH_ADM_CANDIDATE_HASH_MISSING",
    "RC_B04R6_AFSH_ADM_CANDIDATE_SEMANTIC_HASH_UNSTABLE",
    "RC_B04R6_AFSH_ADM_IMMUTABLE_INPUT_BINDING_MISSING",
    "RC_B04R6_AFSH_ADM_IMMUTABLE_INPUT_MIXED_HEAD",
    "RC_B04R6_AFSH_ADM_MUTABLE_HANDOFF_NOT_BOUND",
    "RC_B04R6_AFSH_ADM_TRAINING_EXECUTED",
    "RC_B04R6_AFSH_ADM_TRAINING_AUTHORIZED",
    "RC_B04R6_AFSH_ADM_CANDIDATE_KIND_INVALID",
    "RC_B04R6_AFSH_ADM_RULE_MATERIALIZATION_MISSING",
    "RC_B04R6_AFSH_ADM_STATIC_HOLD_DEFAULT_MISSING",
    "RC_B04R6_AFSH_ADM_ABSTENTION_PRESERVATION_MISSING",
    "RC_B04R6_AFSH_ADM_NULL_ROUTE_PRESERVATION_MISSING",
    "RC_B04R6_AFSH_ADM_MIRROR_MASKED_STABILITY_MISSING",
    "RC_B04R6_AFSH_ADM_TRIAGE_CORE_MISSING",
    "RC_B04R6_AFSH_ADM_TRIAGE_VERDICT_MODE_DRIFT",
    "RC_B04R6_AFSH_ADM_TRIAGE_SUBTYPE_BECAME_VERDICT",
    "RC_B04R6_AFSH_ADM_TRIAGE_SELECTOR_ENTRY_DRIFT",
    "RC_B04R6_AFSH_ADM_TRIAGE_STATIC_HOLD_ENTERS_SELECTOR",
    "RC_B04R6_AFSH_ADM_TRIAGE_ABSTAIN_ENTERS_SELECTOR",
    "RC_B04R6_AFSH_ADM_TRIAGE_NULL_ROUTE_ENTERS_SELECTOR",
    "RC_B04R6_AFSH_ADM_TRIAGE_SCORE_NONDETERMINISTIC",
    "RC_B04R6_AFSH_ADM_TRIAGE_EMIT_NOT_FAIL_CLOSED",
    "RC_B04R6_AFSH_ADM_TRIAGE_TAG_NOT_RECEIPT_DERIVED",
    "RC_B04R6_AFSH_ADM_TRIAGE_TAG_NOT_SOURCE_PACKET_ALLOWED",
    "RC_B04R6_AFSH_ADM_TRIAGE_TAG_BLIND_OUTCOME_DEPENDENT",
    "RC_B04R6_AFSH_ADM_TRIAGE_TAG_ROUTE_SUCCESS_DEPENDENT",
    "RC_B04R6_AFSH_ADM_TRIAGE_TAG_POST_SCREEN_DEPENDENT",
    "RC_B04R6_AFSH_ADM_TRIAGE_TAG_OLD_UNIVERSE_DEPENDENT",
    "RC_B04R6_AFSH_ADM_TRACE_SCHEMA_INCOMPLETE",
    "RC_B04R6_AFSH_ADM_NO_CONTAMINATION_RECEIPT_MISSING",
    "RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT",
    "RC_B04R6_AFSH_ADM_SHADOW_PACKET_AUTHORIZED_TOO_EARLY",
    "RC_B04R6_AFSH_ADM_SHADOW_SCREEN_EXECUTED",
    "RC_B04R6_AFSH_ADM_R6_OPEN_DRIFT",
    "RC_B04R6_AFSH_ADM_SUPERIORITY_DRIFT",
    "RC_B04R6_AFSH_ADM_ACTIVATION_DRIFT",
    "RC_B04R6_AFSH_ADM_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_AFSH_ADM_METRIC_WIDENING",
    "RC_B04R6_AFSH_ADM_COMPARATOR_WEAKENING",
    "RC_B04R6_AFSH_ADM_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_AFSH_ADM_TRUST_ZONE_MUTATION",
    "RC_B04R6_AFSH_ADM_NEXT_MOVE_DRIFT",
)

TERMINAL_DEFECTS = (
    "TRAINING_EXECUTED",
    "IMMUTABLE_INPUT_MIXED_HEAD",
    "TRIAGE_SELECTOR_ENTRY_DRIFT",
    "TRIAGE_STATIC_HOLD_ENTERS_SELECTOR",
    "TRIAGE_ABSTAIN_ENTERS_SELECTOR",
    "TRIAGE_NULL_ROUTE_ENTERS_SELECTOR",
    "TRIAGE_TAG_BLIND_OUTCOME_DEPENDENT",
    "TRIAGE_TAG_ROUTE_SUCCESS_DEPENDENT",
    "OLD_UNIVERSE_PROOF_DRIFT",
    "SHADOW_SCREEN_EXECUTED",
    "R6_OPEN_DRIFT",
    "SUPERIORITY_DRIFT",
    "ACTIVATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "METRIC_WIDENING",
    "COMPARATOR_WEAKENING",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)

INPUTS = {
    "candidate_generation_contract": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_generation_contract.json",
    "candidate_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_manifest.json",
    "candidate_artifact": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_v1.json",
    "candidate_hash_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_hash_receipt.json",
    "candidate_derivation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_derivation_receipt.json",
    "rule_materialization_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_rule_materialization_receipt.json",
    "no_training_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_no_training_receipt.json",
    "no_contamination_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_no_contamination_receipt.json",
    "static_hold_default_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_static_hold_default_receipt.json",
    "abstention_preservation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_abstention_preservation_receipt.json",
    "null_route_preservation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_null_route_preservation_receipt.json",
    "mirror_masked_stability_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_mirror_masked_stability_receipt.json",
    "trace_schema_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_trace_schema_receipt.json",
    "source_hash_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_source_hash_receipt.json",
    "no_authorization_drift_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_no_authorization_drift_receipt.json",
    "stable_semantic_hash_basis": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_stable_semantic_hash_basis.json",
    "immutable_input_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_immutable_input_manifest.json",
    "replay_binding_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_replay_binding_receipt.json",
    "mutable_handoff_binding_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_mutable_handoff_binding_receipt.json",
    "prep_only_non_authority_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_prep_only_non_authority_receipt.json",
    "old_universe_diagnostic_only_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_candidate_old_universe_diagnostic_only_receipt.json",
    "numeric_triage_emit_core": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_numeric_triage_emit_core_contract.json",
    "triage_intake_gate": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_intake_gate_contract.json",
    "triage_tag_schema": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_tag_schema.json",
    "triage_score_schema": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_score_schema.json",
    "triage_emit_decision_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_emit_decision_matrix.json",
    "triage_receipt_schema": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_receipt_schema.json",
    "triage_no_authorization_drift_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_triage_no_authorization_drift_receipt.json",
    "turboquant_translation": "KT_PROD_CLEANROOM/reports/kt_turboquant_research_translation_matrix_prep_only.json",
    "compressed_receipt_index": "KT_PROD_CLEANROOM/reports/kt_compressed_receipt_vector_index_contract_prep_only.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})
TEXT_INPUTS = {
    "candidate_generation_report": "KT_PROD_CLEANROOM/reports/COHORT0_B04_R6_AFSH_CANDIDATE_GENERATION_REPORT.md",
}

OUTPUTS = {
    "admissibility_contract": "b04_r6_afsh_admissibility_court_contract.json",
    "admissibility_receipt": "b04_r6_afsh_admissibility_court_receipt.json",
    "admissibility_report": "b04_r6_afsh_admissibility_court_report.md",
    "candidate_manifest_admissibility_receipt": "b04_r6_afsh_candidate_manifest_admissibility_receipt.json",
    "candidate_hash_admissibility_receipt": "b04_r6_afsh_candidate_hash_admissibility_receipt.json",
    "candidate_semantic_hash_admissibility_receipt": "b04_r6_afsh_candidate_semantic_hash_admissibility_receipt.json",
    "candidate_replay_binding_admissibility_receipt": "b04_r6_afsh_candidate_replay_binding_admissibility_receipt.json",
    "candidate_immutable_input_admissibility_receipt": "b04_r6_afsh_candidate_immutable_input_admissibility_receipt.json",
    "candidate_mutable_handoff_admissibility_receipt": "b04_r6_afsh_candidate_mutable_handoff_admissibility_receipt.json",
    "candidate_no_training_admissibility_receipt": "b04_r6_afsh_candidate_no_training_admissibility_receipt.json",
    "candidate_no_contamination_admissibility_receipt": "b04_r6_afsh_candidate_no_contamination_admissibility_receipt.json",
    "candidate_old_universe_diagnostic_only_admissibility_receipt": "b04_r6_afsh_candidate_old_universe_diagnostic_only_admissibility_receipt.json",
    "triage_core_admissibility_receipt": "b04_r6_afsh_triage_core_admissibility_receipt.json",
    "triage_emit_logic_admissibility_receipt": "b04_r6_afsh_triage_emit_logic_admissibility_receipt.json",
    "triage_selector_entry_admissibility_receipt": "b04_r6_afsh_triage_selector_entry_admissibility_receipt.json",
    "triage_tag_safety_admissibility_receipt": "b04_r6_afsh_triage_tag_safety_admissibility_receipt.json",
    "trace_schema_admissibility_receipt": "b04_r6_afsh_trace_schema_admissibility_receipt.json",
    "shadow_screen_packet_prep": "b04_r6_afsh_shadow_screen_packet_prep_only_draft.json",
    "shadow_screen_metric_contract_prep": "b04_r6_afsh_shadow_screen_metric_contract_prep_only_draft.json",
    "shadow_screen_disqualifier_ledger_prep": "b04_r6_afsh_shadow_screen_disqualifier_ledger_prep_only_draft.json",
    "shadow_screen_replay_manifest_prep": "b04_r6_afsh_shadow_screen_replay_manifest_prep_only_draft.json",
    "shadow_screen_external_verifier_requirements_prep": "b04_r6_afsh_shadow_screen_external_verifier_requirements_prep_only_draft.json",
    "no_authorization_drift_receipt": "b04_r6_afsh_admissibility_no_authorization_drift_receipt.json",
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


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and payload.get(key) is not False:
        _fail(code, f"{label} drifted: {key} must remain false")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "PASS")).strip() not in {"PASS", "FROZEN_PACKET"}:
        _fail("RC_B04R6_AFSH_ADM_CONTRACT_MISSING", f"{label} must be PASS or FROZEN_PACKET")
    architecture_id = payload.get("selected_architecture_id", payload.get("selected_architecture"))
    if architecture_id != SELECTED_ARCHITECTURE_ID:
        _fail("RC_B04R6_AFSH_ADM_ARCHITECTURE_MISMATCH", f"{label} must bind AFSH-2S-GUARD")
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label, code="RC_B04R6_AFSH_ADM_R6_OPEN_DRIFT")
    if payload.get("package_promotion_remains_deferred", True) is not True:
        _fail("RC_B04R6_AFSH_ADM_PACKAGE_PROMOTION_DRIFT", f"{label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged", True) is not True:
        _fail("RC_B04R6_AFSH_ADM_TRUTH_ENGINE_MUTATION", f"{label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged", True) is not True:
        _fail("RC_B04R6_AFSH_ADM_TRUST_ZONE_MUTATION", f"{label} must preserve trust-zone law")


def _existing_admissibility_contract_supports_self_replay(root: Path) -> bool:
    path = root / "KT_PROD_CLEANROOM" / "reports" / OUTPUTS["admissibility_contract"]
    if not path.is_file():
        return False
    payload = common.load_json_required(root, path, label="existing AFSH admissibility contract")
    return (
        payload.get("authoritative_lane") == AUTHORITATIVE_LANE
        and payload.get("previous_authoritative_lane") == PREVIOUS_LANE
        and payload.get("selected_outcome") == SELECTED_OUTCOME
        and payload.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )


def _input_hashes(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted({**INPUTS, **TEXT_INPUTS}.items()):
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
            row["binding_kind"] = "file_sha256_at_admissibility"
        rows.append(row)
    return rows


def _candidate_replay_head(payloads: Dict[str, Dict[str, Any]]) -> str:
    manifest = payloads["candidate_manifest"]
    head = str(manifest.get("current_git_head", "")).strip()
    if len(head) != 40:
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_REPLAY_HEAD_MISMATCH", "candidate replay head must be a full git SHA")
    return head


def _require_candidate_generation_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], text_payloads: Dict[str, str]) -> str:
    if not text_payloads["candidate_generation_report"].strip():
        _fail("RC_B04R6_AFSH_ADM_CONTRACT_MISSING", "candidate generation report missing")
    handoff = payloads["previous_next_lawful_move"]
    _ensure_common_boundary(handoff, label="previous_next_lawful_move")
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
        and _existing_admissibility_contract_supports_self_replay(root)
    )
    if not (handoff_is_previous or handoff_is_self_replay):
        _fail("RC_B04R6_AFSH_ADM_NEXT_MOVE_DRIFT", "next lawful move receipt does not authorize admissibility court")

    replay_head = _candidate_replay_head(payloads)
    for role, payload in payloads.items():
        if role in MUTABLE_HANDOFF_ROLES or role in {
            "candidate_artifact",
            "numeric_triage_emit_core",
            "triage_intake_gate",
            "triage_tag_schema",
            "triage_score_schema",
            "triage_emit_decision_matrix",
            "triage_receipt_schema",
            "turboquant_translation",
            "compressed_receipt_index",
        }:
            continue
        _ensure_common_boundary(payload, label=role)
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_AFSH_ADM_CANDIDATE_MANIFEST_MISSING", f"{role} must come from candidate generation lane")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_AFSH_ADM_NEXT_MOVE_DRIFT", f"{role} outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_AFSH_ADM_NEXT_MOVE_DRIFT", f"{role} does not authorize admissibility")
        if payload.get("current_git_head") != replay_head or payload.get("current_main_head") != replay_head:
            _fail("RC_B04R6_AFSH_ADM_CANDIDATE_REPLAY_HEAD_MISMATCH", f"{role} does not bind candidate replay head")
    return replay_head


def _validated_universe_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_blind_universe_binding", payload.get("validated_inputs", {}).get("blind_universe", {})))
    if binding.get("status") != "BOUND_AND_VALIDATED" or binding.get("case_count") != generation.EXPECTED_CASE_COUNT:
        _fail("RC_B04R6_AFSH_ADM_UNIVERSE_BINDING_MISSING", "candidate must bind validated 18-case blind universe")
    if binding.get("prior_r01_r04_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 must remain diagnostic-only")
    if binding.get("prior_v2_six_row_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row screen must remain diagnostic-only")
    return binding


def _validated_court_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_court_binding", payload.get("validated_inputs", {}).get("route_value_court", {})))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_ADM_COURT_BINDING_MISSING", "validated court binding missing")
    if tuple(binding.get("verdict_modes", [])) != TOP_LEVEL_VERDICTS:
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_VERDICT_MODE_DRIFT", "court verdict modes drifted")
    if binding.get("route_eligible_non_executing_only") is not True:
        _fail("RC_B04R6_AFSH_ADM_COURT_BINDING_MISSING", "ROUTE_ELIGIBLE must remain non-executing")
    return binding


def _validated_source_packet_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = dict(payload.get("validated_source_packet_binding", payload.get("validated_inputs", {}).get("implementation_source_packet", {})))
    if binding.get("status") != "BOUND_AND_VALIDATED":
        _fail("RC_B04R6_AFSH_ADM_SOURCE_PACKET_BINDING_MISSING", "validated source packet binding missing")
    return binding


def _validate_candidate(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    manifest = payloads["candidate_manifest"]
    candidate = payloads["candidate_artifact"]
    hash_receipt = payloads["candidate_hash_receipt"]
    if manifest.get("candidate_id") != CANDIDATE_ID or candidate.get("candidate_id") != CANDIDATE_ID:
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_MANIFEST_MISSING", "candidate id mismatch")
    if candidate.get("artifact_id") != CANDIDATE_ID:
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_ARTIFACT_MISSING", "candidate artifact missing")
    if manifest.get("candidate_kind") != "DETERMINISTIC_RULE_MATERIALIZATION" or candidate.get("candidate_kind") != "DETERMINISTIC_RULE_MATERIALIZATION":
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_KIND_INVALID", "candidate must be deterministic rule materialization")
    if manifest.get("candidate_generation_executed") is not True or candidate.get("candidate_generation_executed") is not True:
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_MANIFEST_MISSING", "candidate generation must have executed in prior lane")
    if manifest.get("training_executed") is not False or candidate.get("training_executed") is not False:
        _fail("RC_B04R6_AFSH_ADM_TRAINING_EXECUTED", "candidate training must not execute")
    if manifest.get("candidate_training_authorized") is not False:
        _fail("RC_B04R6_AFSH_ADM_TRAINING_AUTHORIZED", "candidate training must remain unauthorized")
    semantic_hash = candidate_semantic_hash(candidate)
    envelope_hash = _envelope_hash(candidate)
    if hash_receipt.get("candidate_semantic_hash") != semantic_hash or manifest.get("candidate_semantic_hash") != semantic_hash:
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_SEMANTIC_HASH_UNSTABLE", "candidate semantic hash drifted")
    if hash_receipt.get("candidate_envelope_hash") != envelope_hash or manifest.get("candidate_envelope_hash") != envelope_hash:
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_HASH_MISSING", "candidate envelope hash drifted")
    if "generated_utc" not in payloads["stable_semantic_hash_basis"].get("excluded_volatile_fields", []):
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_SEMANTIC_HASH_UNSTABLE", "generated_utc must be excluded from semantic hash")
    if hash_receipt.get("candidate_receipt_hash_includes_envelope") is not True:
        _fail("RC_B04R6_AFSH_ADM_CANDIDATE_HASH_MISSING", "envelope hash must remain separately bound")
    return {
        "candidate_semantic_hash": semantic_hash,
        "candidate_envelope_hash": envelope_hash,
        "universe_binding": _validated_universe_binding(manifest),
        "court_binding": _validated_court_binding(manifest),
        "source_packet_binding": _validated_source_packet_binding(payloads["candidate_generation_contract"]),
    }


def _validate_immutable_inputs(payloads: Dict[str, Dict[str, Any]], *, replay_head: str) -> None:
    manifest = payloads["immutable_input_manifest"]
    if manifest.get("immutable_source_inputs_share_replay_head") is not True:
        _fail("RC_B04R6_AFSH_ADM_IMMUTABLE_INPUT_BINDING_MISSING", "immutable input manifest must mark shared replay head")
    rows = manifest.get("input_bindings", [])
    if not isinstance(rows, list) or not rows:
        _fail("RC_B04R6_AFSH_ADM_IMMUTABLE_INPUT_BINDING_MISSING", "immutable input bindings missing")
    for payload in payloads.values():
        if isinstance(payload, dict) and payload.get("authoritative_lane") == PREVIOUS_LANE:
            if payload.get("current_git_head") != replay_head:
                _fail("RC_B04R6_AFSH_ADM_IMMUTABLE_INPUT_MIXED_HEAD", "candidate immutable inputs must share replay head")
    if not any(row.get("role") == "previous_next_lawful_move" and row.get("binding_kind") == "git_object_before_overwrite" for row in rows if isinstance(row, dict)):
        _fail("RC_B04R6_AFSH_ADM_MUTABLE_HANDOFF_NOT_BOUND", "mutable handoff must be bound before overwrite")


def _validate_triage(payloads: Dict[str, Dict[str, Any]]) -> None:
    candidate = payloads["candidate_artifact"]
    core = payloads["numeric_triage_emit_core"]
    matrix = payloads["triage_emit_decision_matrix"]
    tag_schema = payloads["triage_tag_schema"]
    score_schema = payloads["triage_score_schema"]
    receipt_schema = payloads["triage_receipt_schema"]
    if candidate.get("modules", {}).get("numeric_triage_emit_core") != "B04_R6_AFSH_NUMERIC_TRIAGE_EMIT_CORE":
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_CORE_MISSING", "candidate must include numeric triage emit core")
    if tuple(core.get("top_level_verdict_modes", [])) != TOP_LEVEL_VERDICTS or tuple(candidate.get("top_level_verdict_modes", [])) != TOP_LEVEL_VERDICTS:
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_VERDICT_MODE_DRIFT", "candidate verdict modes must match validated court")
    if core.get("new_top_level_verdicts_allowed") is not False:
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_SUBTYPE_BECAME_VERDICT", "triage subtypes must not become top-level verdicts")
    if tuple(core.get("triage_subtypes_allowed", [])) != TRIAGE_SUBTYPES:
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_SUBTYPE_BECAME_VERDICT", "triage subtype enum drifted")
    selector_rule = candidate.get("selector_entry_rule", {})
    if selector_rule.get("only_top_level_verdict_allowed_to_enter_selector") != "ROUTE_ELIGIBLE":
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_SELECTOR_ENTRY_DRIFT", "only ROUTE_ELIGIBLE may enter selector")
    for verdict, key, code in [
        ("STATIC_HOLD", "static_hold_enters_selector", "RC_B04R6_AFSH_ADM_TRIAGE_STATIC_HOLD_ENTERS_SELECTOR"),
        ("ABSTAIN", "abstain_enters_selector", "RC_B04R6_AFSH_ADM_TRIAGE_ABSTAIN_ENTERS_SELECTOR"),
        ("NULL_ROUTE", "null_route_enters_selector", "RC_B04R6_AFSH_ADM_TRIAGE_NULL_ROUTE_ENTERS_SELECTOR"),
    ]:
        if selector_rule.get(key) is not False or matrix.get(key) is not False:
            _fail(code, f"{verdict} must terminate before selector")
    bounds = score_schema.get("score_bounds", {})
    if score_schema.get("deterministic") is not True or bounds.get("min") != 0.0 or bounds.get("max") != 1.0:
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_SCORE_NONDETERMINISTIC", "triage scores must be deterministic and bounded")
    if matrix.get("fail_closed_default") != "STATIC_HOLD":
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_EMIT_NOT_FAIL_CLOSED", "triage emit logic must fail closed to STATIC_HOLD")
    if tag_schema.get("tags_must_be_receipt_derived") is not True:
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_TAG_NOT_RECEIPT_DERIVED", "triage tags must be receipt-derived")
    if tag_schema.get("tags_must_be_source_packet_allowed") is not True:
        _fail("RC_B04R6_AFSH_ADM_TRIAGE_TAG_NOT_SOURCE_PACKET_ALLOWED", "triage tags must be source-packet allowed")
    forbidden_dependencies = set(tag_schema.get("forbidden_tag_dependencies", []))
    for dependency, code in [
        ("blind_outcome_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_BLIND_OUTCOME_DEPENDENT"),
        ("blind_route_success_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_ROUTE_SUCCESS_DEPENDENT"),
        ("post_screen_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_POST_SCREEN_DEPENDENT"),
        ("old_r01_r04_counted_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_OLD_UNIVERSE_DEPENDENT"),
        ("old_v2_six_row_counted_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_OLD_UNIVERSE_DEPENDENT"),
    ]:
        if dependency not in forbidden_dependencies:
            _fail(code, f"triage tag dependency must be forbidden: {dependency}")
    required_fields = set(receipt_schema.get("required_fields", []))
    for field in ("numeric_scores", "why_not_route", "selector_entry_authorized"):
        if field not in required_fields:
            _fail("RC_B04R6_AFSH_ADM_TRACE_SCHEMA_INCOMPLETE", f"triage receipt schema missing {field}")
    for field in NUMERIC_SCORE_FIELDS:
        if field not in score_schema.get("numeric_score_fields", []) or field not in receipt_schema.get("numeric_scores_required", []):
            _fail("RC_B04R6_AFSH_ADM_TRIAGE_SCORE_NONDETERMINISTIC", f"triage score field missing: {field}")


def _validate_trace_and_contamination(payloads: Dict[str, Dict[str, Any]]) -> None:
    candidate = payloads["candidate_artifact"]
    trace_receipt = payloads["trace_schema_receipt"]
    trace_requirements = candidate.get("trace_requirements", {})
    for field in TRACE_FIELDS:
        if trace_requirements.get(field) is not True or field not in trace_receipt.get("required_trace_fields", []):
            _fail("RC_B04R6_AFSH_ADM_TRACE_SCHEMA_INCOMPLETE", f"trace field missing: {field}")
    no_contamination = payloads["no_contamination_receipt"]
    forbidden_status = no_contamination.get("forbidden_access_status", {})
    for field in FORBIDDEN_ACCESS_FIELDS:
        if forbidden_status.get(field) is not False:
            _fail("RC_B04R6_AFSH_ADM_NO_CONTAMINATION_RECEIPT_MISSING", f"forbidden access drifted: {field}")
    if payloads["old_universe_diagnostic_only_receipt"].get("prior_r01_r04_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 treatment drifted")
    if payloads["old_universe_diagnostic_only_receipt"].get("prior_v2_six_row_treatment") != "DIAGNOSTIC_ONLY":
        _fail("RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row treatment drifted")


def _validate_prep_only_and_memory(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in ("prep_only_non_authority_receipt", "turboquant_translation", "compressed_receipt_index"):
        payload = payloads[role]
        if role != "prep_only_non_authority_receipt" and payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_AFSH_ADM_SHADOW_PACKET_AUTHORIZED_TOO_EARLY", f"{role} must remain PREP_ONLY")
    turbo = payloads["turboquant_translation"]
    if "SHADOW_SCREEN_EXECUTION" not in turbo.get("cannot_authorize", []):
        _fail("RC_B04R6_AFSH_ADM_SHADOW_SCREEN_EXECUTED", "memory prep must not authorize shadow execution")
    compressed = payloads["compressed_receipt_index"]
    if compressed.get("compressed_index_is_source_of_truth") is not False:
        _fail("RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "compressed index cannot become source of truth")
    if compressed.get("raw_hash_bound_artifact_required_after_retrieval") is not True:
        _fail("RC_B04R6_AFSH_ADM_CONTRACT_MISSING", "raw hash-bound artifact remains required")


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_generation_executed_in_prior_lane": True,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "afsh_admissibility_executed": True,
        "shadow_screen_packet_next_lawful_lane": True,
        "shadow_screen_packet_authorized_as_authority": False,
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
    candidate_replay_head: str,
    current_branch: str,
    status: str = "PASS",
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "candidate_replay_binding_head": candidate_replay_head,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "current_branch": current_branch,
        "allowed_outcomes": [OUTCOME_ADMISSIBLE, OUTCOME_DEFERRED, OUTCOME_BLOCKED, OUTCOME_INVALID],
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "candidate_generation_executed": True,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "afsh_candidate_training_authorized": False,
        "afsh_candidate_training_executed": False,
        "afsh_admissibility_executed": True,
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
        "reason_codes": list(ADMISSIBILITY_REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
    }
    if extra:
        payload.update(extra)
    return payload


def _validation_rows() -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    specs = [
        ("admissibility_contract_preserves_current_main_head", "RC_B04R6_AFSH_ADM_MAIN_HEAD_MISMATCH", "admissibility binds current main head", "core"),
        ("admissibility_binds_candidate_replay_head", "RC_B04R6_AFSH_ADM_CANDIDATE_REPLAY_HEAD_MISMATCH", "candidate replay head remains bound", "replay"),
        ("admissibility_binds_selected_afsh_architecture", "RC_B04R6_AFSH_ADM_ARCHITECTURE_MISMATCH", "AFSH-2S-GUARD remains selected", "core"),
        ("admissibility_binds_validated_blind_universe", "RC_B04R6_AFSH_ADM_UNIVERSE_BINDING_MISSING", "validated blind universe remains bound", "core"),
        ("admissibility_binds_validated_route_value_court", "RC_B04R6_AFSH_ADM_COURT_BINDING_MISSING", "validated route-value court remains bound", "core"),
        ("admissibility_binds_validated_source_packet", "RC_B04R6_AFSH_ADM_SOURCE_PACKET_BINDING_MISSING", "validated source packet remains bound", "core"),
        ("candidate_manifest_exists_and_parses", "RC_B04R6_AFSH_ADM_CANDIDATE_MANIFEST_MISSING", "candidate manifest exists", "manifest"),
        ("candidate_artifact_exists_and_parses", "RC_B04R6_AFSH_ADM_CANDIDATE_ARTIFACT_MISSING", "candidate artifact exists", "manifest"),
        ("candidate_hash_receipt_bound", "RC_B04R6_AFSH_ADM_CANDIDATE_HASH_MISSING", "candidate hash receipt bound", "hash"),
        ("candidate_semantic_hash_excludes_generated_utc", "RC_B04R6_AFSH_ADM_CANDIDATE_SEMANTIC_HASH_UNSTABLE", "semantic hash excludes generated_utc", "hash"),
        ("candidate_receipt_hash_includes_envelope", "RC_B04R6_AFSH_ADM_CANDIDATE_HASH_MISSING", "envelope hash separately bound", "hash"),
        ("candidate_immutable_inputs_share_replay_head", "RC_B04R6_AFSH_ADM_IMMUTABLE_INPUT_BINDING_MISSING", "immutable inputs share replay head", "replay"),
        ("candidate_mixed_head_inputs_fail_closed", "RC_B04R6_AFSH_ADM_IMMUTABLE_INPUT_MIXED_HEAD", "mixed-head immutable inputs fail closed", "replay"),
        ("candidate_mutable_handoff_bound_before_overwrite", "RC_B04R6_AFSH_ADM_MUTABLE_HANDOFF_NOT_BOUND", "mutable handoff bound before overwrite", "replay"),
        ("candidate_kind_is_deterministic_rule_materialization", "RC_B04R6_AFSH_ADM_CANDIDATE_KIND_INVALID", "candidate kind is deterministic", "candidate"),
        ("candidate_training_executed_false", "RC_B04R6_AFSH_ADM_TRAINING_EXECUTED", "training not executed", "training"),
        ("candidate_training_remains_unauthorized", "RC_B04R6_AFSH_ADM_TRAINING_AUTHORIZED", "training unauthorized", "training"),
        ("candidate_generation_executed_in_prior_lane_only", "RC_B04R6_AFSH_ADM_CANDIDATE_MANIFEST_MISSING", "generation occurred in prior lane", "candidate"),
        ("admissibility_does_not_execute_training", "RC_B04R6_AFSH_ADM_TRAINING_EXECUTED", "admissibility does not train", "training"),
        ("static_hold_default_preserved", "RC_B04R6_AFSH_ADM_STATIC_HOLD_DEFAULT_MISSING", "static hold default preserved", "behavior"),
        ("abstention_preservation_required", "RC_B04R6_AFSH_ADM_ABSTENTION_PRESERVATION_MISSING", "abstention preserved", "behavior"),
        ("null_route_preservation_required", "RC_B04R6_AFSH_ADM_NULL_ROUTE_PRESERVATION_MISSING", "null route preserved", "behavior"),
        ("mirror_masked_stability_required", "RC_B04R6_AFSH_ADM_MIRROR_MASKED_STABILITY_MISSING", "mirror/masked stability preserved", "behavior"),
        ("route_value_court_compatibility_preserved", "RC_B04R6_AFSH_ADM_COURT_BINDING_MISSING", "route-value court compatibility preserved", "behavior"),
        ("candidate_includes_numeric_triage_emit_core", "RC_B04R6_AFSH_ADM_TRIAGE_CORE_MISSING", "candidate includes numeric triage core", "triage"),
        ("triage_top_level_verdict_modes_match_validated_court_modes", "RC_B04R6_AFSH_ADM_TRIAGE_VERDICT_MODE_DRIFT", "triage verdicts match court", "triage"),
        ("triage_subtypes_do_not_create_new_verdict_modes", "RC_B04R6_AFSH_ADM_TRIAGE_SUBTYPE_BECAME_VERDICT", "triage subtypes are not verdicts", "triage"),
        ("only_route_eligible_enters_selector", "RC_B04R6_AFSH_ADM_TRIAGE_SELECTOR_ENTRY_DRIFT", "only ROUTE_ELIGIBLE enters selector", "triage"),
        ("static_hold_cases_do_not_enter_selector", "RC_B04R6_AFSH_ADM_TRIAGE_STATIC_HOLD_ENTERS_SELECTOR", "STATIC_HOLD terminates", "triage"),
        ("abstain_cases_do_not_enter_selector", "RC_B04R6_AFSH_ADM_TRIAGE_ABSTAIN_ENTERS_SELECTOR", "ABSTAIN terminates", "triage"),
        ("null_route_cases_do_not_enter_selector", "RC_B04R6_AFSH_ADM_TRIAGE_NULL_ROUTE_ENTERS_SELECTOR", "NULL_ROUTE terminates", "triage"),
        ("triage_scores_are_deterministic", "RC_B04R6_AFSH_ADM_TRIAGE_SCORE_NONDETERMINISTIC", "triage scores deterministic", "triage"),
        ("triage_emit_logic_is_fail_closed", "RC_B04R6_AFSH_ADM_TRIAGE_EMIT_NOT_FAIL_CLOSED", "triage emit logic fail closed", "triage"),
        ("triage_tags_are_receipt_derived", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_NOT_RECEIPT_DERIVED", "triage tags receipt-derived", "triage"),
        ("triage_tags_are_source_packet_allowed", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_NOT_SOURCE_PACKET_ALLOWED", "triage tags source-packet allowed", "triage"),
        ("triage_tags_do_not_use_blind_outcomes", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_BLIND_OUTCOME_DEPENDENT", "triage tags do not use blind outcomes", "triage"),
        ("triage_tags_do_not_use_route_success_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_ROUTE_SUCCESS_DEPENDENT", "triage tags do not use route-success labels", "triage"),
        ("triage_tags_do_not_use_post_screen_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_POST_SCREEN_DEPENDENT", "triage tags do not use post-screen labels", "triage"),
        ("triage_tags_do_not_use_old_r01_r04_counted_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_OLD_UNIVERSE_DEPENDENT", "triage tags do not use R01-R04 labels", "triage"),
        ("triage_tags_do_not_use_old_v2_six_row_counted_labels", "RC_B04R6_AFSH_ADM_TRIAGE_TAG_OLD_UNIVERSE_DEPENDENT", "triage tags do not use v2 six-row labels", "triage"),
        ("triage_receipt_schema_emits_numeric_scores", "RC_B04R6_AFSH_ADM_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits numeric scores", "triage"),
        ("triage_receipt_schema_emits_why_not_route", "RC_B04R6_AFSH_ADM_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits why-not-route", "triage"),
        ("triage_receipt_schema_emits_selector_entry_authorization_status", "RC_B04R6_AFSH_ADM_TRACE_SCHEMA_INCOMPLETE", "triage receipt emits selector-entry status", "triage"),
        ("no_contamination_receipt_passes", "RC_B04R6_AFSH_ADM_NO_CONTAMINATION_RECEIPT_MISSING", "no-contamination receipt passes", "contamination"),
        ("old_universe_diagnostic_only_receipt_passes", "RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "old universes diagnostic-only", "contamination"),
        ("prior_r01_r04_remain_diagnostic_only", "RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "R01-R04 diagnostic-only", "contamination"),
        ("prior_v2_six_row_remains_diagnostic_only", "RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "v2 six-row diagnostic-only", "contamination"),
        ("prep_only_shadow_screen_packet_draft_cannot_authorize_execution", "RC_B04R6_AFSH_ADM_SHADOW_PACKET_AUTHORIZED_TOO_EARLY", "shadow packet draft prep-only", "prep_only"),
        ("prep_only_shadow_metric_contract_cannot_change_current_metrics", "RC_B04R6_AFSH_ADM_METRIC_WIDENING", "shadow metric draft cannot widen metrics", "prep_only"),
        ("prep_only_disqualifier_ledger_cannot_authorize_screen", "RC_B04R6_AFSH_ADM_SHADOW_PACKET_AUTHORIZED_TOO_EARLY", "disqualifier draft prep-only", "prep_only"),
        ("prep_only_external_verifier_requirements_cannot_authorize_public_claims", "RC_B04R6_AFSH_ADM_SUPERIORITY_DRIFT", "external verifier draft cannot claim superiority", "prep_only"),
        ("turboquant_research_packet_remains_prep_only", "RC_B04R6_AFSH_ADM_SHADOW_PACKET_AUTHORIZED_TOO_EARLY", "TurboQuant remains prep-only", "memory"),
        ("compressed_index_cannot_be_source_of_truth", "RC_B04R6_AFSH_ADM_OLD_UNIVERSE_PROOF_DRIFT", "compressed index cannot be source of truth", "memory"),
        ("raw_hash_bound_artifact_required_after_compressed_retrieval", "RC_B04R6_AFSH_ADM_CONTRACT_MISSING", "raw artifact remains required", "memory"),
        ("admissibility_does_not_authorize_shadow_screen_execution", "RC_B04R6_AFSH_ADM_SHADOW_SCREEN_EXECUTED", "shadow execution unauthorized", "authorization"),
        ("admissibility_does_not_open_r6", "RC_B04R6_AFSH_ADM_R6_OPEN_DRIFT", "R6 remains closed", "authorization"),
        ("admissibility_does_not_claim_superiority", "RC_B04R6_AFSH_ADM_SUPERIORITY_DRIFT", "superiority unearned", "authorization"),
        ("admissibility_does_not_authorize_activation_review", "RC_B04R6_AFSH_ADM_ACTIVATION_DRIFT", "activation unauthorized", "authorization"),
        ("admissibility_does_not_authorize_package_promotion", "RC_B04R6_AFSH_ADM_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", "authorization"),
        ("metric_widening_forbidden", "RC_B04R6_AFSH_ADM_METRIC_WIDENING", "metric widening forbidden", "authorization"),
        ("comparator_weakening_forbidden", "RC_B04R6_AFSH_ADM_COMPARATOR_WEAKENING", "comparator weakening forbidden", "authorization"),
        ("truth_engine_mutation_forbidden", "RC_B04R6_AFSH_ADM_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", "authorization"),
        ("trust_zone_mutation_forbidden", "RC_B04R6_AFSH_ADM_TRUST_ZONE_MUTATION", "trust-zone law unchanged", "authorization"),
        ("no_authorization_drift_receipt_passes", "RC_B04R6_AFSH_ADM_SHADOW_SCREEN_EXECUTED", "no authorization drift", "authorization"),
        ("next_lawful_move_is_shadow_screen_packet", "RC_B04R6_AFSH_ADM_NEXT_MOVE_DRIFT", "next lawful move is shadow-screen packet authoring", "next_move"),
    ]
    for check_id, reason, detail, group in specs:
        rows.append(_pass_row(check_id, reason, detail, group=group))
    for field in TRACE_FIELDS:
        rows.append(_pass_row(f"trace_schema_emits_{field}", "RC_B04R6_AFSH_ADM_TRACE_SCHEMA_INCOMPLETE", f"trace emits {field}", group="trace"))
    return rows


def _prep_only_block(*, artifact_id: str, schema_id: str, purpose: str) -> Dict[str, Any]:
    return {
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "authority": "PREP_ONLY",
        "status": "PREP_ONLY",
        "purpose": purpose,
        "cannot_authorize_shadow_screen_execution": True,
        "cannot_open_r6": True,
        "cannot_claim_superiority": True,
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
        "schema_id": "kt.b04_r6.future_blocker_register.v3",
        "artifact_id": "B04_R6_FUTURE_BLOCKER_REGISTER",
        "current_authoritative_lane": "RUN_B04_R6_AFSH_ADMISSIBILITY_COURT",
        "blockers": [
            {
                "blocker_id": "B04R6-FB-018",
                "future_blocker": "Candidate is admissible but shadow-screen packet authority is not authored.",
                "neutralization_now": [
                    OUTPUTS["shadow_screen_packet_prep"],
                    OUTPUTS["shadow_screen_metric_contract_prep"],
                    OUTPUTS["shadow_screen_disqualifier_ledger_prep"],
                    OUTPUTS["shadow_screen_replay_manifest_prep"],
                    OUTPUTS["shadow_screen_external_verifier_requirements_prep"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-019",
                "future_blocker": "Shadow-screen packet accidentally authorizes execution rather than packet authoring.",
                "neutralization_now": [OUTPUTS["no_authorization_drift_receipt"]],
            },
            {
                "blocker_id": "B04R6-FB-020",
                "future_blocker": "External verifier or compression prep is treated as proof.",
                "neutralization_now": [OUTPUTS["shadow_screen_external_verifier_requirements_prep"]],
            },
        ],
    }


def _report(rows: list[Dict[str, str]]) -> str:
    lines = [
        "# B04 R6 AFSH Admissibility Court",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "This lane admits `B04_R6_AFSH_CANDIDATE_V1` for a future shadow-screen packet. It does not execute a shadow screen, open R6, claim learned-router superiority, authorize activation/cutover, escalate to lobes, promote a package, or mutate truth/trust law.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 AFSH admissibility court")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    text_payloads = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    candidate_replay_head = _require_candidate_generation_inputs(root, payloads, text_payloads)
    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_AFSH_ADM_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    validation_summary = _validate_candidate(payloads)
    _validate_immutable_inputs(payloads, replay_head=candidate_replay_head)
    _validate_triage(payloads)
    _validate_trace_and_contamination(payloads)
    _validate_prep_only_and_memory(payloads)

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)
    rows = _validation_rows()
    generated_utc = utc_now_iso_z()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        candidate_replay_head=candidate_replay_head,
        current_branch=current_branch,
    )
    common_extra = {
        **validation_summary,
        "candidate_admissibility_executed": True,
        "candidate_generation_executed": True,
        "candidate_training_executed": False,
        "shadow_screen_packet_authorized_as_authority": False,
        "shadow_screen_execution_authorized": False,
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
        OUTPUTS["admissibility_contract"]: receipt(
            "kt.b04_r6.afsh_admissibility_court_contract.v1",
            "B04_R6_AFSH_ADMISSIBILITY_COURT_CONTRACT",
            ("core", "manifest", "hash", "replay", "candidate", "training", "behavior", "triage", "trace", "contamination", "prep_only", "memory", "authorization", "next_move"),
            {"admissibility_verdict": "ADMISSIBLE_FOR_SHADOW_SCREEN_PACKET_AUTHORING_ONLY"},
        ),
        OUTPUTS["admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_admissibility_court_receipt.v1",
            "B04_R6_AFSH_ADMISSIBILITY_COURT_RECEIPT",
            ("core", "hash", "replay", "training", "behavior", "triage", "trace", "contamination", "authorization", "next_move"),
        ),
        OUTPUTS["candidate_manifest_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_manifest_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_MANIFEST_ADMISSIBILITY_RECEIPT",
            ("manifest", "candidate", "core"),
        ),
        OUTPUTS["candidate_hash_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_hash_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_HASH_ADMISSIBILITY_RECEIPT",
            ("hash",),
        ),
        OUTPUTS["candidate_semantic_hash_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_semantic_hash_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_SEMANTIC_HASH_ADMISSIBILITY_RECEIPT",
            ("hash",),
        ),
        OUTPUTS["candidate_replay_binding_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_replay_binding_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_REPLAY_BINDING_ADMISSIBILITY_RECEIPT",
            ("replay",),
        ),
        OUTPUTS["candidate_immutable_input_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_immutable_input_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_IMMUTABLE_INPUT_ADMISSIBILITY_RECEIPT",
            ("replay",),
        ),
        OUTPUTS["candidate_mutable_handoff_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_mutable_handoff_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_MUTABLE_HANDOFF_ADMISSIBILITY_RECEIPT",
            ("replay",),
        ),
        OUTPUTS["candidate_no_training_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_no_training_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_NO_TRAINING_ADMISSIBILITY_RECEIPT",
            ("training",),
        ),
        OUTPUTS["candidate_no_contamination_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_no_contamination_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_NO_CONTAMINATION_ADMISSIBILITY_RECEIPT",
            ("contamination",),
            {"forbidden_access_status": {field: False for field in FORBIDDEN_ACCESS_FIELDS}},
        ),
        OUTPUTS["candidate_old_universe_diagnostic_only_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_candidate_old_universe_diagnostic_only_admissibility_receipt.v1",
            "B04_R6_AFSH_CANDIDATE_OLD_UNIVERSE_DIAGNOSTIC_ONLY_ADMISSIBILITY_RECEIPT",
            ("contamination",),
            {"prior_r01_r04_treatment": "DIAGNOSTIC_ONLY", "prior_v2_six_row_treatment": "DIAGNOSTIC_ONLY"},
        ),
        OUTPUTS["triage_core_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_triage_core_admissibility_receipt.v1",
            "B04_R6_AFSH_TRIAGE_CORE_ADMISSIBILITY_RECEIPT",
            ("triage",),
        ),
        OUTPUTS["triage_emit_logic_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_triage_emit_logic_admissibility_receipt.v1",
            "B04_R6_AFSH_TRIAGE_EMIT_LOGIC_ADMISSIBILITY_RECEIPT",
            ("triage",),
        ),
        OUTPUTS["triage_selector_entry_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_triage_selector_entry_admissibility_receipt.v1",
            "B04_R6_AFSH_TRIAGE_SELECTOR_ENTRY_ADMISSIBILITY_RECEIPT",
            ("triage",),
        ),
        OUTPUTS["triage_tag_safety_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_triage_tag_safety_admissibility_receipt.v1",
            "B04_R6_AFSH_TRIAGE_TAG_SAFETY_ADMISSIBILITY_RECEIPT",
            ("triage",),
        ),
        OUTPUTS["trace_schema_admissibility_receipt"]: receipt(
            "kt.b04_r6.afsh_trace_schema_admissibility_receipt.v1",
            "B04_R6_AFSH_TRACE_SCHEMA_ADMISSIBILITY_RECEIPT",
            ("trace",),
            {"required_trace_fields": list(TRACE_FIELDS), "trace_schema_complete": True},
        ),
        OUTPUTS["no_authorization_drift_receipt"]: receipt(
            "kt.b04_r6.afsh_admissibility_no_authorization_drift_receipt.v1",
            "B04_R6_AFSH_ADMISSIBILITY_NO_AUTHORIZATION_DRIFT_RECEIPT",
            ("authorization", "next_move"),
            {"no_downstream_authorization_drift": True},
        ),
        OUTPUTS["future_blocker_register"]: _future_blocker_register(),
        OUTPUTS["next_lawful_move"]: receipt(
            "kt.operator.b04_r6_next_lawful_move_receipt.v11",
            "B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            ("next_move",),
            {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE},
        ),
        OUTPUTS["admissibility_report"]: _report(rows),
    }
    outputs.update(
        {
            OUTPUTS["shadow_screen_packet_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_SHADOW_SCREEN_PACKET_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_shadow_screen_packet_prep_only_draft.v1",
                purpose="Prep-only draft for authoring a future shadow-screen execution packet after admissibility.",
            ),
            OUTPUTS["shadow_screen_metric_contract_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_SHADOW_SCREEN_METRIC_CONTRACT_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_shadow_screen_metric_contract_prep_only_draft.v1",
                purpose="Prep-only frozen metric contract draft; cannot widen current metrics.",
            ),
            OUTPUTS["shadow_screen_disqualifier_ledger_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_SHADOW_SCREEN_DISQUALIFIER_LEDGER_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_shadow_screen_disqualifier_ledger_prep_only_draft.v1",
                purpose="Prep-only disqualifier ledger draft for a future screen packet.",
            ),
            OUTPUTS["shadow_screen_replay_manifest_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_SHADOW_SCREEN_REPLAY_MANIFEST_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_shadow_screen_replay_manifest_prep_only_draft.v1",
                purpose="Prep-only replay manifest draft for a future screen packet.",
            ),
            OUTPUTS["shadow_screen_external_verifier_requirements_prep"]: _prep_only_block(
                artifact_id="B04_R6_AFSH_SHADOW_SCREEN_EXTERNAL_VERIFIER_REQUIREMENTS_PREP_ONLY_DRAFT",
                schema_id="kt.b04_r6.afsh_shadow_screen_external_verifier_requirements_prep_only_draft.v1",
                purpose="Prep-only external verifier requirements; cannot authorize public superiority claims.",
            ),
        }
    )

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "pass_count": len(rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run B04 R6 AFSH admissibility court.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=Path(args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
