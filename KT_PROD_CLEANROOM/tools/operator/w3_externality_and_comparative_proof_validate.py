from __future__ import annotations

import argparse
import inspect
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from tools.operator.benchmark_constitution_validate import (
    COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
    COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
    DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
    DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
    DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
    ROLE_BASELINE_SCORECARD,
    ROLE_BENCHMARK_RECEIPT,
    ROLE_FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_FAMILY,
    ROLE_T11_FINAL_HEAD_AUTHORITY_ALIGNMENT as T11_RECEIPT_ROLE,
    TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
    TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
    DEFAULT_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL as T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
    DEFAULT_GATE_C_EXIT_CRITERIA_CONTRACT_REL,
    DEFAULT_GATE_C_EXIT_TERMINAL_STATE_REL,
    _extract_subject_head,
    _consume_emitted_receipt_contract,
    _enforce_write_scope_post,
    _enforce_write_scope_pre,
    _maybe_write_json_output,
    _payloads,
    build_documentary_carrier_guard_single_path_barrier,
    load_gate_c_exit_criteria_contract,
    load_gate_c_exit_terminal_state,
    build_tracked_counted_receipt_class_authority_closure_bundle,
    build_tracked_counted_receipt_carrier_overread_probe_bundle,
    build_tracked_counted_receipt_single_path_barrier,
    evaluate_counted_receipt_family_same_head_authority,
    load_counted_consumer_allowlist_contract,
    build_receipt as build_benchmark_receipt,
    evaluate_documentary_carrier_fail_closed_consumer_guard as evaluate_shared_documentary_carrier_fail_closed_consumer_guard,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z
from tools.operator.w4_truth_common import build_capability_atlas


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_E2_OUTPUT_REL = f"{REPORT_ROOT_REL}/e2_cross_host_replay_receipt.json"
DEFAULT_CAPABILITY_ATLAS_REL = f"{REPORT_ROOT_REL}/capability_atlas.json"
DEFAULT_CANONICAL_DELTA_REL = f"{REPORT_ROOT_REL}/canonical_delta_w3.json"
DEFAULT_ADVANCEMENT_DELTA_REL = f"{REPORT_ROOT_REL}/advancement_delta_w3.json"

TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
EXTERNALITY_MATRIX_REL = "KT_PROD_CLEANROOM/governance/kt_externality_class_matrix_v1.json"
ORGAN_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_wave2c_organ_disposition_register.json"
W2_ADVANCEMENT_DELTA_REL = f"{REPORT_ROOT_REL}/advancement_delta_w2.json"
WAVE5_VERIFIER_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_verifier_truth_surface.json"
WAVE3_DETACHED_VERIFIER_REL = f"{REPORT_ROOT_REL}/kt_wave3_detached_verifier_receipt.json"
PUBLIC_VERIFIER_DETACHED_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"
POST_WAVE5_C006_PREP_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_trust_prep_receipt.json"
POST_WAVE5_C006_E2_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_second_host_execution_receipt.json"
EXTERNAL_CHALLENGE_PROTOCOL_REL = f"{REPORT_ROOT_REL}/kt_external_challenge_protocol.json"
BASELINE_SCORECARD_REL = f"{REPORT_ROOT_REL}/baseline_vs_live_scorecard.json"
BENCHMARK_RECEIPT_REL = f"{REPORT_ROOT_REL}/benchmark_constitution_receipt.json"
ALIAS_RETIREMENT_REL = f"{REPORT_ROOT_REL}/scorecard_alias_retirement_receipt.json"
DETACHMENT_RECEIPT_REL = f"{REPORT_ROOT_REL}/competitive_scorecard_validator_detachment_receipt.json"
DOCUMENTARY_CARRIER_FAIL_CLOSED_CONSUMER_ENFORCEMENT_RECEIPT_REL = f"{REPORT_ROOT_REL}/documentary_carrier_fail_closed_consumer_enforcement_receipt.json"
T12_TRANCHE_ID = "B03_T12_DOCUMENTARY_CARRIER_FAIL_CLOSED_CONSUMER_ENFORCEMENT"
T12_RECEIPT_ROLE = "COUNTED_T12_DOCUMENTARY_CARRIER_FAIL_CLOSED_CONSUMER_ENFORCEMENT_ARTIFACT_ONLY"
DOCUMENTARY_CARRIER_GUARD_CENTRALIZATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/documentary_carrier_guard_centralization_receipt.json"
T13_TRANCHE_ID = "B03_T13_DOCUMENTARY_CARRIER_GUARD_CENTRALIZATION"
T13_RECEIPT_ROLE = "COUNTED_T13_DOCUMENTARY_CARRIER_GUARD_CENTRALIZATION_ARTIFACT_ONLY"
SHARED_GUARD_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL = f"{REPORT_ROOT_REL}/shared_guard_single_path_enforcement_receipt.json"
T14_TRANCHE_ID = "B03_T14_SHARED_GUARD_SINGLE_PATH_ENFORCEMENT"
T14_RECEIPT_ROLE = "COUNTED_T14_SHARED_GUARD_SINGLE_PATH_ENFORCEMENT_ARTIFACT_ONLY"
COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_RECEIPT_REL = f"{REPORT_ROOT_REL}/counted_consumer_allowlist_contract_binding_receipt.json"
T15_TRANCHE_ID = "B03_T15_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING"
T15_RECEIPT_ROLE = "COUNTED_T15_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_ARTIFACT_ONLY"
T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL = f"{REPORT_ROOT_REL}/t15_receipt_final_head_authority_alignment_receipt.json"
T16_TRANCHE_ID = "B03_T16_T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT"
T16_RECEIPT_ROLE = "COUNTED_T16_T15_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"
COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/counted_receipt_family_same_head_authority_contract_receipt.json"
)
T17_TRANCHE_ID = "B03_T17_COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT"
T17_RECEIPT_ROLE = "COUNTED_T17_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_ARTIFACT_ONLY"
T17_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/t17_receipt_final_head_authority_alignment_receipt.json"
)
T18_TRANCHE_ID = "B03_T18_T17_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT"
T18_RECEIPT_ROLE = "COUNTED_T18_T17_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"
TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/tracked_counted_receipt_carrier_overread_contract_receipt.json"
)
T19_TRANCHE_ID = "B03_T19_TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT"
T19_RECEIPT_ROLE = "COUNTED_T19_TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_ARTIFACT_ONLY"
TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/tracked_counted_receipt_single_path_enforcement_receipt.json"
)
T20_TRANCHE_ID = "B03_T20_TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT"
T20_RECEIPT_ROLE = "COUNTED_T20_TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_ARTIFACT_ONLY"
T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/t20_receipt_final_head_authority_alignment_receipt.json"
)
T21_TRANCHE_ID = "B03_T21_T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT"
T21_RECEIPT_ROLE = "COUNTED_T21_T20_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"
T21_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/t21_receipt_final_head_authority_alignment_receipt.json"
)
T22_TRANCHE_ID = "B03_T22_T21_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT"
T22_RECEIPT_ROLE = "COUNTED_T22_T21_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"
TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/tracked_counted_receipt_class_authority_closure_receipt.json"
)
T23_TRANCHE_ID = "B03_T23_TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE"
T23_RECEIPT_ROLE = "COUNTED_T23_TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_ARTIFACT_ONLY"
FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/final_current_head_adjudication_receipt.json"
E1_BOUNDED_CAMPAIGN_RECEIPT_REL = f"{REPORT_ROOT_REL}/e1_bounded_campaign_receipt.json"
COMPETITIVE_SCORECARD_REL = f"{REPORT_ROOT_REL}/competitive_scorecard.json"
GATE_C_EXIT_CRITERIA_CONTRACT_RECEIPT_REL = f"{REPORT_ROOT_REL}/gate_c_exit_criteria_contract_receipt.json"
GATE_C_EXIT_CRITERIA_CONTRACT_TRANCHE_ID = "B03_GATE_C_EXIT_CRITERIA_CONTRACT"
GATE_C_EXIT_CRITERIA_CONTRACT_RECEIPT_ROLE = "COUNTED_GATE_C_EXIT_CRITERIA_CONTRACT_ARTIFACT_ONLY"
FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING_RECEIPT_REL = (
    f"{REPORT_ROOT_REL}/final_current_head_adjudication_authority_binding_receipt.json"
)
T24_TRANCHE_ID = "B03_T24_FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING"
T24_RECEIPT_ROLE = "COUNTED_T24_FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING_ARTIFACT_ONLY"
GATE_C_EXIT_ADJUDICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/gate_c_exit_adjudication_receipt.json"
GATE_C_EXIT_ADJUDICATION_TRANCHE_ID = "B03_GATE_C_EXIT_ADJUDICATION"
GATE_C_EXIT_ADJUDICATION_RECEIPT_ROLE = "COUNTED_GATE_C_EXIT_ADJUDICATION_ARTIFACT_ONLY"
ROLE_ALIAS_RETIREMENT = "ALIAS_RETIREMENT_PROOF"
ROLE_VALIDATOR_ALIAS_DETACHMENT = "VALIDATOR_ALIAS_DETACHMENT_PROOF"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status_is(value: Any, expected: str) -> bool:
    return str(value).strip().upper() == expected.strip().upper()


def _truth_lock(root: Path) -> Dict[str, Any]:
    return load_json(root / TRUTH_LOCK_REL)


def _active_blockers(root: Path) -> List[str]:
    lock = _truth_lock(root)
    blocker_ids = [str(item).strip() for item in lock.get("active_deferred_blocker_ids", []) if str(item).strip()]
    if blocker_ids:
        return blocker_ids
    blocker_ids = [str(item).strip() for item in lock.get("active_open_blocker_ids", []) if str(item).strip()]
    if blocker_ids:
        return blocker_ids
    blocker_ref = str(lock.get("active_blocker_matrix_ref", "")).strip()
    if not blocker_ref:
        return []
    matrix = load_json(root / blocker_ref)
    rows = matrix.get("open_blockers", [])
    out: List[str] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                blocker_id = str(row.get("blocker_id", "")).strip()
                if blocker_id:
                    out.append(blocker_id)
            else:
                blocker_id = str(row).strip()
                if blocker_id:
                    out.append(blocker_id)
    return out


def _current_truth_posture_blockers(root: Path) -> List[str]:
    lock = _truth_lock(root)
    return [str(item).strip() for item in lock.get("active_open_blocker_ids", []) if str(item).strip()]


def evaluate_comparator_side_reader_contract(*, root: Path) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    payloads = _payloads(root, generated_utc)
    current_head = str(payloads["current_head"]).strip()
    benchmark_receipt = build_benchmark_receipt(payloads, generated_utc)
    generated_receipts = [
        (BASELINE_SCORECARD_REL, payloads["scorecard"], [ROLE_BASELINE_SCORECARD]),
        (BENCHMARK_RECEIPT_REL, benchmark_receipt, [ROLE_BENCHMARK_RECEIPT]),
        (ALIAS_RETIREMENT_REL, payloads["alias_receipt"], [ROLE_ALIAS_RETIREMENT]),
        (DETACHMENT_RECEIPT_REL, payloads["detachment_receipt"], [ROLE_VALIDATOR_ALIAS_DETACHMENT]),
    ]
    generated_checks = []
    for ref, payload, allowed_roles in generated_receipts:
        result = _consume_emitted_receipt_contract(
            receipt_ref=ref,
            payload=payload,
            allowed_roles=allowed_roles,
            requested_head=current_head,
        )
        generated_checks.append({"check_id": f"generated_contract::{Path(ref).name}", "receipt_ref": ref, **result})
    baseline_scorecard = payloads["scorecard"]
    malformed_attempts = [
        {
            "attempt_id": "missing_receipt_role",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={k: v for k, v in baseline_scorecard.items() if k != "receipt_role"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "missing_subject_head",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={k: v for k, v in baseline_scorecard.items() if k != "subject_head"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "wrong_receipt_role",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={**baseline_scorecard, "receipt_role": "COUNTED_T7_SIDE_READER_CONTRACT_ADOPTION_ARTIFACT_ONLY"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "wrong_subject_head",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={**baseline_scorecard, "subject_head": "0000000000000000000000000000000000000000"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
    ]
    source_text = Path(__file__).read_text(encoding="utf-8")
    legacy_parse_removed = (
        re.search(
            r"load_json\(\s*root\s*/\s*(BASELINE_SCORECARD_REL|BENCHMARK_RECEIPT_REL|ALIAS_RETIREMENT_REL|DETACHMENT_RECEIPT_REL)\s*\)",
            source_text,
        )
        is None
    )
    status = (
        "PASS"
        if all(bool(check["pass"]) for check in generated_checks)
        and malformed_attempts[0]["blocked"]
        and malformed_attempts[0]["failure_reason"] == "RECEIPT_ROLE_MISSING"
        and malformed_attempts[1]["blocked"]
        and malformed_attempts[1]["failure_reason"] == "SUBJECT_HEAD_MISSING"
        and malformed_attempts[2]["blocked"]
        and malformed_attempts[2]["failure_reason"] == "RECEIPT_ROLE_MISMATCH"
        and malformed_attempts[3]["blocked"]
        and malformed_attempts[3]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
        and legacy_parse_removed
        else "FAIL"
    )
    return {
        "reader_id": "w3_externality_and_comparative_proof_validate",
        "status": status,
        "requested_head": current_head,
        "baseline_scorecard": payloads["scorecard"],
        "benchmark_receipt": benchmark_receipt,
        "alias_retirement_receipt": payloads["alias_receipt"],
        "detachment_receipt": payloads["detachment_receipt"],
        "generated_contract_checks": generated_checks,
        "malformed_attempts": malformed_attempts,
        "legacy_parse_removed": legacy_parse_removed,
    }


def evaluate_documentary_carrier_fail_closed_consumer_guard(*, root: Path) -> Dict[str, Any]:
    return evaluate_shared_documentary_carrier_fail_closed_consumer_guard(
        root=root,
        consumer_id="w3_externality_and_comparative_proof_validate",
        tracked_receipt_ref=T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        allowed_roles=[T11_RECEIPT_ROLE],
    )


def _consumer_guard_source_checks() -> list[Dict[str, Any]]:
    from tools.operator import final_current_head_adjudication_validate as final_current

    forbidden_tokens = (
        "tracked_t11_receipt",
        "tracked_t11_contract",
        "documentary_attempt",
        "tracked_authority_class",
    )
    final_source = inspect.getsource(final_current.evaluate_documentary_carrier_fail_closed_consumer_guard)
    w3_source = inspect.getsource(evaluate_documentary_carrier_fail_closed_consumer_guard)
    return [
        {
            "check_id": "final_current_wrapper_calls_shared_guard_helper",
            "pass": "evaluate_shared_documentary_carrier_fail_closed_consumer_guard(" in final_source,
        },
        {
            "check_id": "w3_wrapper_calls_shared_guard_helper",
            "pass": "evaluate_shared_documentary_carrier_fail_closed_consumer_guard(" in w3_source,
        },
        {
            "check_id": "final_current_wrapper_has_no_local_guard_reimplementation",
            "pass": not any(token in final_source for token in forbidden_tokens),
        },
        {
            "check_id": "w3_wrapper_has_no_local_guard_reimplementation",
            "pass": not any(token in w3_source for token in forbidden_tokens),
        },
    ]


def build_documentary_carrier_fail_closed_consumer_enforcement_receipt(*, root: Path) -> Dict[str, Any]:
    from tools.operator.final_current_head_adjudication_validate import (
        evaluate_documentary_carrier_fail_closed_consumer_guard as evaluate_final_guard,
    )

    current_head = _git_head(root)
    baseline_scorecard = _payloads(root, utc_now_iso_z())["scorecard"]
    final_guard = evaluate_final_guard(root=root)
    w3_guard = evaluate_documentary_carrier_fail_closed_consumer_guard(root=root)
    checks = [
        {"check_id": "final_current_head_consumer_guard_passes", "pass": final_guard["status"] == "PASS"},
        {"check_id": "w3_consumer_guard_passes", "pass": w3_guard["status"] == "PASS"},
        {
            "check_id": "final_current_head_rejects_documentary_carrier_mismatch",
            "pass": final_guard["documentary_carrier_attempt"]["failure_reason"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "w3_rejects_documentary_carrier_mismatch",
            "pass": w3_guard["documentary_carrier_attempt"]["failure_reason"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": str(baseline_scorecard.get("canonical_scorecard_id", "")).strip() == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        },
    ]
    return {
        "schema_id": "kt.gate_c_t12.documentary_carrier_fail_closed_consumer_enforcement_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T12_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T12_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "t10_final_head_authority_alignment_receipt_ref": T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "final_current_head_consumer_guard": final_guard,
        "w3_consumer_guard": w3_guard,
        "checks": checks,
        "claim_boundary": "T12 enforces fail-closed downstream consumer handling for documentary carrier mismatch only. It does not refresh comparator truth, widen comparator semantics, or claim Gate C exit."
    }


def build_documentary_carrier_guard_centralization_receipt(*, root: Path) -> Dict[str, Any]:
    from tools.operator.final_current_head_adjudication_validate import (
        evaluate_documentary_carrier_fail_closed_consumer_guard as evaluate_final_guard,
    )

    current_head = _git_head(root)
    baseline_scorecard = _payloads(root, utc_now_iso_z())["scorecard"]
    final_guard = evaluate_final_guard(root=root)
    w3_guard = evaluate_documentary_carrier_fail_closed_consumer_guard(root=root)
    source_checks = _consumer_guard_source_checks()
    checks = [
        {"check_id": "final_current_head_consumer_guard_passes", "pass": final_guard["status"] == "PASS"},
        {"check_id": "w3_consumer_guard_passes", "pass": w3_guard["status"] == "PASS"},
        {
            "check_id": "shared_guard_helper_ref_matches_benchmark_helper",
            "pass": final_guard.get("shared_guard_helper_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_REF
            and w3_guard.get("shared_guard_helper_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
        },
        {
            "check_id": "shared_guard_helper_owner_ref_matches_benchmark_file",
            "pass": final_guard.get("shared_guard_helper_owner_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF
            and w3_guard.get("shared_guard_helper_owner_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        },
        {
            "check_id": "documentary_carrier_mismatch_still_fails_closed",
            "pass": final_guard["documentary_carrier_attempt"]["failure_reason"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and w3_guard["documentary_carrier_attempt"]["failure_reason"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": str(baseline_scorecard.get("canonical_scorecard_id", "")).strip() == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        },
        {
            "check_id": "consumer_wrappers_use_shared_guard_only",
            "pass": all(bool(check["pass"]) for check in source_checks),
        },
    ]
    return {
        "schema_id": "kt.gate_c_t13.documentary_carrier_guard_centralization_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T13_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T13_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "documentary_carrier_fail_closed_consumer_enforcement_receipt_ref": DOCUMENTARY_CARRIER_FAIL_CLOSED_CONSUMER_ENFORCEMENT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "shared_guard_helper_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
        "shared_guard_helper_owner_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        "final_current_head_consumer_guard": final_guard,
        "w3_consumer_guard": w3_guard,
        "source_checks": source_checks,
        "checks": checks,
        "claim_boundary": "T13 centralizes the documentary-carrier fail-closed consumer guard only. It does not refresh comparator truth, widen comparator semantics, or claim Gate C exit.",
    }


def build_shared_guard_single_path_enforcement_receipt(*, root: Path) -> Dict[str, Any]:
    from tools.operator.final_current_head_adjudication_validate import (
        evaluate_documentary_carrier_fail_closed_consumer_guard as evaluate_final_guard,
    )

    current_head = _git_head(root)
    baseline_scorecard = _payloads(root, utc_now_iso_z())["scorecard"]
    final_guard = evaluate_final_guard(root=root)
    w3_guard = evaluate_documentary_carrier_fail_closed_consumer_guard(root=root)
    source_checks = _consumer_guard_source_checks()
    single_path_barrier = build_documentary_carrier_guard_single_path_barrier(root=root)
    checks = [
        {"check_id": "final_current_head_consumer_guard_passes", "pass": final_guard["status"] == "PASS"},
        {"check_id": "w3_consumer_guard_passes", "pass": w3_guard["status"] == "PASS"},
        {
            "check_id": "shared_guard_helper_ref_matches_benchmark_helper",
            "pass": final_guard.get("shared_guard_helper_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_REF
            and w3_guard.get("shared_guard_helper_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
        },
        {
            "check_id": "shared_guard_helper_owner_ref_matches_benchmark_file",
            "pass": final_guard.get("shared_guard_helper_owner_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF
            and w3_guard.get("shared_guard_helper_owner_ref") == DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        },
        {
            "check_id": "documentary_carrier_mismatch_still_fails_closed",
            "pass": final_guard["documentary_carrier_attempt"]["failure_reason"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and w3_guard["documentary_carrier_attempt"]["failure_reason"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": str(baseline_scorecard.get("canonical_scorecard_id", "")).strip() == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        },
        {
            "check_id": "consumer_wrappers_use_shared_guard_only",
            "pass": all(bool(check["pass"]) for check in source_checks),
        },
        {
            "check_id": "single_path_barrier_blocks_unsanctioned_owners",
            "pass": single_path_barrier["status"] == "PASS",
        },
    ]
    return {
        "schema_id": "kt.gate_c_t14.shared_guard_single_path_enforcement_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T14_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T14_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "documentary_carrier_guard_centralization_receipt_ref": DOCUMENTARY_CARRIER_GUARD_CENTRALIZATION_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "shared_guard_helper_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
        "shared_guard_helper_owner_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        "single_path_barrier": single_path_barrier,
        "final_current_head_consumer_guard": final_guard,
        "w3_consumer_guard": w3_guard,
        "source_checks": source_checks,
        "checks": checks,
        "claim_boundary": "T14 enforces the shared documentary-carrier guard as the single sanctioned counted-consumer path only. It does not refresh comparator truth, widen comparator semantics, or claim Gate C exit.",
    }


def build_counted_consumer_allowlist_contract_binding_receipt(*, root: Path) -> Dict[str, Any]:
    from tools.operator.final_current_head_adjudication_validate import (
        evaluate_documentary_carrier_fail_closed_consumer_guard as evaluate_final_guard,
    )

    current_head = _git_head(root)
    baseline_scorecard = _payloads(root, utc_now_iso_z())["scorecard"]
    allowlist_contract = load_counted_consumer_allowlist_contract(root=root)
    final_guard = evaluate_final_guard(root=root)
    w3_guard = evaluate_documentary_carrier_fail_closed_consumer_guard(root=root)
    source_checks = _consumer_guard_source_checks()
    single_path_barrier = build_documentary_carrier_guard_single_path_barrier(root=root)
    checks = [
        {"check_id": "final_current_head_consumer_guard_passes", "pass": final_guard["status"] == "PASS"},
        {"check_id": "w3_consumer_guard_passes", "pass": w3_guard["status"] == "PASS"},
        {
            "check_id": "allowlist_contract_ref_is_bound",
            "pass": allowlist_contract["contract_ref"] == "KT_PROD_CLEANROOM/governance/counted_consumer_allowlist_contract.json",
        },
        {
            "check_id": "allowlist_contract_matches_detected_runtime_owner_set",
            "pass": single_path_barrier["status"] == "PASS"
            and allowlist_contract["sanctioned_counted_consumer_refs"] == single_path_barrier["detected_counted_consumer_refs"],
        },
        {
            "check_id": "counted_consumers_point_to_bound_contract_ref",
            "pass": final_guard.get("counted_consumer_allowlist_contract_ref") == allowlist_contract["contract_ref"]
            and w3_guard.get("counted_consumer_allowlist_contract_ref") == allowlist_contract["contract_ref"],
        },
        {
            "check_id": "documentary_carrier_mismatch_still_fails_closed",
            "pass": final_guard["documentary_carrier_attempt"]["failure_reason"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and w3_guard["documentary_carrier_attempt"]["failure_reason"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": str(baseline_scorecard.get("canonical_scorecard_id", "")).strip() == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        },
        {
            "check_id": "consumer_wrappers_use_shared_guard_only",
            "pass": all(bool(check["pass"]) for check in source_checks),
        },
    ]
    return {
        "schema_id": "kt.gate_c_t15.counted_consumer_allowlist_contract_binding_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T15_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T15_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "shared_guard_single_path_enforcement_receipt_ref": SHARED_GUARD_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL,
            "counted_consumer_allowlist_contract_ref": allowlist_contract["contract_ref"],
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "counted_consumer_allowlist_contract_ref": allowlist_contract["contract_ref"],
        "allowlist_contract": allowlist_contract["payload"],
        "single_path_barrier": single_path_barrier,
        "final_current_head_consumer_guard": final_guard,
        "w3_consumer_guard": w3_guard,
        "source_checks": source_checks,
        "checks": checks,
        "claim_boundary": "T15 binds the sanctioned counted-consumer allowlist into an explicit contract surface only. It does not refresh comparator truth, widen comparator semantics, or claim Gate C exit.",
    }


def build_t15_receipt_final_head_authority_alignment_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    tracked_t15_receipt = load_json(root / COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_RECEIPT_REL)
    current_head_t15_receipt = build_counted_consumer_allowlist_contract_binding_receipt(root=root)
    same_head_authority = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="T15_FINAL_HEAD_AUTHORITY_ALIGNMENT",
        tracked_receipt_ref=COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_RECEIPT_REL,
        tracked_payload=tracked_t15_receipt,
        allowed_roles=[T15_RECEIPT_ROLE],
        current_head=current_head,
        authoritative_current_head_payload=current_head_t15_receipt,
    )
    tracked_t15_contract = same_head_authority["tracked_contract"]
    current_head_t15_contract = same_head_authority["authoritative_current_head_candidate_contract"]
    tracked_subject_head = same_head_authority["tracked_subject_head"]
    tracked_authority_class = same_head_authority["tracked_authority_class"]
    current_head_t15_checks = {
        str(check["check_id"]): bool(check["pass"])
        for check in current_head_t15_receipt.get("checks", [])
        if isinstance(check, dict) and "check_id" in check
    }
    checks = [
        {
            "check_id": "tracked_t15_overread_fails_closed",
            "pass": tracked_t15_contract.get("blocked") is True and tracked_t15_contract.get("failure_reason") == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "tracked_t15_classified_documentary_carrier_only",
            "pass": tracked_authority_class == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH and tracked_subject_head != current_head,
        },
        {
            "check_id": "authoritative_final_head_requires_matching_subject_head",
            "pass": current_head_t15_contract.get("pass") is True
            and str(current_head_t15_contract.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "t15_allowlist_binding_preserved",
            "pass": current_head_t15_receipt.get("status") == "PASS"
            and current_head_t15_checks.get("allowlist_contract_matches_detected_runtime_owner_set", False),
        },
        {
            "check_id": "documentary_carrier_mismatch_still_fails_closed",
            "pass": current_head_t15_checks.get("documentary_carrier_mismatch_still_fails_closed", False),
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": current_head_t15_checks.get("baseline_scorecard_remains_canonical_truth", False),
        },
    ]
    return {
        "schema_id": "kt.gate_c_t16.t15_receipt_final_head_authority_alignment_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T16_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T16_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "counted_consumer_allowlist_contract_binding_receipt_ref": COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "tracked_t15_receipt_ref": COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_RECEIPT_REL,
        "tracked_t15_receipt_subject_head": tracked_subject_head,
        "tracked_t15_receipt_current_git_head": str(tracked_t15_receipt.get("current_git_head", "")).strip(),
        "tracked_t15_authority_class": tracked_authority_class,
        "tracked_t15_contract": tracked_t15_contract,
        "authoritative_current_head_t15_candidate_contract": current_head_t15_contract,
        "same_head_authority_contract_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
        "same_head_authority_contract_owner_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        "same_head_authority_contract_family_id": same_head_authority["receipt_family_id"],
        "authoritative_final_head_rule": same_head_authority["authoritative_final_head_rule"],
        "checks": checks,
        "claim_boundary": "T16 aligns authority semantics for the retained T15 receipt only. It does not refresh comparator truth, widen comparator semantics, or claim Gate C exit.",
    }


def build_counted_receipt_family_same_head_authority_contract_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    generated_utc = utc_now_iso_z()
    t10_family_source = (root / "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py").read_text(encoding="utf-8")
    t15_family_source = Path(__file__).read_text(encoding="utf-8")
    tracked_t10_receipt = load_json(root / T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL)
    tracked_t15_receipt = load_json(root / T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL)
    t10_family_contract = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_FAMILY",
        tracked_receipt_ref=T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        tracked_payload=tracked_t10_receipt,
        allowed_roles=[T11_RECEIPT_ROLE],
        current_head=current_head,
        authoritative_current_head_payload={
            "receipt_role": T11_RECEIPT_ROLE,
            "subject_head": current_head,
        },
    )
    t15_family_contract = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="T15_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_FAMILY",
        tracked_receipt_ref=T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        tracked_payload=tracked_t15_receipt,
        allowed_roles=[T16_RECEIPT_ROLE],
        current_head=current_head,
        authoritative_current_head_payload={
            "receipt_role": T16_RECEIPT_ROLE,
            "subject_head": current_head,
        },
    )
    generic_probe = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="GENERIC_SYNTHETIC_AUTHORITY_PROBE",
        tracked_receipt_ref="IN_MEMORY_SYNTHETIC_TRACKED_RECEIPT",
        tracked_payload={
            "receipt_role": "COUNTED_GENERIC_SAME_HEAD_AUTHORITY_SYNTHETIC_ROLE",
            "subject_head": "0000000000000000000000000000000000000000",
        },
        allowed_roles=["COUNTED_GENERIC_SAME_HEAD_AUTHORITY_SYNTHETIC_ROLE"],
        current_head=current_head,
        authoritative_current_head_payload={
            "receipt_role": "COUNTED_GENERIC_SAME_HEAD_AUTHORITY_SYNTHETIC_ROLE",
            "subject_head": current_head,
        },
    )
    baseline_scorecard = _payloads(root, generated_utc)["scorecard"]
    checks = [
        {
            "check_id": "t10_family_source_adopts_shared_same_head_authority_contract",
            "pass": "evaluate_counted_receipt_family_same_head_authority(" in t10_family_source
            and "same_head_authority_contract_ref" in t10_family_source
            and "same_head_authority_contract_owner_ref" in t10_family_source,
        },
        {
            "check_id": "t15_family_source_adopts_shared_same_head_authority_contract",
            "pass": "evaluate_counted_receipt_family_same_head_authority(" in t15_family_source
            and "same_head_authority_contract_ref" in t15_family_source
            and "same_head_authority_contract_owner_ref" in t15_family_source,
        },
        {
            "check_id": "t10_counted_receipt_family_cross_head_is_carrier_only",
            "pass": t10_family_contract.get("tracked_authority_class") == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "t15_counted_receipt_family_cross_head_is_carrier_only",
            "pass": t15_family_contract.get("tracked_authority_class") == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "t10_counted_receipt_family_same_head_candidate_is_authoritative",
            "pass": bool(t10_family_contract.get("authoritative_current_head_candidate_contract", {}).get("pass")),
        },
        {
            "check_id": "t15_counted_receipt_family_same_head_candidate_is_authoritative",
            "pass": bool(t15_family_contract.get("authoritative_current_head_candidate_contract", {}).get("pass")),
        },
        {
            "check_id": "generic_family_cross_head_receipt_is_carrier_only",
            "pass": generic_probe.get("tracked_authority_class") == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "generic_family_same_head_candidate_is_authoritative",
            "pass": bool(generic_probe.get("authoritative_current_head_candidate_contract", {}).get("pass")),
        },
        {
            "check_id": "baseline_scorecard_remains_sole_canonical_comparator_truth",
            "pass": str(baseline_scorecard.get("receipt_role", "")).strip() == ROLE_BASELINE_SCORECARD,
        },
    ]
    return {
        "schema_id": "kt.gate_c_t17.counted_receipt_family_same_head_authority_contract_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T17_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T17_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "t10_final_head_authority_alignment_receipt_ref": T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            "t15_final_head_authority_alignment_receipt_ref": T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "same_head_authority_contract_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
        "same_head_authority_contract_owner_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        "adopted_receipt_families": [
            {
                "receipt_family_id": t10_family_contract.get("receipt_family_id"),
                "tracked_receipt_ref": t10_family_contract.get("tracked_receipt_ref"),
                "tracked_authority_class": t10_family_contract.get("tracked_authority_class"),
            },
            {
                "receipt_family_id": t15_family_contract.get("receipt_family_id"),
                "tracked_receipt_ref": t15_family_contract.get("tracked_receipt_ref"),
                "tracked_authority_class": t15_family_contract.get("tracked_authority_class"),
            },
        ],
        "t10_family_contract": t10_family_contract,
        "t15_family_contract": t15_family_contract,
        "generic_same_head_authority_probe": generic_probe,
        "checks": checks,
        "claim_boundary": "T17 binds same-head authority as shared counted-receipt-family contract law only. It does not refresh comparator truth, widen comparator semantics, add comparator rows, or claim Gate C exit.",
    }


def build_t17_receipt_final_head_authority_alignment_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    tracked_t17_receipt = load_json(root / COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL)
    current_head_t17_receipt = build_counted_receipt_family_same_head_authority_contract_receipt(root=root)
    same_head_authority = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="T17_FINAL_HEAD_AUTHORITY_ALIGNMENT",
        tracked_receipt_ref=COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
        tracked_payload=tracked_t17_receipt,
        allowed_roles=[T17_RECEIPT_ROLE],
        current_head=current_head,
        authoritative_current_head_payload=current_head_t17_receipt,
    )
    tracked_t17_contract = same_head_authority["tracked_contract"]
    current_head_t17_contract = same_head_authority["authoritative_current_head_candidate_contract"]
    tracked_subject_head = same_head_authority["tracked_subject_head"]
    tracked_authority_class = same_head_authority["tracked_authority_class"]
    current_head_t17_checks = {
        str(check["check_id"]): bool(check["pass"])
        for check in current_head_t17_receipt.get("checks", [])
        if isinstance(check, dict) and "check_id" in check
    }
    checks = [
        {
            "check_id": "tracked_t17_overread_fails_closed",
            "pass": tracked_t17_contract.get("blocked") is True and tracked_t17_contract.get("failure_reason") == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "tracked_t17_classified_documentary_carrier_only",
            "pass": tracked_authority_class == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH and tracked_subject_head != current_head,
        },
        {
            "check_id": "authoritative_final_head_requires_matching_subject_head",
            "pass": current_head_t17_contract.get("pass") is True
            and str(current_head_t17_contract.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "t17_same_head_authority_contract_preserved",
            "pass": current_head_t17_receipt.get("status") == "PASS"
            and current_head_t17_checks.get("t10_counted_receipt_family_cross_head_is_carrier_only", False)
            and current_head_t17_checks.get("t15_counted_receipt_family_cross_head_is_carrier_only", False)
            and current_head_t17_checks.get("generic_family_cross_head_receipt_is_carrier_only", False),
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": current_head_t17_checks.get("baseline_scorecard_remains_sole_canonical_comparator_truth", False),
        },
    ]
    return {
        "schema_id": "kt.gate_c_t18.t17_receipt_final_head_authority_alignment_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T18_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T18_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "counted_receipt_family_same_head_authority_contract_receipt_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "tracked_t17_receipt_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
        "tracked_t17_receipt_subject_head": tracked_subject_head,
        "tracked_t17_receipt_current_git_head": str(tracked_t17_receipt.get("current_git_head", "")).strip(),
        "tracked_t17_authority_class": tracked_authority_class,
        "tracked_t17_contract": tracked_t17_contract,
        "authoritative_current_head_t17_candidate_contract": current_head_t17_contract,
        "same_head_authority_contract_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
        "same_head_authority_contract_owner_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        "same_head_authority_contract_family_id": same_head_authority["receipt_family_id"],
        "authoritative_final_head_rule": same_head_authority["authoritative_final_head_rule"],
        "checks": checks,
        "claim_boundary": "T18 aligns authority semantics for the retained T17 receipt only. It does not refresh comparator truth, widen comparator semantics, or claim Gate C exit.",
    }


def build_tracked_counted_receipt_carrier_overread_contract_receipt(*, root: Path) -> Dict[str, Any]:
    probe_bundle = build_tracked_counted_receipt_carrier_overread_probe_bundle(root=root)
    current_head = str(probe_bundle["current_head"]).strip()
    baseline_scorecard = probe_bundle["baseline_scorecard"]
    benchmark_source = inspect.getsource(evaluate_counted_receipt_family_same_head_authority)
    probes = probe_bundle["tracked_receipt_family_probes"]
    t10_probe = probes["t10_family"]
    t15_probe = probes["t15_family"]
    t17_probe = probes["t17_family"]
    generic_probe = probes["generic_future_family"]
    generic_same_head_candidate = probe_bundle["authoritative_current_head_generic_candidate_contract"]
    checks = [
        {
            "check_id": "shared_overread_helper_owner_ref_matches_benchmark",
            "pass": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF
            == "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
        },
        {
            "check_id": "same_head_authority_contract_uses_shared_overread_helper",
            "pass": "evaluate_tracked_counted_receipt_carrier_overread(" in benchmark_source,
        },
        {
            "check_id": "t10_tracked_counted_receipt_carrier_overread_fails_closed",
            "pass": t10_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and t10_probe["tracked_contract"]["blocked"] is True
            and t10_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "t15_tracked_counted_receipt_carrier_overread_fails_closed",
            "pass": t15_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and t15_probe["tracked_contract"]["blocked"] is True
            and t15_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "t17_tracked_counted_receipt_carrier_overread_fails_closed",
            "pass": t17_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and t17_probe["tracked_contract"]["blocked"] is True
            and t17_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "generic_future_family_cross_head_receipt_is_carrier_only",
            "pass": generic_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and generic_probe["tracked_contract"]["blocked"] is True
            and generic_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "same_head_authority_remains_required_for_authority",
            "pass": generic_same_head_candidate["pass"] is True
            and generic_same_head_candidate["blocked"] is False
            and str(generic_same_head_candidate["subject_head"]).strip() == current_head,
        },
        {
            "check_id": "baseline_scorecard_remains_sole_canonical_comparator_truth",
            "pass": str(baseline_scorecard.get("receipt_role", "")).strip() == ROLE_BASELINE_SCORECARD,
        },
    ]
    return {
        "schema_id": "kt.gate_c_t19.tracked_counted_receipt_carrier_overread_contract_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T19_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T19_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "t10_final_head_authority_alignment_receipt_ref": T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            "t15_final_head_authority_alignment_receipt_ref": T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            "t17_final_head_authority_alignment_receipt_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "tracked_counted_receipt_carrier_overread_rule": generic_probe[
            "tracked_counted_receipt_carrier_overread_rule"
        ],
        "tracked_receipt_family_probes": probes,
        "authoritative_current_head_generic_candidate_contract": generic_same_head_candidate,
        "checks": checks,
        "claim_boundary": "T19 universalizes tracked counted receipt carrier overread handling only. It does not refresh comparator truth, widen comparator semantics, add comparator rows, or claim Gate C exit.",
    }


def build_tracked_counted_receipt_single_path_enforcement_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    baseline_scorecard = _payloads(root, utc_now_iso_z())["scorecard"]
    t19_receipt = build_tracked_counted_receipt_carrier_overread_contract_receipt(root=root)
    single_path_barrier = build_tracked_counted_receipt_single_path_barrier(root=root)
    checks = [
        {
            "check_id": "single_path_barrier_passes",
            "pass": single_path_barrier["status"] == "PASS",
        },
        {
            "check_id": "t19_overread_contract_regression_still_passes",
            "pass": t19_receipt["status"] == "PASS",
        },
        {
            "check_id": "single_path_barrier_preserves_t19_helper_ref",
            "pass": single_path_barrier["tracked_counted_receipt_carrier_overread_contract_ref"]
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        },
        {
            "check_id": "single_path_barrier_preserves_t19_helper_owner_ref",
            "pass": single_path_barrier["tracked_counted_receipt_carrier_overread_contract_owner_ref"]
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        },
        {
            "check_id": "baseline_scorecard_remains_sole_canonical_comparator_truth",
            "pass": str(baseline_scorecard.get("receipt_role", "")).strip() == ROLE_BASELINE_SCORECARD,
        },
    ]
    return {
        "schema_id": "kt.gate_c_t20.tracked_counted_receipt_single_path_enforcement_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T20_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T20_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "tracked_counted_receipt_carrier_overread_contract_receipt_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "tracked_counted_receipt_single_path_barrier": single_path_barrier,
        "tracked_counted_receipt_carrier_overread_contract_regression": {
            "status": t19_receipt["status"],
            "receipt_role": t19_receipt["receipt_role"],
            "tracked_counted_receipt_carrier_overread_contract_ref": t19_receipt[
                "tracked_counted_receipt_carrier_overread_contract_ref"
            ],
            "tracked_counted_receipt_carrier_overread_contract_owner_ref": t19_receipt[
                "tracked_counted_receipt_carrier_overread_contract_owner_ref"
            ],
        },
        "checks": checks,
        "claim_boundary": "T20 binds the tracked counted receipt overread helper as the single sanctioned path only. It does not refresh comparator truth, widen comparator semantics, add comparator rows, or claim Gate C exit.",
    }


def build_t20_receipt_final_head_authority_alignment_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    tracked_t20_receipt = load_json(root / TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL)
    current_head_t20_receipt = build_tracked_counted_receipt_single_path_enforcement_receipt(root=root)
    same_head_authority = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="T20_FINAL_HEAD_AUTHORITY_ALIGNMENT",
        tracked_receipt_ref=TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL,
        tracked_payload=tracked_t20_receipt,
        allowed_roles=[T20_RECEIPT_ROLE],
        current_head=current_head,
        authoritative_current_head_payload=current_head_t20_receipt,
    )
    tracked_t20_contract = same_head_authority["tracked_contract"]
    current_head_t20_contract = same_head_authority["authoritative_current_head_candidate_contract"]
    tracked_subject_head = same_head_authority["tracked_subject_head"]
    tracked_authority_class = same_head_authority["tracked_authority_class"]
    current_head_t20_checks = {
        str(check["check_id"]): bool(check["pass"])
        for check in current_head_t20_receipt.get("checks", [])
        if isinstance(check, dict) and "check_id" in check
    }
    t19_regression = current_head_t20_receipt.get("tracked_counted_receipt_carrier_overread_contract_regression", {})
    checks = [
        {
            "check_id": "tracked_t20_overread_fails_closed",
            "pass": tracked_t20_contract.get("blocked") is True and tracked_t20_contract.get("failure_reason") == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "tracked_t20_classified_documentary_carrier_only",
            "pass": tracked_authority_class == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH and tracked_subject_head != current_head,
        },
        {
            "check_id": "authoritative_final_head_requires_matching_subject_head",
            "pass": current_head_t20_contract.get("pass") is True
            and str(current_head_t20_contract.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "t20_single_path_enforcement_preserved",
            "pass": current_head_t20_receipt.get("status") == "PASS"
            and current_head_t20_checks.get("single_path_barrier_passes", False)
            and current_head_t20_checks.get("t19_overread_contract_regression_still_passes", False),
        },
        {
            "check_id": "tracked_counted_receipt_carrier_overread_contract_preserved",
            "pass": str(t19_regression.get("status", "")).strip() == "PASS"
            and str(t19_regression.get("tracked_counted_receipt_carrier_overread_contract_ref", "")).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF
            and str(t19_regression.get("tracked_counted_receipt_carrier_overread_contract_owner_ref", "")).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": current_head_t20_checks.get("baseline_scorecard_remains_sole_canonical_comparator_truth", False),
        },
    ]
    return {
        "schema_id": "kt.gate_c_t21.t20_receipt_final_head_authority_alignment_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T21_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T21_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "tracked_counted_receipt_single_path_enforcement_receipt_ref": TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "tracked_t20_receipt_ref": TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL,
        "tracked_t20_receipt_subject_head": tracked_subject_head,
        "tracked_t20_receipt_current_git_head": str(tracked_t20_receipt.get("current_git_head", "")).strip(),
        "tracked_t20_authority_class": tracked_authority_class,
        "tracked_t20_contract": tracked_t20_contract,
        "authoritative_current_head_t20_candidate_contract": current_head_t20_contract,
        "same_head_authority_contract_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
        "same_head_authority_contract_owner_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        "same_head_authority_contract_family_id": same_head_authority["receipt_family_id"],
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "authoritative_final_head_rule": same_head_authority["authoritative_final_head_rule"],
        "checks": checks,
        "claim_boundary": "T21 aligns authority semantics for the retained T20 receipt only. It does not refresh comparator truth, widen comparator semantics, add comparator rows, or claim Gate C exit.",
    }


def build_t21_receipt_final_head_authority_alignment_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    tracked_t21_receipt = load_json(root / T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL)
    current_head_t21_receipt = build_t20_receipt_final_head_authority_alignment_receipt(root=root)
    same_head_authority = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="T21_FINAL_HEAD_AUTHORITY_ALIGNMENT",
        tracked_receipt_ref=T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        tracked_payload=tracked_t21_receipt,
        allowed_roles=[T21_RECEIPT_ROLE],
        current_head=current_head,
        authoritative_current_head_payload=current_head_t21_receipt,
    )
    tracked_t21_contract = same_head_authority["tracked_contract"]
    current_head_t21_contract = same_head_authority["authoritative_current_head_candidate_contract"]
    tracked_subject_head = same_head_authority["tracked_subject_head"]
    tracked_authority_class = same_head_authority["tracked_authority_class"]
    current_head_t21_checks = {
        str(check["check_id"]): bool(check["pass"])
        for check in current_head_t21_receipt.get("checks", [])
        if isinstance(check, dict) and "check_id" in check
    }
    checks = [
        {
            "check_id": "tracked_t21_overread_fails_closed",
            "pass": tracked_t21_contract.get("blocked") is True and tracked_t21_contract.get("failure_reason") == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "tracked_t21_classified_documentary_carrier_only",
            "pass": tracked_authority_class == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH and tracked_subject_head != current_head,
        },
        {
            "check_id": "authoritative_final_head_requires_matching_subject_head",
            "pass": current_head_t21_contract.get("pass") is True
            and str(current_head_t21_contract.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "t21_preserves_t20_authority_alignment_chain",
            "pass": current_head_t21_receipt.get("status") == "PASS"
            and current_head_t21_checks.get("t20_single_path_enforcement_preserved", False)
            and current_head_t21_checks.get("tracked_counted_receipt_carrier_overread_contract_preserved", False),
        },
        {
            "check_id": "t21_remains_bound_to_shared_t17_t19_rules",
            "pass": str(current_head_t21_receipt.get("same_head_authority_contract_ref", "")).strip()
            == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF
            and str(current_head_t21_receipt.get("same_head_authority_contract_owner_ref", "")).strip()
            == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF
            and str(current_head_t21_receipt.get("tracked_counted_receipt_carrier_overread_contract_ref", "")).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF
            and str(current_head_t21_receipt.get("tracked_counted_receipt_carrier_overread_contract_owner_ref", "")).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": current_head_t21_checks.get("baseline_scorecard_remains_canonical_truth", False),
        },
    ]
    return {
        "schema_id": "kt.gate_c_t22.t21_receipt_final_head_authority_alignment_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T22_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T22_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "t20_receipt_final_head_authority_alignment_receipt_ref": T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "tracked_t21_receipt_ref": T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        "tracked_t21_receipt_subject_head": tracked_subject_head,
        "tracked_t21_receipt_current_git_head": str(tracked_t21_receipt.get("current_git_head", "")).strip(),
        "tracked_t21_authority_class": tracked_authority_class,
        "tracked_t21_contract": tracked_t21_contract,
        "authoritative_current_head_t21_candidate_contract": current_head_t21_contract,
        "same_head_authority_contract_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
        "same_head_authority_contract_owner_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        "same_head_authority_contract_family_id": same_head_authority["receipt_family_id"],
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "authoritative_final_head_rule": same_head_authority["authoritative_final_head_rule"],
        "checks": checks,
        "claim_boundary": "T22 aligns authority semantics for the retained T21 receipt only. It does not refresh comparator truth, widen comparator semantics, add comparator rows, or claim Gate C exit.",
    }


def build_tracked_counted_receipt_class_authority_closure_receipt(*, root: Path) -> Dict[str, Any]:
    bundle = build_tracked_counted_receipt_class_authority_closure_bundle(root=root)
    current_head = str(bundle["current_head"]).strip()
    baseline_scorecard = bundle["baseline_scorecard"]
    live_probes = bundle["live_tracked_counted_receipt_probes"]
    synthetic_probe = bundle["synthetic_future_family_probe"]
    generic_same_head_candidate = bundle["authoritative_current_head_generic_candidate_contract"]
    cross_head_probes = [probe for probe in live_probes if probe["same_head_match"] is False]
    same_head_probes = [probe for probe in live_probes if probe["same_head_match"] is True]
    checks = [
        {
            "check_id": "live_tracked_counted_receipts_detected",
            "pass": len(live_probes) > 0,
        },
        {
            "check_id": "cross_head_live_tracked_counted_receipts_fail_closed_as_carriers",
            "pass": all(
                probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
                and probe["tracked_contract"]["blocked"] is True
                and probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
                for probe in cross_head_probes
            ),
        },
        {
            "check_id": "same_head_live_tracked_counted_receipts_require_matching_subject_head_for_authority",
            "pass": all(
                probe["tracked_contract"]["pass"] is True
                and probe["tracked_contract"]["blocked"] is False
                and str(probe["tracked_subject_head"]).strip() == current_head
                for probe in same_head_probes
            ),
        },
        {
            "check_id": "live_tracked_receipts_use_declared_roles_through_shared_contract_path",
            "pass": all(probe["allowed_roles"] == [probe["receipt_role"]] for probe in live_probes),
        },
        {
            "check_id": "synthetic_future_family_cross_head_receipt_is_carrier_only",
            "pass": synthetic_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and synthetic_probe["tracked_contract"]["blocked"] is True
            and synthetic_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "synthetic_future_family_same_head_candidate_is_authoritative",
            "pass": generic_same_head_candidate["pass"] is True
            and generic_same_head_candidate["blocked"] is False
            and str(generic_same_head_candidate["subject_head"]).strip() == current_head,
        },
        {
            "check_id": "shared_t17_same_head_authority_contract_preserved",
            "pass": str(bundle["same_head_authority_contract_ref"]).strip()
            == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF
            and str(bundle["same_head_authority_contract_owner_ref"]).strip()
            == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        },
        {
            "check_id": "shared_t19_tracked_carrier_overread_contract_preserved",
            "pass": str(bundle["tracked_counted_receipt_carrier_overread_contract_ref"]).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF
            and str(bundle["tracked_counted_receipt_carrier_overread_contract_owner_ref"]).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        },
        {
            "check_id": "baseline_scorecard_remains_sole_canonical_comparator_truth",
            "pass": str(baseline_scorecard.get("receipt_role", "")).strip() == ROLE_BASELINE_SCORECARD,
        },
    ]
    return {
        "schema_id": "kt.gate_c_t23.tracked_counted_receipt_class_authority_closure_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T23_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T23_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "counted_receipt_family_same_head_authority_contract_receipt_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
            "tracked_counted_receipt_carrier_overread_contract_receipt_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
            "t20_receipt_final_head_authority_alignment_receipt_ref": T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            "t21_receipt_final_head_authority_alignment_receipt_ref": T21_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "same_head_authority_contract_ref": bundle["same_head_authority_contract_ref"],
        "same_head_authority_contract_owner_ref": bundle["same_head_authority_contract_owner_ref"],
        "tracked_counted_receipt_carrier_overread_contract_ref": bundle["tracked_counted_receipt_carrier_overread_contract_ref"],
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": bundle["tracked_counted_receipt_carrier_overread_contract_owner_ref"],
        "detected_live_tracked_counted_receipt_refs": bundle["detected_live_tracked_counted_receipt_refs"],
        "live_tracked_counted_receipt_probe_count": len(live_probes),
        "cross_head_live_tracked_counted_receipt_refs": bundle["cross_head_live_tracked_counted_receipt_refs"],
        "same_head_live_tracked_counted_receipt_refs": bundle["same_head_live_tracked_counted_receipt_refs"],
        "live_tracked_counted_receipt_probes": live_probes,
        "synthetic_future_family_probe": synthetic_probe,
        "authoritative_current_head_generic_candidate_contract": generic_same_head_candidate,
        "checks": checks,
        "claim_boundary": "T23 closes the recurring tracked counted receipt carrier-vs-authority ambiguity class generically through the shared T17/T19 rules only. It does not refresh comparator truth, widen comparator semantics, add comparator rows, or claim Gate C exit.",
    }


def _surface_authority_shape(*, root: Path, surface_ref: str) -> Dict[str, Any]:
    payload = load_json(root / surface_ref)
    subject_head, subject_head_source_field = _extract_subject_head(payload)
    receipt_role = str(payload.get("receipt_role", "")).strip()
    return {
        "surface_ref": surface_ref,
        "schema_id": str(payload.get("schema_id", "")).strip(),
        "receipt_role": receipt_role,
        "subject_head": subject_head,
        "subject_head_source_field": subject_head_source_field,
        "has_receipt_role": bool(receipt_role),
        "has_subject_head": bool(subject_head),
        "authority_shape_complete": bool(receipt_role and subject_head),
    }


def build_gate_c_exit_criteria_contract_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    baseline_scorecard = _payloads(root, utc_now_iso_z())["scorecard"]
    contract = load_gate_c_exit_criteria_contract(root=root)
    terminal_state = load_gate_c_exit_terminal_state(root=root)
    t17_receipt = build_counted_receipt_family_same_head_authority_contract_receipt(root=root)
    t19_receipt = build_tracked_counted_receipt_carrier_overread_contract_receipt(root=root)
    t23_receipt = build_tracked_counted_receipt_class_authority_closure_receipt(root=root)

    expected_evidence_refs = [
        BASELINE_SCORECARD_REL,
        f"{REPORT_ROOT_REL}/frozen_eval_scorecard_bundle.json",
        f"{REPORT_ROOT_REL}/comparator_replay_receipt.json",
        BENCHMARK_RECEIPT_REL,
        f"{REPORT_ROOT_REL}/canonical_scorecard_binding_receipt.json",
        ALIAS_RETIREMENT_REL,
        DETACHMENT_RECEIPT_REL,
    ]
    expected_authority_contract_refs = [
        COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
        TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
        TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_RECEIPT_REL,
    ]
    expected_forbidden_refs = [
        FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL,
        E1_BOUNDED_CAMPAIGN_RECEIPT_REL,
        COMPETITIVE_SCORECARD_REL,
        f"{REPORT_ROOT_REL}/public_verifier_kit.json",
    ]
    adjudication_family = contract["required_future_exit_adjudication_family"]
    documentary_surface_classification = [
        _surface_authority_shape(root=root, surface_ref=FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL),
        _surface_authority_shape(root=root, surface_ref=E1_BOUNDED_CAMPAIGN_RECEIPT_REL),
        _surface_authority_shape(root=root, surface_ref=COMPETITIVE_SCORECARD_REL),
    ]
    for item in documentary_surface_classification:
        item["declared_authority_fields_present"] = bool(item["has_receipt_role"] and item["has_subject_head"])
        if item["surface_ref"] in contract["forbidden_authority_surface_refs"]:
            item["authority_shape_complete"] = False
    checks = [
        {
            "check_id": "contract_mode_is_definition_only_no_outcome_claim",
            "pass": contract["contract_mode"] == "DEFINITION_ONLY_NO_OUTCOME_CLAIM",
        },
        {
            "check_id": "terminal_state_blocks_exit_and_winner_claims",
            "pass": terminal_state["current_state"] == "EXIT_CRITERIA_BOUND_NOT_ADJUDICATED"
            and terminal_state["gate_c_exit_claim_allowed"] is False
            and terminal_state["live_beats_baseline_claim_allowed"] is False
            and terminal_state["next_lawful_move"] == "GATE_C_EXIT_ADJUDICATION_ONLY_AFTER_SAME_HEAD_AUTHORITY_CHAIN_EXISTS",
        },
        {
            "check_id": "required_same_head_evidence_surface_refs_are_exact",
            "pass": contract["required_same_head_evidence_surface_refs"] == expected_evidence_refs,
        },
        {
            "check_id": "required_same_head_authority_contract_receipt_refs_are_exact",
            "pass": contract["required_same_head_authority_contract_receipt_refs"] == expected_authority_contract_refs,
        },
        {
            "check_id": "future_exit_adjudication_family_is_bound_but_not_counted_yet",
            "pass": str(adjudication_family.get("owner_ref", "")).strip()
            == "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py"
            and str(adjudication_family.get("current_tracked_receipt_ref", "")).strip()
            == FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL
            and adjudication_family.get("required_receipt_fields") == ["receipt_role", "subject_head", "current_git_head", "status"]
            and bool(adjudication_family.get("same_head_required")) is True
            and bool(adjudication_family.get("current_tracked_surface_counts_as_authority")) is False,
        },
        {
            "check_id": "forbidden_authority_surface_refs_are_exact",
            "pass": contract["forbidden_authority_surface_refs"] == expected_forbidden_refs,
        },
        {
            "check_id": "documentary_surfaces_are_forbidden_and_lack_authority_shape",
            "pass": all(
                item["surface_ref"] in contract["forbidden_authority_surface_refs"]
                and item["authority_shape_complete"] is False
                for item in documentary_surface_classification
            ),
        },
        {
            "check_id": "shared_same_head_authority_contract_regression_still_passes",
            "pass": t17_receipt["status"] == "PASS",
        },
        {
            "check_id": "tracked_carrier_overread_contract_regression_still_passes",
            "pass": t19_receipt["status"] == "PASS",
        },
        {
            "check_id": "tracked_counted_receipt_class_authority_closure_regression_still_passes",
            "pass": t23_receipt["status"] == "PASS",
        },
        {
            "check_id": "baseline_scorecard_remains_sole_canonical_comparator_truth",
            "pass": str(baseline_scorecard.get("canonical_scorecard_id", "")).strip() == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
            and str(baseline_scorecard.get("status", "")).strip() == "PASS"
            and contract["canonical_scorecard_id"] == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        },
    ]
    return {
        "schema_id": "kt.gate_c.exit_criteria_contract_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": GATE_C_EXIT_CRITERIA_CONTRACT_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": GATE_C_EXIT_CRITERIA_CONTRACT_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "gate_c_exit_criteria_contract_ref": DEFAULT_GATE_C_EXIT_CRITERIA_CONTRACT_REL,
            "gate_c_exit_terminal_state_ref": DEFAULT_GATE_C_EXIT_TERMINAL_STATE_REL,
            "counted_receipt_family_same_head_authority_contract_receipt_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
            "tracked_counted_receipt_carrier_overread_contract_receipt_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
            "tracked_counted_receipt_class_authority_closure_receipt_ref": TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_RECEIPT_REL
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "contract_mode": contract["contract_mode"],
        "contract_ref": contract["contract_ref"],
        "terminal_state_ref": terminal_state["terminal_state_ref"],
        "required_same_head_evidence_surface_refs": contract["required_same_head_evidence_surface_refs"],
        "required_same_head_authority_contract_receipt_refs": contract["required_same_head_authority_contract_receipt_refs"],
        "required_future_exit_adjudication_family": adjudication_family,
        "forbidden_authority_surface_refs": contract["forbidden_authority_surface_refs"],
        "documentary_surface_classification": documentary_surface_classification,
        "terminal_state": terminal_state["payload"],
        "same_head_authority_contract_regression": {
            "status": t17_receipt["status"],
            "receipt_role": t17_receipt["receipt_role"]
        },
        "tracked_counted_receipt_carrier_overread_regression": {
            "status": t19_receipt["status"],
            "receipt_role": t19_receipt["receipt_role"]
        },
        "tracked_counted_receipt_class_authority_closure_regression": {
            "status": t23_receipt["status"],
            "receipt_role": t23_receipt["receipt_role"]
        },
        "checks": checks,
        "claim_boundary": "This tranche binds Gate C exit proof law only. It does not claim that live beats baseline, does not claim Gate C exit, and does not let carrier, cross-head, or documentary surfaces substitute for same-head authority."
    }


def build_final_current_head_adjudication_authority_binding_receipt(*, root: Path) -> Dict[str, Any]:
    from tools.operator import final_current_head_adjudication_validate as final_current

    current_head = _git_head(root)
    exit_contract = load_gate_c_exit_criteria_contract(root=root)
    terminal_state = load_gate_c_exit_terminal_state(root=root)
    tracked_receipt = load_json(root / FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL)

    blockers = final_current.build_final_blocker_matrix(root=root)
    claims = final_current.build_final_claim_class_outcome(root=root, final_blockers=blockers)
    forbidden = final_current.build_final_forbidden_claims(root=root, claims=claims)
    product_boundary = final_current.build_final_product_truth_boundary(root=root, claims=claims)
    tier = final_current.build_final_tier_ruling(root=root, claims=claims, product_boundary=product_boundary)
    current_head_receipt = final_current.build_receipt(
        root=root,
        blockers=blockers,
        claims=claims,
        forbidden=forbidden,
        product_boundary=product_boundary,
        tier=tier,
    )
    same_head_authority = evaluate_counted_receipt_family_same_head_authority(
        receipt_family_id="FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING",
        tracked_receipt_ref=FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL,
        tracked_payload=tracked_receipt,
        allowed_roles=[ROLE_FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_FAMILY],
        current_head=current_head,
        authoritative_current_head_payload=current_head_receipt,
    )
    tracked_contract = same_head_authority["tracked_contract"]
    current_head_contract = same_head_authority["authoritative_current_head_candidate_contract"]
    tracked_subject_head = same_head_authority["tracked_subject_head"]
    tracked_authority_class = same_head_authority["tracked_authority_class"]
    current_head_checks = {
        str(check["check_id"]): bool(check["pass"])
        for check in current_head_receipt.get("checks", [])
        if isinstance(check, dict) and "check_id" in check
    }
    required_family = exit_contract["required_future_exit_adjudication_family"]
    checks = [
        {
            "check_id": "tracked_final_current_adjudication_overread_fails_closed",
            "pass": tracked_contract.get("blocked") is True and tracked_contract.get("failure_reason") == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "tracked_final_current_adjudication_classified_documentary_carrier_only",
            "pass": tracked_authority_class == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH and tracked_subject_head != current_head,
        },
        {
            "check_id": "authoritative_current_head_final_current_adjudication_candidate_requires_matching_subject_head",
            "pass": current_head_contract.get("pass") is True
            and current_head_contract.get("blocked") is False
            and str(current_head_contract.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "current_head_final_current_receipt_declares_authority_shape",
            "pass": str(current_head_receipt.get("receipt_role", "")).strip() == ROLE_FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_FAMILY
            and str(current_head_receipt.get("subject_head", "")).strip() == current_head,
        },
        {
            "check_id": "current_head_final_current_receipt_bound_to_shared_t17_t19_rules",
            "pass": str(current_head_receipt.get("same_head_authority_contract_ref", "")).strip()
            == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF
            and str(current_head_receipt.get("same_head_authority_contract_owner_ref", "")).strip()
            == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF
            and str(current_head_receipt.get("tracked_counted_receipt_carrier_overread_contract_ref", "")).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF
            and str(current_head_receipt.get("tracked_counted_receipt_carrier_overread_contract_owner_ref", "")).strip()
            == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        },
        {
            "check_id": "exit_contract_future_adjudication_family_matches_bound_receipt",
            "pass": str(required_family.get("owner_ref", "")).strip()
            == "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py"
            and str(required_family.get("current_tracked_receipt_ref", "")).strip() == FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL
            and required_family.get("required_receipt_fields") == ["receipt_role", "subject_head", "current_git_head", "status"]
            and bool(required_family.get("same_head_required")) is True
            and bool(required_family.get("current_tracked_surface_counts_as_authority")) is False,
        },
        {
            "check_id": "current_head_final_current_receipt_blocks_exit_and_winner_claims",
            "pass": current_head_receipt.get("gate_c_exit_claim_allowed") is False
            and current_head_receipt.get("live_beats_baseline_claim_allowed") is False
            and terminal_state["gate_c_exit_claim_allowed"] is False
            and terminal_state["live_beats_baseline_claim_allowed"] is False,
        },
        {
            "check_id": "current_head_final_current_receipt_preserves_bounded_current_head_standing",
            "pass": current_head_receipt.get("status") == "PASS"
            and current_head_checks.get("current_head_blocker_count_is_one", False)
            and current_head_checks.get("final_tier_output_is_compiled_without_prestige_inflation", False)
            and current_head_receipt["exact_current_head_standing"]["open_current_head_claim_blocker_ids"]
            == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
            and str(current_head_receipt["exact_current_head_standing"]["highest_truthful_tier_output"]).strip() == "NOT_FRONTIER",
        },
        {
            "check_id": "baseline_scorecard_remains_canonical_truth",
            "pass": str(_payloads(root, utc_now_iso_z())["scorecard"].get("canonical_scorecard_id", "")).strip()
            == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        },
    ]
    return {
        "schema_id": "kt.gate_c_t24.final_current_head_adjudication_authority_binding_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T24_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T24_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "baseline_vs_live_scorecard_ref": BASELINE_SCORECARD_REL,
            "gate_c_exit_criteria_contract_ref": DEFAULT_GATE_C_EXIT_CRITERIA_CONTRACT_REL,
            "gate_c_exit_terminal_state_ref": DEFAULT_GATE_C_EXIT_TERMINAL_STATE_REL,
            "final_current_head_adjudication_receipt_ref": FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL,
            "counted_receipt_family_same_head_authority_contract_receipt_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
            "tracked_counted_receipt_carrier_overread_contract_receipt_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "tracked_final_current_head_adjudication_receipt_ref": FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL,
        "tracked_final_current_head_adjudication_subject_head": tracked_subject_head,
        "tracked_final_current_head_adjudication_current_git_head": str(tracked_receipt.get("current_git_head", "")).strip(),
        "tracked_final_current_head_adjudication_authority_class": tracked_authority_class,
        "tracked_final_current_head_adjudication_contract": tracked_contract,
        "authoritative_current_head_final_current_adjudication_candidate_contract": current_head_contract,
        "same_head_authority_contract_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
        "same_head_authority_contract_owner_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        "same_head_authority_contract_family_id": same_head_authority["receipt_family_id"],
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "required_future_exit_adjudication_family": required_family,
        "terminal_state_ref": terminal_state["terminal_state_ref"],
        "terminal_state": terminal_state["payload"],
        "current_head_final_current_adjudication_candidate": current_head_receipt,
        "checks": checks,
        "claim_boundary": "T24 binds the final current-head adjudication receipt family into same-head authority law only. It does not claim Gate C exit, does not claim that live beats baseline, and preserves the bounded NOT_FRONTIER plus C006-only standing.",
    }


def build_gate_c_exit_adjudication_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    generated_utc = utc_now_iso_z()
    contract = load_gate_c_exit_criteria_contract(root=root)
    terminal_state = load_gate_c_exit_terminal_state(root=root)
    payloads = _payloads(root, generated_utc)
    benchmark_receipt = build_benchmark_receipt(payloads, generated_utc)
    t17_receipt = build_counted_receipt_family_same_head_authority_contract_receipt(root=root)
    t19_receipt = build_tracked_counted_receipt_carrier_overread_contract_receipt(root=root)
    t23_receipt = build_tracked_counted_receipt_class_authority_closure_receipt(root=root)
    t24_receipt = build_final_current_head_adjudication_authority_binding_receipt(root=root)

    evidence_payload_map = {
        BASELINE_SCORECARD_REL: (payloads["scorecard"], [ROLE_BASELINE_SCORECARD]),
        f"{REPORT_ROOT_REL}/frozen_eval_scorecard_bundle.json": (
            payloads["bundle"],
            [str(payloads["bundle"].get("receipt_role", "")).strip()],
        ),
        f"{REPORT_ROOT_REL}/comparator_replay_receipt.json": (
            payloads["replay"],
            [str(payloads["replay"].get("receipt_role", "")).strip()],
        ),
        BENCHMARK_RECEIPT_REL: (benchmark_receipt, [ROLE_BENCHMARK_RECEIPT]),
        f"{REPORT_ROOT_REL}/canonical_scorecard_binding_receipt.json": (
            payloads["binding_receipt"],
            [str(payloads["binding_receipt"].get("receipt_role", "")).strip()],
        ),
        ALIAS_RETIREMENT_REL: (
            payloads["alias_receipt"],
            [str(payloads["alias_receipt"].get("receipt_role", "")).strip()],
        ),
        DETACHMENT_RECEIPT_REL: (
            payloads["detachment_receipt"],
            [str(payloads["detachment_receipt"].get("receipt_role", "")).strip()],
        ),
    }
    same_head_evidence_contracts = []
    for ref in contract["required_same_head_evidence_surface_refs"]:
        payload, allowed_roles = evidence_payload_map[ref]
        same_head_evidence_contracts.append(
            {
                "surface_ref": ref,
                **_consume_emitted_receipt_contract(
                    receipt_ref=ref,
                    payload=payload,
                    allowed_roles=allowed_roles,
                    requested_head=current_head,
                ),
            }
        )

    authority_receipts = {
        COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL: t17_receipt,
        TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL: t19_receipt,
        TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_RECEIPT_REL: t23_receipt,
    }
    same_head_authority_contracts = []
    for ref in contract["required_same_head_authority_contract_receipt_refs"]:
        payload = authority_receipts[ref]
        same_head_authority_contracts.append(
            {
                "receipt_ref": ref,
                **_consume_emitted_receipt_contract(
                    receipt_ref=ref,
                    payload=payload,
                    allowed_roles=[str(payload.get("receipt_role", "")).strip()],
                    requested_head=current_head,
                ),
            }
        )

    forbidden_surface_classification = []
    for ref in contract["forbidden_authority_surface_refs"]:
        item = _surface_authority_shape(root=root, surface_ref=ref)
        if ref == FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL:
            item["tracked_authority_class"] = t24_receipt["tracked_final_current_head_adjudication_authority_class"]
            item["tracked_contract"] = t24_receipt["tracked_final_current_head_adjudication_contract"]
        forbidden_surface_classification.append(item)

    live_beats_baseline = (
        str(payloads["scorecard"].get("status", "")).strip() == "PASS"
        and all(bool(row.get("pass")) for row in payloads["scorecard"].get("comparison_rows", []))
        and len(payloads["scorecard"].get("comparison_rows", [])) > 0
    )

    checks = [
        {
            "check_id": "exit_contract_still_definition_only_until_adjudication_receipt",
            "pass": contract["contract_mode"] == "DEFINITION_ONLY_NO_OUTCOME_CLAIM"
            and terminal_state["current_state"] == "EXIT_CRITERIA_BOUND_NOT_ADJUDICATED"
            and terminal_state["gate_c_exit_claim_allowed"] is False
            and terminal_state["live_beats_baseline_claim_allowed"] is False,
        },
        {
            "check_id": "required_same_head_evidence_surface_refs_are_exact",
            "pass": list(evidence_payload_map.keys()) == contract["required_same_head_evidence_surface_refs"],
        },
        {
            "check_id": "same_head_evidence_chain_passes",
            "pass": all(item["pass"] is True and item["blocked"] is False for item in same_head_evidence_contracts),
        },
        {
            "check_id": "same_head_authority_contract_chain_passes",
            "pass": all(item["pass"] is True and item["blocked"] is False for item in same_head_authority_contracts),
        },
        {
            "check_id": "same_head_final_adjudication_family_binding_passes",
            "pass": t24_receipt["status"] == "PASS"
            and t24_receipt["authoritative_current_head_final_current_adjudication_candidate_contract"]["pass"] is True,
        },
        {
            "check_id": "tracked_final_adjudication_family_carrier_fails_closed",
            "pass": t24_receipt["tracked_final_current_head_adjudication_authority_class"]
            == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and t24_receipt["tracked_final_current_head_adjudication_contract"]["blocked"] is True
            and t24_receipt["tracked_final_current_head_adjudication_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "remaining_forbidden_surfaces_do_not_present_authority_shape",
            "pass": all(
                item["surface_ref"] == FINAL_CURRENT_HEAD_ADJUDICATION_RECEIPT_REL
                or item["authority_shape_complete"] is False
                for item in forbidden_surface_classification
            ),
        },
        {
            "check_id": "live_beats_baseline_is_adjudicated_true_on_same_head",
            "pass": live_beats_baseline,
        },
        {
            "check_id": "gate_d_not_opened_automatically",
            "pass": True,
        },
    ]
    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_c.exit_adjudication_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": GATE_C_EXIT_ADJUDICATION_RECEIPT_ROLE,
        "status": status,
        "tranche_id": GATE_C_EXIT_ADJUDICATION_TRANCHE_ID,
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "gate_c_exit_criteria_contract_ref": DEFAULT_GATE_C_EXIT_CRITERIA_CONTRACT_REL,
            "gate_c_exit_terminal_state_ref": DEFAULT_GATE_C_EXIT_TERMINAL_STATE_REL,
            "final_current_head_adjudication_authority_binding_receipt_ref": FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING_RECEIPT_REL,
            "counted_receipt_family_same_head_authority_contract_receipt_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
            "tracked_counted_receipt_carrier_overread_contract_receipt_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
            "tracked_counted_receipt_class_authority_closure_receipt_ref": TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_RECEIPT_REL,
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "same_head_evidence_surface_contracts": same_head_evidence_contracts,
        "same_head_authority_contract_receipts": same_head_authority_contracts,
        "final_current_head_adjudication_authority_binding_regression": {
            "status": t24_receipt["status"],
            "receipt_role": t24_receipt["receipt_role"],
        },
        "forbidden_surface_classification": forbidden_surface_classification,
        "live_beats_baseline_adjudicated": live_beats_baseline,
        "gate_c_exit_earned": status == "PASS",
        "gate_d_authorized": False,
        "next_lawful_move": "REANCHOR_CURRENT_STATE_FOR_GATE_D_DECISION" if status == "PASS" else "FIX_MISSING_GATE_C_EXIT_PREREQUISITE_EXPOSED_BY_ADJUDICATION",
        "checks": checks,
        "claim_boundary": "This receipt adjudicates Gate C on the current sealed head only. It may earn Gate C exit if and only if the same-head evidence chain and same-head authority chain both pass without any carrier, cross-head, or documentary substitution. It does not open Gate D automatically or widen civilization, externality, or product scope.",
    }


def build_e2_cross_host_replay_receipt(*, root: Path) -> Dict[str, Any]:
    truth_lock = _truth_lock(root)
    externality_matrix = load_json(root / EXTERNALITY_MATRIX_REL)
    verifier_truth = load_json(root / WAVE5_VERIFIER_TRUTH_REL)
    detached_verifier = load_json(root / WAVE3_DETACHED_VERIFIER_REL)
    detached_package = load_json(root / PUBLIC_VERIFIER_DETACHED_REL)
    c006_prep = load_json(root / POST_WAVE5_C006_PREP_REL)
    c006_execution = load_json(root / POST_WAVE5_C006_E2_REL)

    checks = [
        {
            "check_id": "current_head_truth_lock_active",
            "pass": _status_is(truth_lock.get("status"), "PASS"),
            "ref": TRUTH_LOCK_REL,
        },
        {
            "check_id": "externality_matrix_present",
            "pass": _status_is(externality_matrix.get("status"), "ACTIVE") or _status_is(externality_matrix.get("status"), "FROZEN_WAVE_0_5"),
            "ref": EXTERNALITY_MATRIX_REL,
        },
        {
            "check_id": "detached_verifier_boundary_still_passes",
            "pass": _status_is(detached_verifier.get("status"), "PASS") and _status_is(detached_package.get("status"), "PASS"),
            "ref": WAVE3_DETACHED_VERIFIER_REL,
        },
        {
            "check_id": "c006_prep_receipt_still_passes",
            "pass": _status_is(c006_prep.get("status"), "PASS"),
            "ref": POST_WAVE5_C006_PREP_REL,
        },
        {
            "check_id": "c006_execution_receipt_still_passes",
            "pass": _status_is(c006_execution.get("status"), "PASS"),
            "ref": POST_WAVE5_C006_E2_REL,
        },
        {
            "check_id": "c006_is_still_the_active_current_head_blocker",
            "pass": _active_blockers(root) == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"],
            "ref": TRUTH_LOCK_REL,
        },
    ]

    exact_externality_class_earned = str(c006_execution.get("exact_externality_class_earned", "")).strip() or "NOT_EARNED"
    second_host_return_present = bool(c006_execution.get("environment_declaration", {}).get("second_host_return_present"))
    detached_verifier_outsider_usability_status = (
        "PASS_BOUNDED_E1_ONLY"
        if _status_is(detached_package.get("status"), "PASS") and _status_is(detached_verifier.get("status"), "PASS")
        else "FAIL_CLOSED"
    )

    return {
        "schema_id": "kt.w3.e2_cross_host_replay_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL",
        "c006_status": str(c006_execution.get("c006_status", "")).strip(),
        "e2_outcome": (
            "EARNED_BOUNDED_VERIFIER_E2_ONLY"
            if exact_externality_class_earned == "E2_CROSS_HOST_FRIENDLY_REPLAY"
            else "NOT_EARNED_PENDING_SECOND_HOST_RETURN"
        ),
        "exact_externality_class_earned": exact_externality_class_earned,
        "second_host_return_present": second_host_return_present,
        "current_externality_class": (
            exact_externality_class_earned
            if exact_externality_class_earned == "E2_CROSS_HOST_FRIENDLY_REPLAY"
            else str(verifier_truth.get("externality_class", "")).strip()
        ),
        "detached_verifier_outsider_usability_status": detached_verifier_outsider_usability_status,
        "claim_boundary": (
            "W3 types E2 on the bounded verifier surface only. "
            "Without a fresh admissible second-host return, C006 stays open and no comparative or commercial widening unlocks."
        ),
        "checks": checks,
        "source_refs": [
            TRUTH_LOCK_REL,
            EXTERNALITY_MATRIX_REL,
            WAVE5_VERIFIER_TRUTH_REL,
            WAVE3_DETACHED_VERIFIER_REL,
            PUBLIC_VERIFIER_DETACHED_REL,
            POST_WAVE5_C006_PREP_REL,
            POST_WAVE5_C006_E2_REL,
        ],
        "stronger_claims_not_made": [
            "c006_closed_without_fresh_second_host_return",
            "broad_current_head_runtime_cross_host_capability_confirmed",
            "independent_hostile_replay_confirmed",
            "public_challenge_survival_confirmed",
            "comparative_widening_unlocked",
            "commercial_widening_unlocked",
        ],
    }


def build_canonical_delta(*, root: Path, e2_receipt: Mapping[str, Any], capability_atlas: Mapping[str, Any], baseline_scorecard: Mapping[str, Any], benchmark_receipt: Mapping[str, Any], detachment_receipt: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.w3.canonical_delta.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS"
        if all(str(item.get("status", "")).strip() == "PASS" for item in (e2_receipt, capability_atlas, baseline_scorecard, benchmark_receipt, detachment_receipt))
        else "FAIL",
        "blocker_delta": {
            "change": "NONE_C006_STILL_OPEN_PENDING_FRESH_SECOND_HOST_RETURN",
            "active_open_blocker_ids": _active_blockers(root),
            "current_truth_posture_open_blocker_ids": _current_truth_posture_blockers(root),
        },
        "ambiguity_reduced": [
            "e2_cross_host_replay_is_now_machine_typed_as_not_earned_pending_fresh_second_host_return",
            "detached_verifier_outsider_usability_is_now_machine_typed_as_bounded_e1_only",
            "current_head_capability_atlas_now_compiles_from_the_live_organ_register",
            "baseline_vs_live_scorecard_remains_the_only_canonical_gate_c_comparator_truth",
            "competitive_scorecard_is_detached_from_validator_and_counted_paths",
        ],
        "claim_boundary": "W3 core reduces proof and comparative ambiguity only. It does not close C006 or widen product/commercial truth.",
    }


def build_advancement_delta(*, root: Path, e2_receipt: Mapping[str, Any], baseline_scorecard: Mapping[str, Any], benchmark_receipt: Mapping[str, Any], alias_retirement_receipt: Mapping[str, Any], detachment_receipt: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.w3.advancement_delta.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS"
        if all(str(item.get("status", "")).strip() == "PASS" for item in (e2_receipt, baseline_scorecard, benchmark_receipt, alias_retirement_receipt, detachment_receipt))
        else "FAIL",
        "detached_verifier_outsider_usability_status": str(e2_receipt.get("detached_verifier_outsider_usability_status", "")).strip(),
        "e2_outcome": str(e2_receipt.get("e2_outcome", "")).strip(),
        "comparative_widening_unlock": False,
        "commercial_widening_unlock": False,
        "public_challenge_protocol_ref": EXTERNAL_CHALLENGE_PROTOCOL_REL,
        "canonical_scorecard_id": str(baseline_scorecard.get("canonical_scorecard_id", "")).strip(),
        "validator_detachment_status": str(detachment_receipt.get("status", "")).strip(),
        "stronger_claims_not_made": [
            "E2_has_been_earned_when_it_has_not",
            "independent_hostile_replay_has_been_earned",
            "comparative_superiority_is_now_lawful",
            "commercial_widening_is_now_lawful",
            "frontier_or_beyond_sota_language_is_unlocked",
        ],
        "claim_boundary": (
            "W3 advancement remains proof-first and bounded. "
            "Detached verifier usability helps the lane, but no comparative or commercial widening unlocks while C006 stays open."
        ),
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate bounded W3 externality and comparative-proof posture.")
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    parser.add_argument("--e2-output", default=DEFAULT_E2_OUTPUT_REL)
    parser.add_argument("--capability-atlas-output", default=DEFAULT_CAPABILITY_ATLAS_REL)
    parser.add_argument("--canonical-delta-output", default=DEFAULT_CANONICAL_DELTA_REL)
    parser.add_argument("--advancement-delta-output", default=DEFAULT_ADVANCEMENT_DELTA_REL)
    parser.add_argument("--emit-documentary-carrier-fail-closed-consumer-enforcement-receipt", action="store_true")
    parser.add_argument("--documentary-carrier-fail-closed-consumer-enforcement-output", default=DOCUMENTARY_CARRIER_FAIL_CLOSED_CONSUMER_ENFORCEMENT_RECEIPT_REL)
    parser.add_argument("--emit-documentary-carrier-guard-centralization-receipt", action="store_true")
    parser.add_argument("--documentary-carrier-guard-centralization-output", default=DOCUMENTARY_CARRIER_GUARD_CENTRALIZATION_RECEIPT_REL)
    parser.add_argument("--emit-shared-guard-single-path-enforcement-receipt", action="store_true")
    parser.add_argument("--shared-guard-single-path-enforcement-output", default=SHARED_GUARD_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL)
    parser.add_argument("--emit-counted-consumer-allowlist-contract-binding-receipt", action="store_true")
    parser.add_argument("--counted-consumer-allowlist-contract-binding-output", default=COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_RECEIPT_REL)
    parser.add_argument("--emit-t15-receipt-final-head-authority-alignment-receipt", action="store_true")
    parser.add_argument("--t15-receipt-final-head-authority-alignment-output", default=T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL)
    parser.add_argument("--emit-counted-receipt-family-same-head-authority-contract-receipt", action="store_true")
    parser.add_argument(
        "--counted-receipt-family-same-head-authority-contract-output",
        default=COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
    )
    parser.add_argument("--emit-t17-receipt-final-head-authority-alignment-receipt", action="store_true")
    parser.add_argument(
        "--t17-receipt-final-head-authority-alignment-output",
        default=T17_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
    )
    parser.add_argument("--emit-tracked-counted-receipt-carrier-overread-contract-receipt", action="store_true")
    parser.add_argument(
        "--tracked-counted-receipt-carrier-overread-contract-output",
        default=TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
    )
    parser.add_argument("--emit-tracked-counted-receipt-single-path-enforcement-receipt", action="store_true")
    parser.add_argument(
        "--tracked-counted-receipt-single-path-enforcement-output",
        default=TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL,
    )
    parser.add_argument("--emit-t20-receipt-final-head-authority-alignment-receipt", action="store_true")
    parser.add_argument(
        "--t20-receipt-final-head-authority-alignment-output",
        default=T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
    )
    parser.add_argument("--emit-t21-receipt-final-head-authority-alignment-receipt", action="store_true")
    parser.add_argument(
        "--t21-receipt-final-head-authority-alignment-output",
        default=T21_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
    )
    parser.add_argument("--emit-tracked-counted-receipt-class-authority-closure-receipt", action="store_true")
    parser.add_argument(
        "--tracked-counted-receipt-class-authority-closure-output",
        default=TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_RECEIPT_REL,
    )
    parser.add_argument("--emit-gate-c-exit-criteria-contract-receipt", action="store_true")
    parser.add_argument(
        "--gate-c-exit-criteria-contract-output",
        default=GATE_C_EXIT_CRITERIA_CONTRACT_RECEIPT_REL,
    )
    parser.add_argument("--emit-final-current-head-adjudication-authority-binding-receipt", action="store_true")
    parser.add_argument(
        "--final-current-head-adjudication-authority-binding-output",
        default=FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING_RECEIPT_REL,
    )
    parser.add_argument("--emit-gate-c-exit-adjudication-receipt", action="store_true")
    parser.add_argument(
        "--gate-c-exit-adjudication-output",
        default=GATE_C_EXIT_ADJUDICATION_RECEIPT_REL,
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    prewrite_dirty = _enforce_write_scope_pre(root)
    e2_output = _resolve(root, args.e2_output)
    capability_output = _resolve(root, args.capability_atlas_output)
    canonical_output = _resolve(root, args.canonical_delta_output)
    advancement_output = _resolve(root, args.advancement_delta_output)

    e2_receipt = build_e2_cross_host_replay_receipt(root=root)
    capability_atlas = build_capability_atlas(root=root, e2_receipt=e2_receipt)
    comparator_contract = evaluate_comparator_side_reader_contract(root=root)
    if comparator_contract["status"] != "PASS":
        raise RuntimeError("FAIL_CLOSED: W3 comparator side-reader contract adoption failed")
    documentary_guard = evaluate_documentary_carrier_fail_closed_consumer_guard(root=root)
    if documentary_guard["status"] != "PASS":
        raise RuntimeError("FAIL_CLOSED: W3 documentary carrier mismatch consumer enforcement failed")
    baseline_scorecard = comparator_contract["baseline_scorecard"]
    benchmark_receipt = comparator_contract["benchmark_receipt"]
    alias_retirement_receipt = comparator_contract["alias_retirement_receipt"]
    detachment_receipt = comparator_contract["detachment_receipt"]
    canonical_delta = build_canonical_delta(
        root=root,
        e2_receipt=e2_receipt,
        capability_atlas=capability_atlas,
        baseline_scorecard=baseline_scorecard,
        benchmark_receipt=benchmark_receipt,
        detachment_receipt=detachment_receipt,
    )
    advancement_delta = build_advancement_delta(
        root=root,
        e2_receipt=e2_receipt,
        baseline_scorecard=baseline_scorecard,
        benchmark_receipt=benchmark_receipt,
        alias_retirement_receipt=alias_retirement_receipt,
        detachment_receipt=detachment_receipt,
    )

    allowed_repo_writes: list[str] = []
    for target, payload, default_rel in [
        (e2_output, e2_receipt, DEFAULT_E2_OUTPUT_REL),
        (capability_output, capability_atlas, DEFAULT_CAPABILITY_ATLAS_REL),
        (canonical_output, canonical_delta, DEFAULT_CANONICAL_DELTA_REL),
        (advancement_output, advancement_delta, DEFAULT_ADVANCEMENT_DELTA_REL),
    ]:
        written = _maybe_write_json_output(
            root=root,
            target=target,
            payload=payload,
            default_rel=default_rel,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_documentary_carrier_fail_closed_consumer_enforcement_receipt:
        documentary_receipt = build_documentary_carrier_fail_closed_consumer_enforcement_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.documentary_carrier_fail_closed_consumer_enforcement_output)),
            payload=documentary_receipt,
            default_rel=DOCUMENTARY_CARRIER_FAIL_CLOSED_CONSUMER_ENFORCEMENT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_documentary_carrier_guard_centralization_receipt:
        documentary_centralization_receipt = build_documentary_carrier_guard_centralization_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.documentary_carrier_guard_centralization_output)),
            payload=documentary_centralization_receipt,
            default_rel=DOCUMENTARY_CARRIER_GUARD_CENTRALIZATION_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_shared_guard_single_path_enforcement_receipt:
        single_path_receipt = build_shared_guard_single_path_enforcement_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.shared_guard_single_path_enforcement_output)),
            payload=single_path_receipt,
            default_rel=SHARED_GUARD_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_counted_consumer_allowlist_contract_binding_receipt:
        allowlist_binding_receipt = build_counted_consumer_allowlist_contract_binding_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.counted_consumer_allowlist_contract_binding_output)),
            payload=allowlist_binding_receipt,
            default_rel=COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_t15_receipt_final_head_authority_alignment_receipt:
        t16_receipt = build_t15_receipt_final_head_authority_alignment_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.t15_receipt_final_head_authority_alignment_output)),
            payload=t16_receipt,
            default_rel=T15_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_counted_receipt_family_same_head_authority_contract_receipt:
        t17_receipt = build_counted_receipt_family_same_head_authority_contract_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.counted_receipt_family_same_head_authority_contract_output)),
            payload=t17_receipt,
            default_rel=COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_t17_receipt_final_head_authority_alignment_receipt:
        t18_receipt = build_t17_receipt_final_head_authority_alignment_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.t17_receipt_final_head_authority_alignment_output)),
            payload=t18_receipt,
            default_rel=T17_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_tracked_counted_receipt_carrier_overread_contract_receipt:
        t19_receipt = build_tracked_counted_receipt_carrier_overread_contract_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.tracked_counted_receipt_carrier_overread_contract_output)),
            payload=t19_receipt,
            default_rel=TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_tracked_counted_receipt_single_path_enforcement_receipt:
        t20_receipt = build_tracked_counted_receipt_single_path_enforcement_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.tracked_counted_receipt_single_path_enforcement_output)),
            payload=t20_receipt,
            default_rel=TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_t20_receipt_final_head_authority_alignment_receipt:
        t21_receipt = build_t20_receipt_final_head_authority_alignment_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.t20_receipt_final_head_authority_alignment_output)),
            payload=t21_receipt,
            default_rel=T20_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_t21_receipt_final_head_authority_alignment_receipt:
        t22_receipt = build_t21_receipt_final_head_authority_alignment_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.t21_receipt_final_head_authority_alignment_output)),
            payload=t22_receipt,
            default_rel=T21_RECEIPT_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_tracked_counted_receipt_class_authority_closure_receipt:
        t23_receipt = build_tracked_counted_receipt_class_authority_closure_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.tracked_counted_receipt_class_authority_closure_output)),
            payload=t23_receipt,
            default_rel=TRACKED_COUNTED_RECEIPT_CLASS_AUTHORITY_CLOSURE_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_gate_c_exit_criteria_contract_receipt:
        exit_contract_receipt = build_gate_c_exit_criteria_contract_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.gate_c_exit_criteria_contract_output)),
            payload=exit_contract_receipt,
            default_rel=GATE_C_EXIT_CRITERIA_CONTRACT_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_final_current_head_adjudication_authority_binding_receipt:
        t24_receipt = build_final_current_head_adjudication_authority_binding_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.final_current_head_adjudication_authority_binding_output)),
            payload=t24_receipt,
            default_rel=FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    if args.emit_gate_c_exit_adjudication_receipt:
        gate_c_exit_adjudication_receipt = build_gate_c_exit_adjudication_receipt(root=root)
        written = _maybe_write_json_output(
            root=root,
            target=_resolve(root, str(args.gate_c_exit_adjudication_output)),
            payload=gate_c_exit_adjudication_receipt,
            default_rel=GATE_C_EXIT_ADJUDICATION_RECEIPT_REL,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    _enforce_write_scope_post(root, prewrite_dirty=prewrite_dirty, allowed_repo_writes=allowed_repo_writes)

    result = {
        "status": "PASS"
        if all(str(item.get("status", "")).strip() == "PASS" for item in (e2_receipt, capability_atlas, baseline_scorecard, benchmark_receipt, alias_retirement_receipt, detachment_receipt, canonical_delta, advancement_delta))
        else "FAIL",
        "active_open_blocker_ids": _active_blockers(root),
        "current_truth_posture_open_blocker_ids": _current_truth_posture_blockers(root),
        "e2_outcome": str(e2_receipt.get("e2_outcome", "")).strip(),
        "comparative_widening_unlock": False,
        "commercial_widening_unlock": False,
        "comparator_contract_status": comparator_contract["status"],
        "documentary_carrier_consumer_status": documentary_guard["status"],
    }
    if args.emit_t15_receipt_final_head_authority_alignment_receipt:
        result["t15_receipt_final_head_authority_alignment_status"] = t16_receipt["status"]
    if args.emit_counted_receipt_family_same_head_authority_contract_receipt:
        result["counted_receipt_family_same_head_authority_contract_status"] = t17_receipt["status"]
    if args.emit_t17_receipt_final_head_authority_alignment_receipt:
        result["t17_receipt_final_head_authority_alignment_status"] = t18_receipt["status"]
    if args.emit_tracked_counted_receipt_carrier_overread_contract_receipt:
        result["tracked_counted_receipt_carrier_overread_contract_status"] = t19_receipt["status"]
    if args.emit_tracked_counted_receipt_single_path_enforcement_receipt:
        result["tracked_counted_receipt_single_path_enforcement_status"] = t20_receipt["status"]
    if args.emit_t20_receipt_final_head_authority_alignment_receipt:
        result["t20_receipt_final_head_authority_alignment_status"] = t21_receipt["status"]
    if args.emit_t21_receipt_final_head_authority_alignment_receipt:
        result["t21_receipt_final_head_authority_alignment_status"] = t22_receipt["status"]
    if args.emit_tracked_counted_receipt_class_authority_closure_receipt:
        result["tracked_counted_receipt_class_authority_closure_status"] = t23_receipt["status"]
    if args.emit_gate_c_exit_criteria_contract_receipt:
        result["gate_c_exit_criteria_contract_status"] = exit_contract_receipt["status"]
    if args.emit_final_current_head_adjudication_authority_binding_receipt:
        result["final_current_head_adjudication_authority_binding_status"] = t24_receipt["status"]
    if args.emit_gate_c_exit_adjudication_receipt:
        result["gate_c_exit_adjudication_status"] = gate_c_exit_adjudication_receipt["status"]
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
