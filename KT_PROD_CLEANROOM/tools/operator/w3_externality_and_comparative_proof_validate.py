from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from tools.operator.benchmark_constitution_validate import _enforce_write_scope_post, _enforce_write_scope_pre, _maybe_write_json_output
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
    baseline_scorecard = load_json(root / BASELINE_SCORECARD_REL)
    benchmark_receipt = load_json(root / BENCHMARK_RECEIPT_REL)
    alias_retirement_receipt = load_json(root / ALIAS_RETIREMENT_REL)
    detachment_receipt = load_json(root / DETACHMENT_RECEIPT_REL)
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
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
