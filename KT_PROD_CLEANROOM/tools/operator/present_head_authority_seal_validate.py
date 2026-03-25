from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.omega_gate import (
    DEFAULT_ADVANCEMENT_DELTA_REL,
    DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
    DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL,
    DEFAULT_CANONICAL_DELTA_REL,
    DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
    DEFAULT_LOCK_REL,
    DEFAULT_OMEGA_GATE_RECEIPT_REL,
    DEFAULT_REPORT_AUTHORITY_INDEX_REL,
    DEFAULT_TOOLS_BOUNDARY_RULE_REL,
    DOCUMENTARY_POINTER_REL,
    build_advancement_delta_w0,
    build_authority_resolution_index,
    build_authority_supersession_map,
    build_canonical_delta_w0,
    build_current_head_truth_lock,
    build_historical_claim_firewall,
    build_omega_gate_receipt,
    build_report_authority_index,
    build_tools_runtime_boundary_rule,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import active_truth_source_ref, compatibility_surface_is_non_authoritative, load_json_ref, payload_documentary_only


DEFAULT_PRESENT_HEAD_AUTHORITY_SEAL_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/present_head_authority_seal_receipt.json"
DEFAULT_HISTORICAL_CLAIM_FIREWALL_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/historical_claim_firewall_receipt.json"
DEFAULT_AUTHORITY_RESOLUTION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/authority_resolution_receipt.json"


def _resolve(root: Path, rel: str) -> Path:
    return (root / rel).resolve()


def _write(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable(_resolve(root, rel), payload)


def _documentary_only(payload: Dict[str, Any]) -> bool:
    return payload_documentary_only(payload)


def _head_from_payload(payload: Dict[str, Any]) -> str:
    for key in ("validated_head_sha", "pinned_head_sha", "truth_subject_commit", "truth_produced_at_commit"):
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def build_authority_resolution_receipt(*, root: Path, authority_resolution_index: Dict[str, Any]) -> Dict[str, Any]:
    active_source_ref = active_truth_source_ref(root=root)
    active_source_payload = load_json_ref(root=root, ref=active_source_ref)
    documentary_payload = load_json(root / DOCUMENTARY_POINTER_REL)
    documentary_pointer_non_authoritative = compatibility_surface_is_non_authoritative(
        ref=DOCUMENTARY_POINTER_REL,
        active_source_ref=active_source_ref,
        payload=documentary_payload,
        documentary_refs=[DOCUMENTARY_POINTER_REL],
    )
    failures = list(authority_resolution_index.get("failures", [])) if isinstance(authority_resolution_index.get("failures"), list) else []
    checks = [
        {
            "check": "authority_resolution_index_passes",
            "status": authority_resolution_index.get("status", ""),
        },
        {
            "check": "active_truth_source_not_documentary_only",
            "status": "PASS" if not _documentary_only(active_source_payload) else "FAIL",
            "ref": active_source_ref,
        },
        {
            "check": "documentary_compatibility_pointer_is_documentary_only",
            "status": "PASS" if documentary_pointer_non_authoritative else "FAIL",
            "ref": DOCUMENTARY_POINTER_REL,
        },
        {
            "check": "active_current_head_scope_ref_declared",
            "status": "PASS" if str(authority_resolution_index.get("active_current_head_scope", {}).get("ref", "")).strip() == DEFAULT_LOCK_REL else "FAIL",
            "ref": DEFAULT_LOCK_REL,
        },
    ]
    failures.extend([row["check"] for row in checks if row["status"] != "PASS"])
    return {
        "schema_id": "kt.operator.authority_resolution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "current_repo_head": authority_resolution_index.get("current_repo_head", ""),
        "authority_resolution_index_ref": DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
        "active_truth_source_ref": active_source_ref,
        "active_truth_subject_commit": _head_from_payload(active_source_payload),
        "documentary_compatibility_pointer_ref": DOCUMENTARY_POINTER_REL,
        "documentary_compatibility_pointer_documentary_only": documentary_pointer_non_authoritative,
        "checks": checks,
        "failures": failures,
    }


def build_historical_claim_firewall_receipt(*, root: Path, historical_claim_firewall: Dict[str, Any]) -> Dict[str, Any]:
    archive_refs = historical_claim_firewall.get("archive_only_refs", [])
    current_head_refs = historical_claim_firewall.get("active_current_head_refs", [])
    checks = [
        {
            "check": "historical_claim_firewall_active",
            "status": "PASS" if str(historical_claim_firewall.get("status", "")).strip() == "ACTIVE" else "FAIL",
            "ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        },
        {
            "check": "archive_only_refs_present",
            "status": "PASS" if isinstance(archive_refs, list) and all(_resolve(root, str(ref)).exists() for ref in archive_refs) else "FAIL",
        },
        {
            "check": "blocked_current_head_uplifts_declared",
            "status": "PASS" if isinstance(historical_claim_firewall.get("blocked_current_head_uplifts"), list) and len(historical_claim_firewall["blocked_current_head_uplifts"]) >= 5 else "FAIL",
        },
        {
            "check": "active_current_head_refs_present",
            "status": "PASS" if isinstance(current_head_refs, list) and all(_resolve(root, str(ref)).exists() for ref in current_head_refs) else "FAIL",
        },
    ]
    failures = [row["check"] for row in checks if row["status"] != "PASS"]
    return {
        "schema_id": "kt.operator.historical_claim_firewall_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "current_repo_head": historical_claim_firewall.get("current_repo_head", ""),
        "historical_claim_firewall_ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        "checks": checks,
        "failures": failures,
    }


def build_present_head_authority_seal_receipt(
    *,
    root: Path,
    current_head_truth_lock: Dict[str, Any],
    authority_resolution_receipt: Dict[str, Any],
    historical_claim_firewall_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    sealed_scope = current_head_truth_lock.get("sealed_scope", {})
    checks = [
        {
            "check": "current_head_truth_lock_passes",
            "status": current_head_truth_lock.get("status", ""),
            "ref": DEFAULT_LOCK_REL,
        },
        {
            "check": "authority_resolution_receipt_passes",
            "status": authority_resolution_receipt.get("status", ""),
            "ref": DEFAULT_AUTHORITY_RESOLUTION_RECEIPT_REL,
        },
        {
            "check": "historical_claim_firewall_receipt_passes",
            "status": historical_claim_firewall_receipt.get("status", ""),
            "ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_RECEIPT_REL,
        },
        {
            "check": "worktree_scope_is_sealed",
            "status": "PASS"
            if str(sealed_scope.get("scope_class", "")).strip() == "CURRENT_HEAD_WORKTREE_SCOPE_ONLY"
            and bool(str(sealed_scope.get("scope_digest", "")).strip())
            and isinstance(sealed_scope.get("scope_refs"), list)
            and len(sealed_scope["scope_refs"]) > 0
            else "FAIL",
        },
        {
            "check": "documentary_pointer_is_not_active_authority",
            "status": "PASS" if authority_resolution_receipt.get("documentary_compatibility_pointer_documentary_only") is True else "FAIL",
            "ref": DOCUMENTARY_POINTER_REL,
        },
    ]
    failures = [row["check"] for row in checks if row["status"] != "PASS"]
    return {
        "schema_id": "kt.operator.present_head_authority_seal_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "current_repo_head": current_head_truth_lock.get("current_repo_head", ""),
        "authority_resolution_index_ref": DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
        "historical_claim_firewall_ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        "checks": checks,
        "failures": failures,
        "claim_boundary": "Present-head authority seal makes current-head scope authority explicit and blocks documentary or historical uplift. It does not claim clean release, E2+, or public-release admissibility.",
        "forbidden_claims_not_made": [
            "current_head_is_transparency_verified_subject_commit",
            "historical_bounded_frontier_packets_upgrade_current_head",
            "E2_or_higher_externality_is_earned",
            "press_ready_or_enterprise_readiness_is_proven",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate and materialize W0 present-head authority seal surfaces.")
    parser.add_argument("--authority-resolution-output", default=DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL)
    parser.add_argument("--historical-firewall-output", default=DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL)
    parser.add_argument("--tools-boundary-output", default=DEFAULT_TOOLS_BOUNDARY_RULE_REL)
    parser.add_argument("--lock-output", default=DEFAULT_LOCK_REL)
    parser.add_argument("--authority-index-output", default=DEFAULT_REPORT_AUTHORITY_INDEX_REL)
    parser.add_argument("--supersession-output", default=DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL)
    parser.add_argument("--canonical-delta-output", default=DEFAULT_CANONICAL_DELTA_REL)
    parser.add_argument("--advancement-delta-output", default=DEFAULT_ADVANCEMENT_DELTA_REL)
    parser.add_argument("--gate-output", default=DEFAULT_OMEGA_GATE_RECEIPT_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_PRESENT_HEAD_AUTHORITY_SEAL_RECEIPT_REL)
    parser.add_argument("--firewall-receipt-output", default=DEFAULT_HISTORICAL_CLAIM_FIREWALL_RECEIPT_REL)
    parser.add_argument("--resolution-receipt-output", default=DEFAULT_AUTHORITY_RESOLUTION_RECEIPT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()

    current_head_truth_lock = build_current_head_truth_lock(root=root)
    authority_resolution_index = build_authority_resolution_index(root=root, truth_lock=current_head_truth_lock)
    historical_claim_firewall = build_historical_claim_firewall(root=root)
    tools_boundary = build_tools_runtime_boundary_rule(root=root)
    report_authority_index = build_report_authority_index(root=root)
    supersession_map = build_authority_supersession_map(root=root)
    canonical_delta = build_canonical_delta_w0(root=root)
    advancement_delta = build_advancement_delta_w0(root=root)
    omega_gate_receipt = build_omega_gate_receipt(root=root)

    _write(root, str(args.lock_output), current_head_truth_lock)
    _write(root, str(args.authority_resolution_output), authority_resolution_index)
    _write(root, str(args.historical_firewall_output), historical_claim_firewall)
    _write(root, str(args.tools_boundary_output), tools_boundary)
    _write(root, str(args.authority_index_output), report_authority_index)
    _write(root, str(args.supersession_output), supersession_map)
    _write(root, str(args.canonical_delta_output), canonical_delta)
    _write(root, str(args.advancement_delta_output), advancement_delta)
    _write(root, str(args.gate_output), omega_gate_receipt)

    authority_resolution_receipt = build_authority_resolution_receipt(root=root, authority_resolution_index=authority_resolution_index)
    historical_claim_firewall_receipt = build_historical_claim_firewall_receipt(root=root, historical_claim_firewall=historical_claim_firewall)
    present_head_authority_seal_receipt = build_present_head_authority_seal_receipt(
        root=root,
        current_head_truth_lock=current_head_truth_lock,
        authority_resolution_receipt=authority_resolution_receipt,
        historical_claim_firewall_receipt=historical_claim_firewall_receipt,
    )

    _write(root, str(args.resolution_receipt_output), authority_resolution_receipt)
    _write(root, str(args.firewall_receipt_output), historical_claim_firewall_receipt)
    _write(root, str(args.receipt_output), present_head_authority_seal_receipt)

    summary = {
        "status": present_head_authority_seal_receipt["status"],
        "active_current_head_scope_ref": DEFAULT_LOCK_REL,
        "active_truth_source_ref": authority_resolution_receipt["active_truth_source_ref"],
        "documentary_pointer_documentary_only": authority_resolution_receipt["documentary_compatibility_pointer_documentary_only"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if present_head_authority_seal_receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
