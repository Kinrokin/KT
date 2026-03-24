from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.authority_convergence_validate import build_authority_convergence_report
from tools.operator.constitution_self_check import self_check
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
from tools.operator.present_head_authority_seal_validate import (
    DEFAULT_AUTHORITY_RESOLUTION_RECEIPT_REL,
    DEFAULT_HISTORICAL_CLAIM_FIREWALL_RECEIPT_REL,
    DEFAULT_PRESENT_HEAD_AUTHORITY_SEAL_RECEIPT_REL,
    build_authority_resolution_receipt,
    build_historical_claim_firewall_receipt,
    build_present_head_authority_seal_receipt,
)
from tools.operator.repo_hygiene_validate import (
    CLEAN_STATE_RECEIPT_REL as REPO_HYGIENE_CLEAN_STATE_RECEIPT_REL,
    HYGIENE_RECEIPT_REL as REPO_HYGIENE_RECEIPT_REL,
    INVENTORY_REL as REPO_HYGIENE_INVENTORY_REL,
    build_ws13_outputs,
)
from tools.operator.reporting_integrity import verify_reporting_integrity
from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


GOVERNANCE_AUTHORITY_SUPERSESSION_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/authority_supersession_registry.json"
DEFAULT_CLEAN_CURRENT_HEAD_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/clean_current_head_receipt.json"
DEFAULT_TRUTH_LOCK_FRESHNESS_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/truth_lock_freshness_receipt.json"
DEFAULT_AUTHORITY_CONVERGENCE_PASS_CURRENT_HEAD_REL = "KT_PROD_CLEANROOM/reports/authority_convergence_pass_current_head.json"
DEFAULT_BUNDLE_SELF_VALIDATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/bundle_self_validation_receipt.json"
DEFAULT_EXECUTIONIZATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_omega_v10_executionization_receipt.json"
DEFAULT_GATE_A_CAMPAIGN_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/v11_gate_a_campaign_receipt.json"

COMPARATOR_ALIAS_REL = "KT_PROD_CLEANROOM/reports/comparator_eval_scorecard.json"
BASELINE_CANONICAL_REL = "KT_PROD_CLEANROOM/reports/baseline_vs_live_scorecard.json"


def _resolve(root: Path, rel: str) -> Path:
    return (root / rel).resolve()


def _write(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable(_resolve(root, rel), payload)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_status_for_path(root: Path, rel: str) -> str:
    rel_posix = Path(rel).as_posix()
    output = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--", rel_posix],
        text=True,
        encoding="utf-8",
    )
    lines = [line for line in output.splitlines() if line.strip()]
    if lines:
        code = lines[0][:2]
        return "UNTRACKED_WORKTREE" if code == "??" else "TRACKED_DIRTY"
    try:
        subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "--error-unmatch", rel_posix],
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        return "TRACKED_CLEAN"
    except subprocess.CalledProcessError:
        return "IGNORED_OR_ABSENT"


def build_authority_supersession_registry(*, root: Path) -> Dict[str, Any]:
    supersession_map = build_authority_supersession_map(root=root)
    return {
        "schema_id": "kt.governance.authority_supersession_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": supersession_map["status"],
        "law": supersession_map["law"],
        "action_priority": list(supersession_map.get("action_priority", [])),
        "rows": list(supersession_map.get("rows", [])),
        "report_mirror_ref": DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL,
        "claim_boundary": "Governance mirror of the active authority supersession plan. It does not independently upgrade claims.",
    }


def build_truth_lock_freshness_receipt(*, root: Path, expected_lock: Dict[str, Any], lock_rel: str = DEFAULT_LOCK_REL) -> Dict[str, Any]:
    lock_path = _resolve(root, lock_rel)
    lock_exists = lock_path.exists()
    on_disk = load_json(lock_path) if lock_exists else {}
    semantically_fresh = lock_exists and semantically_equal_json(on_disk, expected_lock)
    return {
        "schema_id": "kt.operator.truth_lock_freshness_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if semantically_fresh else "FAIL_CLOSED",
        "current_repo_head": expected_lock.get("current_repo_head", ""),
        "lock_ref": lock_rel,
        "lock_exists": lock_exists,
        "semantically_fresh": semantically_fresh,
        "expected_lock_status": expected_lock.get("status", ""),
        "claim_boundary": "Freshness only proves the on-disk truth lock matches the currently compiled lock payload. It does not prove clean release or higher externality.",
    }


def build_authority_convergence_pass_current_head(*, root: Path) -> Dict[str, Any]:
    report = build_authority_convergence_report(root=root)
    observed = report.get("observed") if isinstance(report.get("observed"), dict) else {}
    return {
        "schema_id": "kt.operator.authority_convergence_pass_current_head.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if report.get("status") == "PASS" else "FAIL_CLOSED",
        "proof_class": str(report.get("proof_class", "")).strip(),
        "current_repo_head": str(observed.get("current_head_commit", "")).strip(),
        "truth_subject_commit": str(observed.get("truth_subject_commit", "")).strip(),
        "current_head_equals_truth_subject": bool(observed.get("current_head_equals_truth_subject")),
        "published_head_authority_claimed": bool(report.get("published_head_authority_claimed")),
        "current_head_authority_claimed": bool(report.get("current_head_authority_claimed")),
        "h1_admissible": bool(report.get("h1_admissible")),
        "active_truth_source": str(observed.get("active_truth_source", "")).strip(),
        "failures": list(report.get("failures", [])),
        "claim_boundary": (
            "This receipt proves the current-head authority boundary is being read lawfully. "
            "When HEAD differs from the published truth subject, current head may only claim that it contains evidence for the published subject."
        ),
    }


def _required_clean_head_refs(current_head_truth_lock: Dict[str, Any]) -> List[str]:
    refs = {
        DEFAULT_LOCK_REL,
        DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
        DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        DEFAULT_TOOLS_BOUNDARY_RULE_REL,
        DEFAULT_REPORT_AUTHORITY_INDEX_REL,
        GOVERNANCE_AUTHORITY_SUPERSESSION_REGISTRY_REL,
        DEFAULT_OMEGA_GATE_RECEIPT_REL,
        DEFAULT_AUTHORITY_RESOLUTION_RECEIPT_REL,
        DEFAULT_HISTORICAL_CLAIM_FIREWALL_RECEIPT_REL,
        DEFAULT_PRESENT_HEAD_AUTHORITY_SEAL_RECEIPT_REL,
        DEFAULT_AUTHORITY_CONVERGENCE_PASS_CURRENT_HEAD_REL,
        DEFAULT_EXECUTIONIZATION_RECEIPT_REL,
    }
    sealed_scope = current_head_truth_lock.get("sealed_scope", {})
    if isinstance(sealed_scope.get("scope_refs"), list):
        for row in sealed_scope["scope_refs"]:
            ref = str(row.get("ref", "")).strip() if isinstance(row, dict) else str(row).strip()
            if ref:
                refs.add(ref)
    return sorted(refs)


def build_clean_current_head_receipt(
    *,
    root: Path,
    required_refs: Sequence[str],
    current_head_truth_lock: Optional[Dict[str, Any]] = None,
    out_rel: str = DEFAULT_CLEAN_CURRENT_HEAD_RECEIPT_REL,
) -> Dict[str, Any]:
    head_sha = _git(root, "rev-parse", "HEAD")
    temp_root = Path(tempfile.mkdtemp(prefix=f"kt_gate_a_{head_sha[:7]}_")).resolve()
    snapshot_root = temp_root / "snapshot"
    snapshot_status_clean = False
    missing_from_snapshot: List[str] = []
    try:
        subprocess.run(
            ["git", "-C", str(root), "worktree", "add", "--detach", str(snapshot_root), head_sha],
            check=True,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        snapshot_head = _git(snapshot_root, "rev-parse", "HEAD")
        status_lines = subprocess.check_output(
            ["git", "-C", str(snapshot_root), "status", "--porcelain=v1"],
            text=True,
            encoding="utf-8",
        ).splitlines()
        snapshot_status_clean = not [line for line in status_lines if line.strip()]
        missing_from_snapshot = [ref for ref in required_refs if not (snapshot_root / Path(ref)).exists()]
    finally:
        try:
            if snapshot_root.exists():
                subprocess.run(
                    ["git", "-C", str(root), "worktree", "remove", "--force", str(snapshot_root)],
                    check=False,
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

    live_states = [
        {
            "ref": ref,
            "live_tracking_state": _git_status_for_path(root, ref),
            "exists_in_live_worktree": _resolve(root, ref).exists(),
        }
        for ref in required_refs
    ]
    required_live_surface_refs_present = all(row["exists_in_live_worktree"] for row in live_states)
    lock = current_head_truth_lock or {}
    sealed_scope = lock.get("sealed_scope") if isinstance(lock.get("sealed_scope"), dict) else {}
    sealed_worktree_scope_accepted = (
        bool(lock)
        and str(lock.get("status", "")).strip() == "PASS"
        and str(lock.get("active_authority_mode", "")).strip() == "WORKTREE_TRANSITIONAL_CURRENT_HEAD_LOCKED"
        and str(sealed_scope.get("scope_class", "")).strip() == "CURRENT_HEAD_WORKTREE_SCOPE_ONLY"
        and bool(str(sealed_scope.get("scope_digest", "")).strip())
        and required_live_surface_refs_present
    )
    status = "PASS" if (snapshot_status_clean and not missing_from_snapshot) or sealed_worktree_scope_accepted else "FAIL_CLOSED"
    return {
        "schema_id": "kt.operator.clean_current_head_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "current_repo_head": head_sha,
        "snapshot_mode": "DETACHED_WORKTREE_AT_HEAD",
        "required_surface_refs": list(required_refs),
        "snapshot_worktree_clean": snapshot_status_clean,
        "missing_from_clean_head_snapshot": missing_from_snapshot,
        "required_live_surface_refs_present": required_live_surface_refs_present,
        "sealed_worktree_scope_accepted": sealed_worktree_scope_accepted,
        "sealed_worktree_scope_class": str(sealed_scope.get("scope_class", "")).strip(),
        "sealed_worktree_scope_digest": str(sealed_scope.get("scope_digest", "")).strip(),
        "counted_authority_snapshot_mode": (
            "CLEAN_HEAD_SNAPSHOT"
            if snapshot_status_clean and not missing_from_snapshot
            else "SEALED_WORKTREE_SCOPE"
            if sealed_worktree_scope_accepted
            else "NONE"
        ),
        "live_surface_states": live_states,
        "claim_boundary": (
            "A PASS here proves either that the exact current HEAD can materialize the counted Gate A authority surfaces from a clean detached snapshot, "
            "or that the current-head truth lock has sealed an explicit bounded worktree scope whose counted authority refs are all present live. "
            "It does not claim press-ready release admissibility or any claim widening above the current ceiling."
        ),
        "next_lawful_move_if_fail": "Materialize the counted Gate A authority surfaces on a clean current head or seal them into an explicit bounded worktree scope before counting higher gates.",
        "artifact_ref": out_rel,
    }


def build_bundle_self_validation_receipt(
    *,
    constitution_report: Dict[str, Any],
    reporting_report: Dict[str, Any],
    authority_resolution_receipt: Dict[str, Any],
    historical_claim_firewall_receipt: Dict[str, Any],
    present_head_authority_seal_receipt: Dict[str, Any],
    omega_gate_receipt: Dict[str, Any],
    authority_supersession_registry: Dict[str, Any],
) -> Dict[str, Any]:
    checks = [
        {"check": "constitution_self_check_passes", "status": constitution_report.get("status", "")},
        {"check": "reporting_integrity_passes", "status": reporting_report.get("status", "")},
        {"check": "authority_resolution_receipt_passes", "status": authority_resolution_receipt.get("status", "")},
        {"check": "historical_claim_firewall_receipt_passes", "status": historical_claim_firewall_receipt.get("status", "")},
        {"check": "present_head_authority_seal_receipt_passes", "status": present_head_authority_seal_receipt.get("status", "")},
        {"check": "omega_gate_receipt_passes", "status": omega_gate_receipt.get("status", "")},
        {"check": "authority_supersession_registry_passes", "status": authority_supersession_registry.get("status", "")},
    ]
    failures = [row["check"] for row in checks if row["status"] != "PASS" and row["status"] != "ACTIVE"]
    return {
        "schema_id": "kt.operator.bundle_self_validation_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL_CLOSED",
        "checks": checks,
        "failures": failures,
        "claim_boundary": "Bundle self-validation proves internal consistency of the Gate A packet only. It does not prove clean head materialization or higher-gate readiness.",
    }


def build_executionization_receipt(
    *,
    root: Path,
    constitution_report: Dict[str, Any],
    reporting_report: Dict[str, Any],
    repo_hygiene_outputs: Dict[str, Dict[str, Any]],
    authority_supersession_registry: Dict[str, Any],
) -> Dict[str, Any]:
    canonical_paths = [
        DEFAULT_LOCK_REL,
        DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
        DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        DEFAULT_TOOLS_BOUNDARY_RULE_REL,
        DEFAULT_REPORT_AUTHORITY_INDEX_REL,
        DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL,
        GOVERNANCE_AUTHORITY_SUPERSESSION_REGISTRY_REL,
        DEFAULT_OMEGA_GATE_RECEIPT_REL,
    ]
    path_binding_ok = all(str(path).startswith("KT_PROD_CLEANROOM/") for path in canonical_paths)
    comparator_alias_clean = not _resolve(root, COMPARATOR_ALIAS_REL).exists()
    checks = [
        {"check": "constitution_self_check_passes", "status": constitution_report.get("status", "")},
        {"check": "reporting_integrity_passes", "status": reporting_report.get("status", "")},
        {"check": "canonical_paths_bound_inside_repo_root", "status": "PASS" if path_binding_ok else "FAIL"},
        {"check": "governance_authority_supersession_registry_emitted", "status": authority_supersession_registry.get("status", "")},
        {"check": "gate_c_alias_drift_absent", "status": "PASS" if comparator_alias_clean else "FAIL"},
    ]
    failures = [row["check"] for row in checks if row["status"] != "PASS"]
    return {
        "schema_id": "kt.operator.kt_omega_v10_executionization_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL_CLOSED",
        "checks": checks,
        "failures": failures,
        "repo_hygiene_status": repo_hygiene_outputs["hygiene"]["status"],
        "repo_hygiene_claim_boundary": (
            "Executionization does not convert a dirty starting state into a clean authority pass. "
            "It binds the batch to real repo paths and records the live hygiene blocker honestly."
        ),
        "canonical_paths": canonical_paths,
        "gate_c_alias_drift_detail": {
            "baseline_vs_live_present": _resolve(root, BASELINE_CANONICAL_REL).exists(),
            "comparator_eval_alias_present": _resolve(root, COMPARATOR_ALIAS_REL).exists(),
        },
    }


def build_gate_a_campaign_receipt(
    *,
    executionization_receipt: Dict[str, Any],
    clean_current_head_receipt: Dict[str, Any],
    truth_lock_freshness_receipt: Dict[str, Any],
    bundle_self_validation_receipt: Dict[str, Any],
    repo_hygiene_outputs: Dict[str, Dict[str, Any]],
    authority_convergence_pass_current_head: Dict[str, Any],
    present_head_authority_seal_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    b00_status = executionization_receipt.get("status", "")
    b01_checks = [
        {"check": "repo_hygiene_validate", "status": repo_hygiene_outputs["hygiene"]["status"]},
        {"check": "authority_convergence_pass_current_head", "status": authority_convergence_pass_current_head.get("status", "")},
        {"check": "truth_lock_freshness_receipt", "status": truth_lock_freshness_receipt.get("status", "")},
        {"check": "bundle_self_validation_receipt", "status": bundle_self_validation_receipt.get("status", "")},
        {"check": "present_head_authority_seal_receipt", "status": present_head_authority_seal_receipt.get("status", "")},
        {"check": "clean_current_head_receipt", "status": clean_current_head_receipt.get("status", "")},
    ]
    b01_failures = [row["check"] for row in b01_checks if row["status"] != "PASS"]
    b01_status = "PASS" if not b01_failures else "HOLD"
    overall_status = "PASS" if b00_status == "PASS" and b01_status == "PASS" else "HOLD"
    return {
        "schema_id": "kt.operator.v11_gate_a_campaign_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": overall_status,
        "batch_statuses": {
            "B00_EXECUTIONIZE_V9": b00_status,
            "B01_GATE_A_AUTHORITY_SEAL": b01_status,
        },
        "b01_checks": b01_checks,
        "b01_failures": b01_failures,
        "next_lawful_move": (
            "Gate A complete; next add one truth engine and contradiction validator."
            if overall_status == "PASS"
            else "Land the counted Gate A authority surfaces on a clean head and rerun the seal before any higher-gate counting."
        ),
        "claim_boundary": "This batch receipt reports executionization plus Gate A authority restoration only. It does not widen runtime, externality, or product claims.",
    }


def run_gate_a_campaign(*, root: Path) -> Dict[str, Dict[str, Any]]:
    constitution_report = self_check()
    reporting_report = verify_reporting_integrity(root=root)
    repo_hygiene_outputs = build_ws13_outputs(root)
    _write(root, REPO_HYGIENE_INVENTORY_REL, repo_hygiene_outputs["inventory"])
    _write(root, REPO_HYGIENE_CLEAN_STATE_RECEIPT_REL, repo_hygiene_outputs["clean_state"])
    _write(root, REPO_HYGIENE_RECEIPT_REL, repo_hygiene_outputs["hygiene"])

    authority_resolution_index = build_authority_resolution_index(root=root)
    historical_claim_firewall = build_historical_claim_firewall(root=root)
    tools_runtime_boundary_rule = build_tools_runtime_boundary_rule(root=root)
    current_head_truth_lock = build_current_head_truth_lock(root=root)
    report_authority_index = build_report_authority_index(root=root)
    authority_supersession_map = build_authority_supersession_map(root=root)
    authority_supersession_registry = build_authority_supersession_registry(root=root)
    canonical_delta = build_canonical_delta_w0(root=root)
    advancement_delta = build_advancement_delta_w0(root=root)
    omega_gate_receipt = build_omega_gate_receipt(root=root)

    authority_resolution_receipt = build_authority_resolution_receipt(root=root, authority_resolution_index=authority_resolution_index)
    historical_claim_firewall_receipt = build_historical_claim_firewall_receipt(root=root, historical_claim_firewall=historical_claim_firewall)
    present_head_authority_seal_receipt = build_present_head_authority_seal_receipt(
        root=root,
        current_head_truth_lock=current_head_truth_lock,
        authority_resolution_receipt=authority_resolution_receipt,
        historical_claim_firewall_receipt=historical_claim_firewall_receipt,
    )
    authority_convergence_pass_current_head = build_authority_convergence_pass_current_head(root=root)

    _write(root, DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL, authority_resolution_index)
    _write(root, DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL, historical_claim_firewall)
    _write(root, DEFAULT_TOOLS_BOUNDARY_RULE_REL, tools_runtime_boundary_rule)
    _write(root, DEFAULT_LOCK_REL, current_head_truth_lock)
    _write(root, DEFAULT_REPORT_AUTHORITY_INDEX_REL, report_authority_index)
    _write(root, DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL, authority_supersession_map)
    _write(root, GOVERNANCE_AUTHORITY_SUPERSESSION_REGISTRY_REL, authority_supersession_registry)
    _write(root, DEFAULT_CANONICAL_DELTA_REL, canonical_delta)
    _write(root, DEFAULT_ADVANCEMENT_DELTA_REL, advancement_delta)
    _write(root, DEFAULT_OMEGA_GATE_RECEIPT_REL, omega_gate_receipt)
    _write(root, DEFAULT_AUTHORITY_RESOLUTION_RECEIPT_REL, authority_resolution_receipt)
    _write(root, DEFAULT_HISTORICAL_CLAIM_FIREWALL_RECEIPT_REL, historical_claim_firewall_receipt)
    _write(root, DEFAULT_PRESENT_HEAD_AUTHORITY_SEAL_RECEIPT_REL, present_head_authority_seal_receipt)
    _write(root, DEFAULT_AUTHORITY_CONVERGENCE_PASS_CURRENT_HEAD_REL, authority_convergence_pass_current_head)

    executionization_receipt = build_executionization_receipt(
        root=root,
        constitution_report=constitution_report,
        reporting_report=reporting_report,
        repo_hygiene_outputs=repo_hygiene_outputs,
        authority_supersession_registry=authority_supersession_registry,
    )
    _write(root, DEFAULT_EXECUTIONIZATION_RECEIPT_REL, executionization_receipt)

    truth_lock_freshness_receipt = build_truth_lock_freshness_receipt(root=root, expected_lock=current_head_truth_lock)
    _write(root, DEFAULT_TRUTH_LOCK_FRESHNESS_RECEIPT_REL, truth_lock_freshness_receipt)

    clean_current_head_receipt = build_clean_current_head_receipt(
        root=root,
        required_refs=_required_clean_head_refs(current_head_truth_lock),
        current_head_truth_lock=current_head_truth_lock,
    )
    _write(root, DEFAULT_CLEAN_CURRENT_HEAD_RECEIPT_REL, clean_current_head_receipt)

    bundle_self_validation_receipt = build_bundle_self_validation_receipt(
        constitution_report=constitution_report,
        reporting_report=reporting_report,
        authority_resolution_receipt=authority_resolution_receipt,
        historical_claim_firewall_receipt=historical_claim_firewall_receipt,
        present_head_authority_seal_receipt=present_head_authority_seal_receipt,
        omega_gate_receipt=omega_gate_receipt,
        authority_supersession_registry=authority_supersession_registry,
    )
    _write(root, DEFAULT_BUNDLE_SELF_VALIDATION_RECEIPT_REL, bundle_self_validation_receipt)

    gate_a_campaign_receipt = build_gate_a_campaign_receipt(
        executionization_receipt=executionization_receipt,
        clean_current_head_receipt=clean_current_head_receipt,
        truth_lock_freshness_receipt=truth_lock_freshness_receipt,
        bundle_self_validation_receipt=bundle_self_validation_receipt,
        repo_hygiene_outputs=repo_hygiene_outputs,
        authority_convergence_pass_current_head=authority_convergence_pass_current_head,
        present_head_authority_seal_receipt=present_head_authority_seal_receipt,
    )
    _write(root, DEFAULT_GATE_A_CAMPAIGN_RECEIPT_REL, gate_a_campaign_receipt)

    return {
        "constitution_report": constitution_report,
        "reporting_report": reporting_report,
        "repo_hygiene_outputs": repo_hygiene_outputs,
        "executionization_receipt": executionization_receipt,
        "truth_lock_freshness_receipt": truth_lock_freshness_receipt,
        "authority_convergence_pass_current_head": authority_convergence_pass_current_head,
        "clean_current_head_receipt": clean_current_head_receipt,
        "bundle_self_validation_receipt": bundle_self_validation_receipt,
        "gate_a_campaign_receipt": gate_a_campaign_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute the v11 campaign's B00/B01 Gate A tranche against the live repo.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    root = repo_root()
    result = run_gate_a_campaign(root=root)
    summary = {
        "status": result["gate_a_campaign_receipt"]["status"],
        "b00_status": result["gate_a_campaign_receipt"]["batch_statuses"]["B00_EXECUTIONIZE_V9"],
        "b01_status": result["gate_a_campaign_receipt"]["batch_statuses"]["B01_GATE_A_AUTHORITY_SEAL"],
        "repo_hygiene_status": result["repo_hygiene_outputs"]["hygiene"]["status"],
        "clean_current_head_status": result["clean_current_head_receipt"]["status"],
        "next_lawful_move": result["gate_a_campaign_receipt"]["next_lawful_move"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
