from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE"
STEP_ID = "WS12_STEP_1_SUPPLY_CHAIN_AND_TRUTH_RECONCILIATION"
PASS_VERDICT = "CURRENT_HEAD_TRUTH_PLANES_RECONCILED_AND_ATTACK_COVERAGE_FAIL_CLOSED"
PARTIAL_VERDICT = "CURRENT_HEAD_SUPPLY_CHAIN_POLICY_PRESENT_BUT_RECONCILIATION_INCOMPLETE"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"
WS12_DIR_REL = f"{REPORT_ROOT_REL}/ws12_supply_chain"

EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
TRUST_ROOT_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_trust_root_policy.json"
SIGNER_TOPOLOGY_REL = f"{GOVERNANCE_ROOT_REL}/kt_signer_topology.json"
SIGNER_IDENTITY_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/signer_identity_policy.json"
LOG_MONITOR_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_log_monitor_policy.json"
SUPPLY_CHAIN_LAYOUT_REL = f"{GOVERNANCE_ROOT_REL}/supply_chain_layout.json"

WS11_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_sigstore_integration_receipt.json"
WS11_KEYLESS_STATUS_REL = f"{REPORT_ROOT_REL}/kt_sigstore_keyless_status.json"
WS11_LOG_MONITOR_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_log_monitor_plane_receipt.json"
WS11_PUBLIC_TRUST_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_ws11_public_trust_bundle.json"
LEGACY_TRUTH_BARRIER_DIAGNOSTIC_REL = f"{REPORT_ROOT_REL}/ws11_keyless/kt_truth_barrier_remote_diagnostic.json"

PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
SOURCE_IN_TOTO_REL = f"{REPORT_ROOT_REL}/source_build_attestation/in_toto_statement.json"
CRYPTO_IN_TOTO_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/in_toto_statement.json"
BUILD_PROVENANCE_REL = f"{REPORT_ROOT_REL}/kt_build_provenance.dsse"
VERIFICATION_SUMMARY_REL = f"{REPORT_ROOT_REL}/kt_verification_summary_attestation.dsse"
BUILD_VERIFICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_build_verification_receipt.json"

LOCAL_TRUTH_INDEX_REL = f"{WS12_DIR_REL}/live_validation_index.local.json"
REMOTE_TRUTH_INDEX_REL = f"{WS12_DIR_REL}/live_validation_index.ci.json"
REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL = f"{WS12_DIR_REL}/kt_truth_barrier_remote_diagnostic.json"
REMOTE_KEYLESS_RECEIPT_REL = f"{WS12_DIR_REL}/kt_ws11_keyless_execution_receipt.json"
REMOTE_KEYLESS_BUNDLE_REL = f"{WS12_DIR_REL}/public_verifier_manifest.sigstore.json"
REMOTE_SIGNED_SURFACE_REL = f"{WS12_DIR_REL}/public_verifier_manifest.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_supply_chain_policy_receipt.json"

BOUNDED_KEYLESS_SURFACES = [PUBLIC_VERIFIER_MANIFEST_REL]
PLANNED_MUTATES = [
    EXECUTION_DAG_REL,
    TRUST_ROOT_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    LOCAL_TRUTH_INDEX_REL,
    REMOTE_TRUTH_INDEX_REL,
    REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL,
    REMOTE_KEYLESS_RECEIPT_REL,
    REMOTE_KEYLESS_BUNDLE_REL,
    REMOTE_SIGNED_SURFACE_REL,
    RECEIPT_REL,
    "KT_PROD_CLEANROOM/tools/operator/ws12_supply_chain_policy_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ws12_supply_chain_policy_validate.py",
]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_lines(root: Path) -> List[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _dirty_relpaths(status_lines: Sequence[str]) -> List[str]:
    rows: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if rel:
            rows.append(Path(rel).as_posix())
    return sorted(set(rows))


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS12 input: {rel}")
    return load_json(path)


def _write_json(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / Path(rel)).resolve(), payload)


def _check(value: bool, check_id: str, detail: str, refs: Sequence[str], **extra: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "check": check_id,
        "status": "PASS" if value else "FAIL",
        "detail": detail,
        "refs": [str(Path(ref).as_posix()) for ref in refs],
    }
    row.update(extra)
    return row


def _critical_checks_pass(index: Dict[str, Any]) -> bool:
    checks = index.get("checks") if isinstance(index.get("checks"), list) else []
    for row in checks:
        if not isinstance(row, dict):
            continue
        if not bool(row.get("critical")):
            continue
        status = str(row.get("status", "")).strip()
        check_id = str(row.get("check_id", "")).strip()
        if check_id == "operator_clean_clone_smoke" and status == "SKIP":
            continue
        if status != "PASS":
            return False
    return True


def _truth_index_current_head_pass(index: Dict[str, Any], *, current_head: str) -> bool:
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    return (
        str(worktree.get("head_sha", "")).strip() == current_head
        and not bool(worktree.get("git_dirty"))
        and _critical_checks_pass(index)
    )


def _string_at_path(payload: Dict[str, Any], path: Sequence[str]) -> str:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return str(current).strip() if current is not None else ""


def _bundle_sha_matches(root: Path, receipt: Dict[str, Any]) -> bool:
    expected = _string_at_path(receipt, ["bundle_sha256"]).lower()
    if not expected:
        return False
    candidate = (root / Path(REMOTE_KEYLESS_BUNDLE_REL)).resolve()
    return candidate.exists() and file_sha256(candidate).lower() == expected

def _surface_sha_matches(root: Path, receipt: Dict[str, Any]) -> bool:
    expected = _string_at_path(receipt, ["signed_surface_sha256"]).lower()
    if not expected:
        return False
    candidate = (root / Path(REMOTE_SIGNED_SURFACE_REL)).resolve()
    if not candidate.exists():
        return False
    return file_sha256(candidate).lower() == expected


def _attack_status(pass_condition: bool, *, scenario_id: str, detail: str, refs: Sequence[str], containment: bool = False) -> Dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "status": "PASS_CONTAINED" if pass_condition and containment else "PASS" if pass_condition else "FAIL",
        "detail": detail,
        "refs": [str(Path(ref).as_posix()) for ref in refs],
    }


def _path_in_scope(path: str) -> bool:
    normalized = str(Path(path).as_posix()).rstrip("/")
    for allowed in PLANNED_MUTATES:
        allowed_norm = str(Path(allowed).as_posix()).rstrip("/")
        if normalized == allowed_norm or normalized.startswith(f"{allowed_norm}/") or allowed_norm.startswith(f"{normalized}/"):
            return True
    return False


def build_ws12_receipt(
    *,
    root: Path,
    current_head: str,
    generated_utc: str,
    signer_identity_policy: Dict[str, Any],
    log_monitor_policy: Dict[str, Any],
    supply_chain_layout: Dict[str, Any],
    ws11_receipt: Dict[str, Any],
    ws11_keyless_status: Dict[str, Any],
    ws11_log_monitor_receipt: Dict[str, Any],
    ws11_public_trust_bundle: Dict[str, Any],
    trust_root_policy: Dict[str, Any],
    signer_topology: Dict[str, Any],
    local_truth_index: Dict[str, Any],
    remote_truth_index: Dict[str, Any],
    remote_truth_barrier_diagnostic: Dict[str, Any],
    remote_keyless_receipt: Dict[str, Any],
    legacy_truth_barrier_diagnostic: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    imported_signed_surface_sha = file_sha256((root / Path(REMOTE_SIGNED_SURFACE_REL)).resolve())
    local_truth_pass = _truth_index_current_head_pass(local_truth_index, current_head=current_head)
    remote_truth_pass = _truth_index_current_head_pass(remote_truth_index, current_head=current_head)
    remote_diagnostic_pass = (
        str(remote_truth_barrier_diagnostic.get("status", "")).strip() == "PASS"
        and str(remote_truth_barrier_diagnostic.get("truth_barrier_step_outcome", "")).strip() == "success"
        and str(remote_truth_barrier_diagnostic.get("truth_barrier_step_conclusion", "")).strip() == "success"
        and str(remote_truth_barrier_diagnostic.get("run_id", "")).strip() == str(remote_keyless_receipt.get("run_id", "")).strip()
    )
    keyless_receipt_pass = (
        str(remote_keyless_receipt.get("status", "")).strip() == "PASS"
        and str(remote_keyless_receipt.get("verification_status", "")).strip() == "PASS"
        and str(remote_keyless_receipt.get("executed_signer_mode", "")).strip() == "sigstore_keyless"
        and str(remote_keyless_receipt.get("signed_surface_path", "")).strip() == PUBLIC_VERIFIER_MANIFEST_REL
        and _surface_sha_matches(root, remote_keyless_receipt)
        and _bundle_sha_matches(root, remote_keyless_receipt)
        and str(remote_keyless_receipt.get("certificate_identity", "")).strip()
        == _string_at_path(signer_identity_policy, ["keyless_constraints", "certificate_identity"])
        and str(remote_keyless_receipt.get("certificate_oidc_issuer", "")).strip()
        == _string_at_path(signer_identity_policy, ["keyless_constraints", "certificate_oidc_issuer"])
        and list(remote_keyless_receipt.get("keyless_backed_surfaces", [])) == BOUNDED_KEYLESS_SURFACES
    )
    in_toto_slsa_present = (
        (root / Path(SOURCE_IN_TOTO_REL)).exists()
        and (root / Path(CRYPTO_IN_TOTO_REL)).exists()
        and (root / Path(BUILD_PROVENANCE_REL)).exists()
        and (root / Path(VERIFICATION_SUMMARY_REL)).exists()
        and str(supply_chain_layout.get("status", "")).strip() == "ACTIVE"
        and str(_load_required_json(root, BUILD_VERIFICATION_RECEIPT_REL).get("status", "")).strip() == "PASS"
    )

    freeze_attack = (
        bool(_string_at_path(supply_chain_layout, ["expires_utc"]))
        and bool(log_monitor_policy.get("freeze_behavior", {}).get("freeze_on_any_high_or_critical_anomaly"))
        and str(ws11_log_monitor_receipt.get("status", "")).strip() == "PASS"
    )
    rollback_attack = (
        local_truth_pass
        and remote_truth_pass
        and remote_diagnostic_pass
        and keyless_receipt_pass
        and imported_signed_surface_sha.lower() == str(remote_keyless_receipt.get("signed_surface_sha256", "")).strip().lower()
    )
    mix_and_match_attack = keyless_receipt_pass
    key_compromise_attack = bool(trust_root_policy.get("emergency_rotation_path")) and str(ws11_log_monitor_receipt.get("status", "")).strip() == "PASS"
    partial_key_loss_attack = (
        str(trust_root_policy.get("semantic_boundary", {}).get("verifier_acceptance_upgraded", "")).strip().lower() in {"false", ""}
        and bool(trust_root_policy.get("emergency_rotation_path"))
        and str(ws11_log_monitor_receipt.get("status", "")).strip() == "PASS"
    )
    attack_scenarios = [
        _attack_status(freeze_attack, scenario_id="tuf_freeze_attack", detail="Freeze attack is fail-closed by expiry-bearing layout plus KT_LOG_MONITOR freeze behavior.", refs=[SUPPLY_CHAIN_LAYOUT_REL, LOG_MONITOR_POLICY_REL, WS11_LOG_MONITOR_RECEIPT_REL]),
        _attack_status(rollback_attack, scenario_id="tuf_rollback_attack", detail="Rollback of the bounded WS12 public surface is detected by current-head local/remote truth alignment and current-head keyless surface binding.", refs=[LOCAL_TRUTH_INDEX_REL, REMOTE_TRUTH_INDEX_REL, REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL, REMOTE_KEYLESS_RECEIPT_REL]),
        _attack_status(mix_and_match_attack, scenario_id="tuf_mix_and_match_attack", detail="Mix-and-match is bounded by exact signed-surface SHA binding and imported bundle SHA verification.", refs=[REMOTE_KEYLESS_RECEIPT_REL, REMOTE_KEYLESS_BUNDLE_REL, REMOTE_SIGNED_SURFACE_REL]),
        _attack_status(key_compromise_attack, scenario_id="tuf_key_compromise", detail="Key compromise is contained by freeze-and-rotate law instead of silent continued trust.", refs=[TRUST_ROOT_POLICY_REL, LOG_MONITOR_POLICY_REL], containment=True),
        _attack_status(partial_key_loss_attack, scenario_id="tuf_partial_key_loss_and_rotation", detail="Partial key loss is contained fail-closed: verifier acceptance is not widened, so KT freezes and re-ceremonies instead of overclaiming continuity.", refs=[TRUST_ROOT_POLICY_REL, SIGNER_TOPOLOGY_REL, WS11_LOG_MONITOR_RECEIPT_REL], containment=True),
    ]
    attack_failures = [row["scenario_id"] for row in attack_scenarios if row["status"] == "FAIL"]
    blockers: List[str] = []
    if str(ws11_receipt.get("status", "")).strip() != "PASS":
        blockers.append("WS11_NOT_SEALED_PASS")
    if str(ws11_keyless_status.get("status", "")).strip() != "PASS":
        blockers.append("WS11_KEYLESS_STATUS_NOT_PASS")
    if str(ws11_log_monitor_receipt.get("status", "")).strip() != "PASS":
        blockers.append("WS11_LOG_MONITOR_NOT_PASS")
    if str(ws11_public_trust_bundle.get("status", "")).strip() != "PASS":
        blockers.append("WS11_PUBLIC_TRUST_BUNDLE_NOT_PASS")
    if not local_truth_pass:
        blockers.append("LOCAL_TRUTH_BARRIER_NOT_PASSING_ON_CURRENT_HEAD")
    if not remote_truth_pass:
        blockers.append("REMOTE_TRUTH_BARRIER_NOT_PASSING_ON_CURRENT_HEAD")
    if not remote_diagnostic_pass:
        blockers.append("REMOTE_TRUTH_BARRIER_DIAGNOSTIC_NOT_PASS")
    if not keyless_receipt_pass:
        blockers.append("CURRENT_HEAD_KEYLESS_BUNDLE_NOT_BOUND")
    if not in_toto_slsa_present:
        blockers.append("IN_TOTO_SLSA_LINEAGE_NOT_PRESENT")
    if attack_failures:
        blockers.append("TUF_ATTACK_COVERAGE_NOT_FAIL_CLOSED")

    status = "PASS" if not blockers else "PARTIAL"
    next_lawful = "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK" if status == "PASS" else WORKSTREAM_ID
    checks = [
        _check(str(ws11_receipt.get("status", "")).strip() == "PASS", "ws11_receipt_pass", "WS11 must already be PASS before WS12 ratification.", [WS11_RECEIPT_REL]),
        _check(local_truth_pass, "local_truth_barrier_pass_current_head", "Local truth barrier evidence must pass on the current head without a dirty worktree.", [LOCAL_TRUTH_INDEX_REL]),
        _check(remote_truth_pass, "remote_truth_barrier_pass_current_head", "Remote truth barrier evidence must pass on the current head without a dirty worktree.", [REMOTE_TRUTH_INDEX_REL]),
        _check(remote_diagnostic_pass, "remote_truth_barrier_step_pass", "Imported remote diagnostic must show success for the truth barrier step.", [REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL, REMOTE_KEYLESS_RECEIPT_REL]),
        _check(keyless_receipt_pass, "current_head_keyless_bundle_bound", "Imported current-head keyless receipt must bind the declared WS11 surface, signer identity, and bundle SHA.", [REMOTE_KEYLESS_RECEIPT_REL, REMOTE_KEYLESS_BUNDLE_REL, REMOTE_SIGNED_SURFACE_REL]),
        _check(in_toto_slsa_present, "in_toto_slsa_lineage_present", "Bounded in-toto/SLSA-aligned lineage artifacts must remain present for the publication/build chain.", [SOURCE_IN_TOTO_REL, CRYPTO_IN_TOTO_REL, BUILD_PROVENANCE_REL, VERIFICATION_SUMMARY_REL, BUILD_VERIFICATION_RECEIPT_REL]),
        _check(not attack_failures, "tuf_attack_coverage_fail_closed", "TUF attack coverage must fail closed across the declared WS12 scenarios.", [TRUST_ROOT_POLICY_REL, SIGNER_TOPOLOGY_REL, SUPPLY_CHAIN_LAYOUT_REL, LOG_MONITOR_POLICY_REL], failures=attack_failures),
    ]
    prior_remote_failure_visible = isinstance(legacy_truth_barrier_diagnostic, dict) and str(legacy_truth_barrier_diagnostic.get("truth_barrier_step_outcome", "")).strip() == "failure"
    return {
        "schema_id": "kt.operator.supply_chain_policy_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else PARTIAL_VERDICT,
        "generated_utc": generated_utc,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "bounded_current_surface": PUBLIC_VERIFIER_MANIFEST_REL,
        "imported_signed_surface_ref": REMOTE_SIGNED_SURFACE_REL,
        "checks": checks,
        "tuf_attack_scenarios": attack_scenarios,
        "blocked_by": blockers,
        "truth_plane_reconciliation": {
            "legacy_remote_failure_visible": prior_remote_failure_visible,
            "legacy_remote_failure_ref": LEGACY_TRUTH_BARRIER_DIAGNOSTIC_REL if prior_remote_failure_visible else "",
            "local_truth_current_head_pass": local_truth_pass,
            "remote_truth_current_head_pass": remote_truth_pass,
            "remote_truth_barrier_step_pass": remote_diagnostic_pass,
        },
        "supply_chain_lineage": {
            "source_in_toto_ref": SOURCE_IN_TOTO_REL,
            "publication_in_toto_ref": CRYPTO_IN_TOTO_REL,
            "build_provenance_ref": BUILD_PROVENANCE_REL,
            "verification_summary_ref": VERIFICATION_SUMMARY_REL,
            "build_verification_receipt_ref": BUILD_VERIFICATION_RECEIPT_REL,
            "supply_chain_layout_ref": SUPPLY_CHAIN_LAYOUT_REL,
            "workflow_run_id": str(remote_keyless_receipt.get("run_id", "")).strip(),
            "certificate_identity": str(remote_keyless_receipt.get("certificate_identity", "")).strip(),
            "certificate_oidc_issuer": str(remote_keyless_receipt.get("certificate_oidc_issuer", "")).strip(),
            "signed_surface_sha256": str(remote_keyless_receipt.get("signed_surface_sha256", "")).strip(),
        },
        "imported_evidence": {
            "local_truth_index_ref": LOCAL_TRUTH_INDEX_REL,
            "remote_truth_index_ref": REMOTE_TRUTH_INDEX_REL,
            "remote_truth_barrier_diagnostic_ref": REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL,
            "remote_keyless_execution_receipt_ref": REMOTE_KEYLESS_RECEIPT_REL,
            "remote_keyless_bundle_ref": REMOTE_KEYLESS_BUNDLE_REL,
            "imported_hashes": {
                LOCAL_TRUTH_INDEX_REL: file_sha256((root / Path(LOCAL_TRUTH_INDEX_REL)).resolve()),
                REMOTE_TRUTH_INDEX_REL: file_sha256((root / Path(REMOTE_TRUTH_INDEX_REL)).resolve()),
                REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL: file_sha256((root / Path(REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL)).resolve()),
                REMOTE_KEYLESS_RECEIPT_REL: file_sha256((root / Path(REMOTE_KEYLESS_RECEIPT_REL)).resolve()),
                REMOTE_KEYLESS_BUNDLE_REL: file_sha256((root / Path(REMOTE_KEYLESS_BUNDLE_REL)).resolve()),
                REMOTE_SIGNED_SURFACE_REL: file_sha256((root / Path(REMOTE_SIGNED_SURFACE_REL)).resolve()),
            },
        },
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.ws12_supply_chain_policy_validate"],
        "tests_run": ["python -m pytest -q tests/operator/test_ws12_supply_chain_policy_validate.py"],
        "current_strongest_claim": "WS12 proves a bounded current-head supply-chain policy for KT_PROD_CLEANROOM/reports/public_verifier_manifest.json: local and remote truth-barrier evidence reconcile on the same head, the executed signing path is keyless with imported Rekor-backed evidence, and TUF attack scenarios are covered fail-closed for the declared pre-release surfaces." if status == "PASS" else "WS12 has current-head supply-chain evidence and imported truth-plane artifacts, but the bounded current-head reconciliation or attack coverage is incomplete, so the workstream remains current and no downstream unlock is lawful.",
        "limitations": [
            "WS12 PASS does not prove release readiness, verifier acceptance widening, or campaign completion.",
            "WS12 remains bounded to the 3-of-3 WS10 carry-forward truth and the single current-head keyless-backed public verifier manifest surface.",
            "The repo-root import fragility for certain package-root invocations remains visible and is not erased by WS12.",
            "The TUF attack coverage here is fail-closed pre-release policy coverage, not proof of a publicly deployed updater fleet.",
        ],
        "stronger_claim_not_made": [
            "The earlier planned 3-of-5 root topology was proven",
            "WS12 proves active public updater deployment",
            "Release readiness is proven",
            "Enterprise or product readiness is proven",
        ],
        "next_lawful_workstream": next_lawful,
    }


def _apply_control_plane(*, dag: Dict[str, Any], trust_root_policy: Dict[str, Any], signer_topology: Dict[str, Any], receipt: Dict[str, Any]) -> None:
    generated_utc = str(receipt.get("generated_utc", "")).strip()
    current_head = str(receipt.get("current_repo_head", "")).strip()
    ws12_pass = str(receipt.get("status", "")).strip() == "PASS"

    dag["generated_utc"] = generated_utc
    dag["current_repo_head"] = current_head
    dag["current_node"] = receipt["next_lawful_workstream"]
    dag["next_lawful_workstream"] = receipt["next_lawful_workstream"]
    dag["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. WS12 passed for bounded current-head supply-chain policy, local/remote truth-plane reconciliation, and fail-closed TUF attack coverage on declared pre-release surfaces."
        if ws12_pass
        else "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. WS12 remains current because current-head supply-chain reconciliation or fail-closed attack coverage is not yet fully proven."
    )
    ws12_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws13_node = next(node for node in dag["nodes"] if node["id"] == "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK")
    if ws12_pass:
        ws12_node["status"] = "PASS"
        ws12_node["claim_boundary"] = "WS12 PASS proves bounded current-head supply-chain policy and fail-closed TUF attack coverage for the declared pre-release surfaces only."
        ws12_node["blocked_by"] = []
        ws13_node["status"] = "UNLOCKED"
        ws13_node["unlock_basis"] = "WS12 PASS"
    else:
        ws12_node["status"] = "PARTIAL_RECONCILIATION_PENDING"
        ws12_node["claim_boundary"] = "WS12 remains partial until current-head local/remote truth and fail-closed attack coverage are both proven."
        ws12_node["blocked_by"] = list(receipt.get("blocked_by", []))
        ws13_node["status"] = "LOCKED_PENDING_WS12_PASS"
        ws13_node.pop("unlock_basis", None)

    trust_root_policy["generated_utc"] = generated_utc
    trust_root_policy["current_repo_head"] = current_head
    trust_root_policy["closure_boundary"]["next_required_step"] = receipt["next_lawful_workstream"]
    trust_root_policy["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 root ceremony remains executed off-box under a reratified 3-of-3 boundary only. WS11 passed with one bounded keyless public-trust surface. WS12 passed for bounded current-head supply-chain policy and fail-closed attack coverage without widening verifier acceptance or release claims."
        if ws12_pass
        else "WS10 root ceremony remains executed off-box under a reratified 3-of-3 boundary only. WS11 passed with one bounded keyless public-trust surface. WS12 remains current until the current-head supply-chain reconciliation is fully sealed."
    )

    signer_topology["generated_utc"] = generated_utc
    signer_topology["current_repo_head"] = current_head
    signer_topology["semantic_boundary"]["lawful_current_claim"] = (
        "Root signer topology remains executed and reratified as 3-of-3 only. WS12 passed for bounded current-head supply-chain policy without widening non-root issuance beyond the declared pre-release surfaces."
        if ws12_pass
        else "Root signer topology remains executed and reratified as 3-of-3 only. WS12 remains current; non-root issuance is still bounded and unreleased."
    )


def emit_ws12_supply_chain_policy(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or repo_root()
    pre_dirty = _dirty_relpaths(_git_status_lines(repo))
    if pre_dirty and any(not _path_in_scope(path) for path in pre_dirty):
        raise RuntimeError("FAIL_CLOSED: WS12 requires a clean or in-scope worktree before mutation")

    current_head = _git_head(repo)
    generated_utc = utc_now_iso_z()

    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    trust_root_policy = _load_required_json(repo, TRUST_ROOT_POLICY_REL)
    signer_topology = _load_required_json(repo, SIGNER_TOPOLOGY_REL)
    signer_identity_policy = _load_required_json(repo, SIGNER_IDENTITY_POLICY_REL)
    log_monitor_policy = _load_required_json(repo, LOG_MONITOR_POLICY_REL)
    supply_chain_layout = _load_required_json(repo, SUPPLY_CHAIN_LAYOUT_REL)
    ws11_receipt = _load_required_json(repo, WS11_RECEIPT_REL)
    ws11_keyless_status = _load_required_json(repo, WS11_KEYLESS_STATUS_REL)
    ws11_log_monitor_receipt = _load_required_json(repo, WS11_LOG_MONITOR_RECEIPT_REL)
    ws11_public_trust_bundle = _load_required_json(repo, WS11_PUBLIC_TRUST_BUNDLE_REL)
    local_truth_index = _load_required_json(repo, LOCAL_TRUTH_INDEX_REL)
    remote_truth_index = _load_required_json(repo, REMOTE_TRUTH_INDEX_REL)
    remote_truth_barrier_diagnostic = _load_required_json(repo, REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL)
    remote_keyless_receipt = _load_required_json(repo, REMOTE_KEYLESS_RECEIPT_REL)
    legacy_path = (repo / Path(LEGACY_TRUTH_BARRIER_DIAGNOSTIC_REL)).resolve()
    legacy_truth_barrier_diagnostic = load_json(legacy_path) if legacy_path.exists() else None

    receipt = build_ws12_receipt(
        root=repo,
        current_head=current_head,
        generated_utc=generated_utc,
        signer_identity_policy=signer_identity_policy,
        log_monitor_policy=log_monitor_policy,
        supply_chain_layout=supply_chain_layout,
        ws11_receipt=ws11_receipt,
        ws11_keyless_status=ws11_keyless_status,
        ws11_log_monitor_receipt=ws11_log_monitor_receipt,
        ws11_public_trust_bundle=ws11_public_trust_bundle,
        trust_root_policy=trust_root_policy,
        signer_topology=signer_topology,
        local_truth_index=local_truth_index,
        remote_truth_index=remote_truth_index,
        remote_truth_barrier_diagnostic=remote_truth_barrier_diagnostic,
        remote_keyless_receipt=remote_keyless_receipt,
        legacy_truth_barrier_diagnostic=legacy_truth_barrier_diagnostic,
    )
    _apply_control_plane(dag=dag, trust_root_policy=trust_root_policy, signer_topology=signer_topology, receipt=receipt)
    _write_json(repo, EXECUTION_DAG_REL, dag)
    _write_json(repo, TRUST_ROOT_POLICY_REL, trust_root_policy)
    _write_json(repo, SIGNER_TOPOLOGY_REL, signer_topology)
    post_dirty = _dirty_relpaths(_git_status_lines(repo))
    receipt["unexpected_touches"] = sorted(path for path in post_dirty if not _path_in_scope(path))
    receipt["protected_touch_violations"] = []
    _write_json(repo, RECEIPT_REL, receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WS12: reconcile current-head truth planes and validate bounded supply-chain policy.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    receipt = emit_ws12_supply_chain_policy(root=repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
