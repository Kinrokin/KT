from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.public_verifier_release_validate import (
    PUBLIC_VERIFIER_CONTRACT_REL,
    PUBLIC_VERIFIER_RULES_REL,
    PUBLIC_VERIFIER_SOURCE_REL,
    _local_dependency_closure,
)
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.ws13_determinism_envelope_validate import (
    CI_KEYLESS_BUNDLE_REL,
    CI_KEYLESS_RECEIPT_REL,
    CI_SIGNED_SURFACE_REL,
    CI_TRUTH_DIAGNOSTIC_REL,
)


WORKSTREAM_ID = "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY"
STEP_ID = "WS14_STEP_1_RELEASE_STATIC_VERIFIER_AND_LOCK_ACCEPTANCE_POLICY"
PASS_VERDICT = "STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY_LOCKED"
PARTIAL_VERDICT = "STATIC_VERIFIER_RELEASE_OR_ACCEPTANCE_POLICY_INCOMPLETE"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"

WS13_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_envelope_receipt.json"
EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
TRUST_ROOT_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_trust_root_policy.json"
SIGNER_TOPOLOGY_REL = f"{GOVERNANCE_ROOT_REL}/kt_signer_topology.json"
SIGNER_IDENTITY_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/signer_identity_policy.json"
SUPPLY_CHAIN_LAYOUT_REL = f"{GOVERNANCE_ROOT_REL}/supply_chain_layout.json"
TRUTH_FRESHNESS_WINDOWS_REL = f"{GOVERNANCE_ROOT_REL}/truth_freshness_windows.json"
LOG_MONITOR_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_log_monitor_policy.json"
LOG_MONITOR_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_log_monitor_plane_receipt.json"
KEYLESS_STATUS_REL = f"{REPORT_ROOT_REL}/kt_sigstore_keyless_status.json"
TUF_ROOT_INITIALIZATION_REL = f"{REPORT_ROOT_REL}/kt_tuf_root_initialization.json"

ACCEPTANCE_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_acceptance_policy.json"
DISTRIBUTION_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_distribution_policy.json"
STATIC_RELEASE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_release_manifest.json"
STATIC_VERIFIER_SBOM_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_sbom.json"
STATIC_VERIFIER_ATTESTATION_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_attestation.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_receipt.json"

PUBLIC_KEY_REF = "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub"
WS15_ID = "WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW"

BASELINE_ALLOWED_DIRTY_PREFIXES = ("KT_PROD_CLEANROOM/reports/ws13_determinism",)
BASELINE_ALLOWED_DIRTY_PATHS = {
    EXECUTION_DAG_REL,
    TRUST_ROOT_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    WS13_RECEIPT_REL,
}
PLANNED_MUTATES = [
    ACCEPTANCE_POLICY_REL,
    DISTRIBUTION_POLICY_REL,
    STATIC_RELEASE_MANIFEST_REL,
    STATIC_VERIFIER_SBOM_REL,
    STATIC_VERIFIER_ATTESTATION_REL,
    RECEIPT_REL,
    EXECUTION_DAG_REL,
    TRUST_ROOT_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    "KT_PROD_CLEANROOM/tools/operator/ws14_static_verifier_release_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ws14_static_verifier_release_validate.py",
]
ALLOWED_SOURCE_ROOTS = (
    "KT_PROD_CLEANROOM/tools/operator/",
    "KT_PROD_CLEANROOM/tools/canonicalize/",
    "KT_PROD_CLEANROOM/tools/verification/",
)
FORBIDDEN_DEPENDENCY_PATTERNS = (
    "KT_ARCHIVE/",
    "/archive/",
    "/historical/",
    "docs/generated/",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
)
FORBIDDEN_SECRET_PATH_PATTERNS = ("private", "secret", "hmac")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.returncode == 0


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


def _check(
    ok: bool,
    check_id: str,
    detail: str,
    refs: Sequence[str],
    failures: Optional[Sequence[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "check": check_id,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
        "refs": [str(Path(ref).as_posix()) for ref in refs],
    }
    if failures:
        row["failures"] = [str(item) for item in failures]
    row.update(extra)
    return row


def _render_stable_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _stable_payload_sha(obj: Any) -> str:
    return hashlib.sha256(_render_stable_json(obj).encode("utf-8")).hexdigest()


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS14 input: {rel}")
    return load_json(path)


def _write_json(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / Path(rel)).resolve(), payload)


def _component(root: Path, rel: str, *, component_type: str, role: str) -> Dict[str, Any]:
    return {
        "component_type": component_type,
        "path": str(Path(rel).as_posix()),
        "role": role,
        "sha256": file_sha256((root / Path(rel)).resolve()),
    }


def _load_ws13_inputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {
        "ws13_receipt": _load_required_json(root, WS13_RECEIPT_REL),
        "ws13_truth_barrier_diagnostic": _load_required_json(root, CI_TRUTH_DIAGNOSTIC_REL),
        "ws13_keyless_receipt": _load_required_json(root, CI_KEYLESS_RECEIPT_REL),
        "ws13_keyless_bundle": _load_required_json(root, CI_KEYLESS_BUNDLE_REL),
    }


def _surface_check_pass(root: Path, ws13_inputs: Dict[str, Dict[str, Any]]) -> Tuple[bool, List[str]]:
    diagnostic = ws13_inputs["ws13_truth_barrier_diagnostic"]
    keyless_receipt = ws13_inputs["ws13_keyless_receipt"]
    failures: List[str] = []
    signed_surface = (root / Path(CI_SIGNED_SURFACE_REL)).resolve()
    bundle = (root / Path(CI_KEYLESS_BUNDLE_REL)).resolve()
    if str(diagnostic.get("status", "")).strip() != "PASS":
        failures.append("truth_barrier_remote_diagnostic_not_pass")
    if str(diagnostic.get("truth_barrier_step_outcome", "")).strip() != "success":
        failures.append("truth_barrier_step_not_success")
    if str(keyless_receipt.get("status", "")).strip() != "PASS":
        failures.append("keyless_receipt_not_pass")
    if str(keyless_receipt.get("verification_status", "")).strip() != "PASS":
        failures.append("keyless_receipt_verification_not_pass")
    if str(keyless_receipt.get("executed_signer_mode", "")).strip() != "sigstore_keyless":
        failures.append("executed_signer_mode_not_keyless")
    if str(keyless_receipt.get("signed_surface_path", "")).strip() != "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json":
        failures.append("signed_surface_path_unexpected")
    if not signed_surface.exists():
        failures.append("signed_surface_copy_missing")
    elif str(keyless_receipt.get("signed_surface_sha256", "")).strip().lower() != file_sha256(signed_surface).lower():
        failures.append("signed_surface_sha_mismatch")
    if not bundle.exists():
        failures.append("keyless_bundle_missing")
    if str(diagnostic.get("run_id", "")).strip() != str(keyless_receipt.get("run_id", "")).strip():
        failures.append("run_id_mismatch")
    return not failures, failures


def _path_in_scope(path: str) -> bool:
    normalized = str(Path(path).as_posix()).rstrip("/")
    if normalized in BASELINE_ALLOWED_DIRTY_PATHS:
        return True
    if any(normalized.startswith(prefix) for prefix in BASELINE_ALLOWED_DIRTY_PREFIXES):
        return True
    for allowed in PLANNED_MUTATES:
        allowed_norm = str(Path(allowed).as_posix()).rstrip("/")
        if normalized == allowed_norm or normalized.startswith(f"{allowed_norm}/") or allowed_norm.startswith(f"{normalized}/"):
            return True
    return False


def _release_dependency_failures(dependency_closure: Sequence[str]) -> List[str]:
    failures: List[str] = []
    for rel in dependency_closure:
        posix_rel = str(Path(rel).as_posix())
        if not any(posix_rel.startswith(prefix) for prefix in ALLOWED_SOURCE_ROOTS):
            failures.append(f"outside_allowed_roots:{posix_rel}")
        if any(pattern in posix_rel.lower() for pattern in FORBIDDEN_SECRET_PATH_PATTERNS):
            failures.append(f"forbidden_secret_path:{posix_rel}")
        if any(pattern in posix_rel for pattern in FORBIDDEN_DEPENDENCY_PATTERNS):
            failures.append(f"forbidden_dependency:{posix_rel}")
    return sorted(set(failures))


def _extract_version_label(value: str) -> str:
    value = str(value).strip()
    if not value:
        return ""
    tail = value.rsplit("/", 1)[-1]
    return tail or value


def build_acceptance_policy(*, root: Path, current_head: str) -> Dict[str, Any]:
    signer_identity_policy = _load_required_json(root, SIGNER_IDENTITY_POLICY_REL)
    trust_root_policy = _load_required_json(root, TRUST_ROOT_POLICY_REL)
    supply_chain_layout = _load_required_json(root, SUPPLY_CHAIN_LAYOUT_REL)
    freshness = _load_required_json(root, TRUTH_FRESHNESS_WINDOWS_REL)
    log_monitor_policy = _load_required_json(root, LOG_MONITOR_POLICY_REL)
    log_monitor_receipt = _load_required_json(root, LOG_MONITOR_RECEIPT_REL)
    tuf_root = _load_required_json(root, TUF_ROOT_INITIALIZATION_REL)
    ws13_receipt = _load_required_json(root, WS13_RECEIPT_REL)
    keyless_receipt = _load_required_json(root, CI_KEYLESS_RECEIPT_REL)
    diagnostic = _load_required_json(root, CI_TRUTH_DIAGNOSTIC_REL)

    allowed_signers = signer_identity_policy.get("allowed_signers") if isinstance(signer_identity_policy.get("allowed_signers"), list) else []
    keypair = next((row for row in allowed_signers if isinstance(row, dict) and str(row.get("mode", "")).strip() == "cosign_keypair"), {})
    keyless = next((row for row in allowed_signers if isinstance(row, dict) and str(row.get("mode", "")).strip() == "sigstore_keyless"), {})
    publication = supply_chain_layout.get("publication") if isinstance(supply_chain_layout.get("publication"), dict) else {}

    bootstrap_root_id = str(trust_root_policy.get("inheritance", {}).get("foundation_trust_root_id", "")).strip() or str(
        tuf_root.get("trust_root_id", "")
    ).strip()
    pending_root_id = str(trust_root_policy.get("ratified_root_topology", {}).get("target_trust_root_id", "")).strip()
    freshness_windows = freshness.get("freshness_windows_hours") if isinstance(freshness.get("freshness_windows_hours"), dict) else {}
    anomaly_rules = log_monitor_policy.get("anomaly_rules") if isinstance(log_monitor_policy.get("anomaly_rules"), list) else []

    return {
        "schema_id": "kt.governance.public_verifier_acceptance_policy.v1",
        "policy_id": "KT_PUBLIC_VERIFIER_ACCEPTANCE_POLICY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "ws13_subject_head_commit": str(ws13_receipt.get("compiled_against", "")).strip(),
        "release_artifact_refs": [
            STATIC_RELEASE_MANIFEST_REL,
            STATIC_VERIFIER_SBOM_REL,
            STATIC_VERIFIER_ATTESTATION_REL,
        ],
        "accepted_verifier_trust_roots": [
            {
                "trust_root_id": bootstrap_root_id,
                "source_ref": TUF_ROOT_INITIALIZATION_REL,
                "acceptance_state": "ACTIVE_BOOTSTRAP_ACCEPTED",
                "claim_boundary": "Bootstrap verifier trust root remains the only active accepted root in WS14; threshold-root acceptance is not widened here.",
            }
        ],
        "pending_not_yet_accepted_trust_roots": [
            {
                "trust_root_id": pending_root_id,
                "source_ref": TRUST_ROOT_POLICY_REL,
                "acceptance_state": "PENDING_LATER_ACCEPTANCE_UPDATE",
                "reason": "WS14 releases the acceptance policy but does not itself publish a threshold-root acceptance bundle.",
            }
        ],
        "accepted_signature_trust_roots": [
            {
                "signer_id": str(keypair.get("signer_id", "")).strip(),
                "mode": str(keypair.get("mode", "")).strip(),
                "public_key_ref": str(keypair.get("public_key_ref", "")).strip(),
                "public_key_sha256": str(keypair.get("public_key_sha256", "")).strip(),
                "accepted_predicates": list(keypair.get("allowed_predicates", [])),
                "scope": "Historical publication attestation verification only.",
            },
            {
                "signer_id": str(keyless.get("signer_id", "")).strip(),
                "mode": str(keyless.get("mode", "")).strip(),
                "certificate_identity": str(keyless.get("certificate_identity", "")).strip(),
                "certificate_oidc_issuer": str(keyless.get("certificate_oidc_issuer", "")).strip(),
                "rekor_url": str(signer_identity_policy.get("rules", {}).get("rekor_url_default", "")).strip(),
                "scope": "Bounded current-head verification of the imported WS13 signed public verifier manifest copy only.",
            },
        ],
        "accepted_predicate_versions": [
            {
                "statement_type": str(publication.get("statement_type", "")).strip(),
                "predicate_type": str(publication.get("predicate_type", "")).strip(),
                "predicate_version": _extract_version_label(publication.get("predicate_type", "")),
                "scope": "Bounded publication statement verification.",
            }
        ],
        "accepted_schema_versions": [
            {"schema_id": "kt.public_verifier_manifest.v4", "scope": "Bounded imported signed verifier surface only."},
            {"schema_id": "kt.operator.ws11_keyless_execution_receipt.v1", "scope": "Current-head keyless execution carry-forward evidence."},
            {"schema_id": "kt.operator.truth_barrier_remote_diagnostic.v1", "scope": "Current-head CI truth-barrier success evidence."},
        ],
        "freshness_rules": {
            "truth_freshness_windows_ref": TRUTH_FRESHNESS_WINDOWS_REL,
            "max_age_hours": freshness_windows,
            "current_head_match_required": True,
            "bounded_current_head_evidence_rule": "The imported WS13 CI diagnostic, keyless receipt, and signed-surface copy must agree on the same run_id and signed-surface SHA; no standalone wall-clock TTL is claimed for those imports beyond current-head binding.",
            "staleness_is_fail_closed": bool(freshness.get("staleness_is_fail_closed")),
        },
        "revocation_and_freeze_behavior": {
            "log_monitor_policy_ref": LOG_MONITOR_POLICY_REL,
            "log_monitor_receipt_ref": LOG_MONITOR_RECEIPT_REL,
            "current_log_monitor_state": str(log_monitor_receipt.get("freeze_state", "")).strip(),
            "freeze_scope": str(log_monitor_policy.get("freeze_behavior", {}).get("downstream_scope", "")).strip(),
            "freeze_on_any_high_or_critical_anomaly": bool(
                log_monitor_policy.get("freeze_behavior", {}).get("freeze_on_any_high_or_critical_anomaly")
            ),
            "anomaly_rules": anomaly_rules,
            "emergency_rotation_path_ref": TRUST_ROOT_POLICY_REL,
            "emergency_rotation_required_actions": list(trust_root_policy.get("emergency_rotation_path", {}).get("required_actions", [])),
            "emergency_rotation_triggers": list(trust_root_policy.get("emergency_rotation_path", {}).get("triggers", [])),
        },
        "private_secret_dependency_rules": {
            "forbidden_inputs": [
                "private signing keys",
                "HMAC or environment-secret trust material",
                "connected-host root material",
                "unpublished trust roots",
            ],
            "allowed_public_material_refs": [
                PUBLIC_KEY_REF,
                CI_SIGNED_SURFACE_REL,
                CI_KEYLESS_BUNDLE_REL,
                CI_KEYLESS_RECEIPT_REL,
                CI_TRUTH_DIAGNOSTIC_REL,
            ],
            "rule": "Declared verifier release surfaces must be verifiable from packaged public material only.",
        },
        "accepted_current_head_surface": {
            "signed_surface_import_ref": CI_SIGNED_SURFACE_REL,
            "signed_surface_sha256": str(keyless_receipt.get("signed_surface_sha256", "")).strip(),
            "keyless_execution_receipt_ref": CI_KEYLESS_RECEIPT_REL,
            "keyless_execution_run_id": str(keyless_receipt.get("run_id", "")).strip(),
            "truth_barrier_remote_diagnostic_ref": CI_TRUTH_DIAGNOSTIC_REL,
            "truth_barrier_remote_run_id": str(diagnostic.get("run_id", "")).strip(),
        },
        "verifier_artifact_reproducibility_class": {
            "artifact_ref": STATIC_RELEASE_MANIFEST_REL,
            "class_id": "CLASS_A_STATIC_JSON_CURRENT_HEAD",
            "enforced_by": "ws14_static_verifier_release_validate.py deterministic re-emit and stable SHA checks",
            "determinism_envelope_ref": "KT_PROD_CLEANROOM/governance/kt_determinism_envelope_policy.json",
        },
        "limitations": [
            "WS14 does not widen verifier trust-root acceptance beyond the bootstrap root.",
            "WS14 does not claim release-ceremony completion or release readiness.",
            "WS14 remains bounded to the imported WS13 current-head signed public verifier surface.",
            "The repo-root import fragility remains visible and is not erased by WS14.",
        ],
        "stronger_claim_not_made": [
            "Threshold-root verifier acceptance is active today",
            "All verifier surfaces are keyless-backed",
            "WS14 proves release ceremony completion",
        ],
    }


def build_distribution_policy(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.public_verifier_distribution_policy.v1",
        "policy_id": "KT_PUBLIC_VERIFIER_DISTRIBUTION_POLICY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "release_artifact_refs": [
            STATIC_RELEASE_MANIFEST_REL,
            STATIC_VERIFIER_SBOM_REL,
            STATIC_VERIFIER_ATTESTATION_REL,
            ACCEPTANCE_POLICY_REL,
            DISTRIBUTION_POLICY_REL,
        ],
        "packaged_public_evidence_refs": [
            CI_SIGNED_SURFACE_REL,
            CI_KEYLESS_BUNDLE_REL,
            CI_KEYLESS_RECEIPT_REL,
            CI_TRUTH_DIAGNOSTIC_REL,
            WS13_RECEIPT_REL,
        ],
        "allowed_distribution_channels": [
            "repo_snapshot_with_hash_bound_release_manifest",
            "static_zip_or_directory_bundle_with_packaged_public_evidence",
            "artifact_download_with_release_manifest_sha_verification",
        ],
        "forbidden_distribution_channels": [
            "mutable_network_fetch_without_hash_binding",
            "embedded_private_key_or_secret_material",
            "secret_backed_remote_verification",
            "implicit_self_update_without_acceptance_policy",
        ],
        "verification_entrypoint": "python -m tools.operator.public_verifier",
        "offline_verification_capable": True,
        "no_private_secret_dependency": True,
        "artifact_classes": [
            {"artifact_ref": STATIC_RELEASE_MANIFEST_REL, "class_id": "CLASS_A_STATIC_JSON_CURRENT_HEAD"},
            {"artifact_ref": STATIC_VERIFIER_SBOM_REL, "class_id": "CLASS_A_STATIC_JSON_CURRENT_HEAD"},
            {"artifact_ref": ACCEPTANCE_POLICY_REL, "class_id": "CLASS_A_STATIC_JSON_CURRENT_HEAD"},
            {"artifact_ref": DISTRIBUTION_POLICY_REL, "class_id": "CLASS_A_STATIC_JSON_CURRENT_HEAD"},
            {"artifact_ref": STATIC_VERIFIER_ATTESTATION_REL, "class_id": "CLASS_A_STATIC_JSON_CURRENT_HEAD_EVIDENCE_SUMMARY"},
            {"artifact_ref": CI_SIGNED_SURFACE_REL, "class_id": "CLASS_C_IMPORTED_CURRENT_HEAD_SIGNED_SURFACE"},
            {"artifact_ref": CI_KEYLESS_BUNDLE_REL, "class_id": "CLASS_C_IMPORTED_TRANSPARENCY_BUNDLE"},
        ],
        "limitations": [
            "Distribution remains bounded to static packaging and packaged public evidence only.",
            "WS14 does not define an auto-update fleet or release ceremony channel.",
            "WS14 does not change the runtime-surface class of KT_PROD_CLEANROOM/reports/public_verifier_manifest.json.",
        ],
    }


def _packaged_public_refs() -> List[str]:
    return [
        PUBLIC_VERIFIER_SOURCE_REL,
        PUBLIC_VERIFIER_CONTRACT_REL,
        PUBLIC_VERIFIER_RULES_REL,
        ACCEPTANCE_POLICY_REL,
        DISTRIBUTION_POLICY_REL,
        SIGNER_IDENTITY_POLICY_REL,
        SUPPLY_CHAIN_LAYOUT_REL,
        TRUTH_FRESHNESS_WINDOWS_REL,
        LOG_MONITOR_POLICY_REL,
        LOG_MONITOR_RECEIPT_REL,
        TUF_ROOT_INITIALIZATION_REL,
        PUBLIC_KEY_REF,
        CI_SIGNED_SURFACE_REL,
        CI_KEYLESS_BUNDLE_REL,
        CI_KEYLESS_RECEIPT_REL,
        CI_TRUTH_DIAGNOSTIC_REL,
        WS13_RECEIPT_REL,
    ]


def _secret_public_ref_failures(root: Path, refs: Sequence[str]) -> List[str]:
    failures: List[str] = []
    for rel in refs:
        posix_rel = str(Path(rel).as_posix())
        if any(token in posix_rel.lower() for token in FORBIDDEN_SECRET_PATH_PATTERNS):
            failures.append(f"secret_path:{posix_rel}")
            continue
        if not (root / Path(rel)).exists():
            failures.append(f"missing_public_ref:{posix_rel}")
    return sorted(set(failures))


def _artifact_components(root: Path, dependency_closure: Sequence[str]) -> List[Dict[str, Any]]:
    refs: List[Tuple[str, str, str]] = []
    refs.extend((rel, "source", "verifier_dependency") for rel in dependency_closure)
    refs.extend(
        [
            (PUBLIC_VERIFIER_CONTRACT_REL, "policy", "verifier_contract"),
            (PUBLIC_VERIFIER_RULES_REL, "policy", "verifier_rules"),
            (ACCEPTANCE_POLICY_REL, "policy", "acceptance_policy"),
            (DISTRIBUTION_POLICY_REL, "policy", "distribution_policy"),
            (SIGNER_IDENTITY_POLICY_REL, "policy", "signer_identity_policy"),
            (SUPPLY_CHAIN_LAYOUT_REL, "policy", "predicate_layout"),
            (TRUTH_FRESHNESS_WINDOWS_REL, "policy", "freshness_policy"),
            (LOG_MONITOR_POLICY_REL, "policy", "log_monitor_policy"),
            (LOG_MONITOR_RECEIPT_REL, "evidence", "log_monitor_receipt"),
            (TUF_ROOT_INITIALIZATION_REL, "trust_root", "bootstrap_root"),
            (PUBLIC_KEY_REF, "trust_root", "historical_cosign_public_key"),
            (CI_SIGNED_SURFACE_REL, "evidence", "bounded_signed_surface_copy"),
            (CI_KEYLESS_BUNDLE_REL, "evidence", "bounded_sigstore_bundle"),
            (CI_KEYLESS_RECEIPT_REL, "evidence", "bounded_keyless_receipt"),
            (CI_TRUTH_DIAGNOSTIC_REL, "evidence", "bounded_truth_diagnostic"),
            (WS13_RECEIPT_REL, "evidence", "ws13_boundary_receipt"),
        ]
    )
    return [_component(root, rel, component_type=component_type, role=role) for rel, component_type, role in refs]


def build_static_release_manifest(*, root: Path, current_head: str, dependency_closure: Sequence[str]) -> Dict[str, Any]:
    ws13_receipt = _load_required_json(root, WS13_RECEIPT_REL)
    keyless_receipt = _load_required_json(root, CI_KEYLESS_RECEIPT_REL)
    diagnostic = _load_required_json(root, CI_TRUTH_DIAGNOSTIC_REL)
    return {
        "schema_id": "kt.operator.static_verifier_release_manifest.v1",
        "artifact_id": Path(STATIC_RELEASE_MANIFEST_REL).name,
        "status": "PASS",
        "scope": "ws14_static_verifier_release",
        "current_repo_head": current_head,
        "ws13_subject_head_commit": str(ws13_receipt.get("compiled_against", "")).strip(),
        "verifier_entrypoint": "python -m tools.operator.public_verifier",
        "verifier_contract_ref": PUBLIC_VERIFIER_CONTRACT_REL,
        "verifier_rules_ref": PUBLIC_VERIFIER_RULES_REL,
        "acceptance_policy_ref": ACCEPTANCE_POLICY_REL,
        "distribution_policy_ref": DISTRIBUTION_POLICY_REL,
        "dependency_closure": list(dependency_closure),
        "packaged_components": _artifact_components(root, dependency_closure),
        "accepted_current_head_surface": {
            "signed_surface_import_ref": CI_SIGNED_SURFACE_REL,
            "signed_surface_sha256": str(keyless_receipt.get("signed_surface_sha256", "")).strip(),
            "keyless_bundle_ref": CI_KEYLESS_BUNDLE_REL,
            "keyless_bundle_sha256": file_sha256((root / Path(CI_KEYLESS_BUNDLE_REL)).resolve()),
            "keyless_execution_receipt_ref": CI_KEYLESS_RECEIPT_REL,
            "keyless_execution_run_id": str(keyless_receipt.get("run_id", "")).strip(),
            "truth_barrier_diagnostic_ref": CI_TRUTH_DIAGNOSTIC_REL,
            "truth_barrier_run_id": str(diagnostic.get("run_id", "")).strip(),
        },
        "reproducibility_class": "CLASS_A_STATIC_JSON_CURRENT_HEAD",
        "limitations": [
            "The packaged signed surface is a bounded imported copy, not a claim that the mutable runtime verifier manifest is globally reproducible.",
            "Threshold-root acceptance remains pending.",
            "Release readiness remains unproven.",
        ],
        "stronger_claim_not_made": [
            "All verifier surfaces are keyless-backed",
            "Threshold-root verifier acceptance is active",
            "Release ceremony completion is proven",
        ],
    }


def build_static_verifier_sbom(*, root: Path, current_head: str, dependency_closure: Sequence[str]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.static_verifier_sbom.v1",
        "artifact_id": Path(STATIC_VERIFIER_SBOM_REL).name,
        "status": "PASS",
        "scope": "ws14_static_verifier_release",
        "current_repo_head": current_head,
        "component_count": len(_artifact_components(root, dependency_closure)),
        "components": _artifact_components(root, dependency_closure),
        "reproducibility_class": "CLASS_A_STATIC_JSON_CURRENT_HEAD",
    }


def build_static_verifier_attestation(*, root: Path, current_head: str) -> Dict[str, Any]:
    acceptance_policy = _load_required_json(root, ACCEPTANCE_POLICY_REL)
    distribution_policy = _load_required_json(root, DISTRIBUTION_POLICY_REL)
    keyless_receipt = _load_required_json(root, CI_KEYLESS_RECEIPT_REL)
    diagnostic = _load_required_json(root, CI_TRUTH_DIAGNOSTIC_REL)
    log_monitor_receipt = _load_required_json(root, LOG_MONITOR_RECEIPT_REL)
    return {
        "schema_id": "kt.operator.static_verifier_attestation.v1",
        "artifact_id": Path(STATIC_VERIFIER_ATTESTATION_REL).name,
        "status": "PASS",
        "scope": "ws14_static_verifier_release",
        "current_repo_head": current_head,
        "accepted_bootstrap_root_id": str(acceptance_policy.get("accepted_verifier_trust_roots", [{}])[0].get("trust_root_id", "")).strip(),
        "pending_threshold_root_id": str(acceptance_policy.get("pending_not_yet_accepted_trust_roots", [{}])[0].get("trust_root_id", "")).strip(),
        "accepted_predicate_versions": acceptance_policy.get("accepted_predicate_versions", []),
        "accepted_schema_versions": acceptance_policy.get("accepted_schema_versions", []),
        "freshness_rules": acceptance_policy.get("freshness_rules", {}),
        "revocation_and_freeze_behavior": acceptance_policy.get("revocation_and_freeze_behavior", {}),
        "keyless_execution_run_id": str(keyless_receipt.get("run_id", "")).strip(),
        "keyless_signed_surface_sha256": str(keyless_receipt.get("signed_surface_sha256", "")).strip(),
        "truth_barrier_run_id": str(diagnostic.get("run_id", "")).strip(),
        "log_monitor_state": str(log_monitor_receipt.get("freeze_state", "")).strip(),
        "distribution_policy_summary": {
            "offline_verification_capable": bool(distribution_policy.get("offline_verification_capable")),
            "no_private_secret_dependency": bool(distribution_policy.get("no_private_secret_dependency")),
            "allowed_distribution_channels": list(distribution_policy.get("allowed_distribution_channels", [])),
        },
        "reproducibility_class": "CLASS_A_STATIC_JSON_CURRENT_HEAD_EVIDENCE_SUMMARY",
        "limitations": [
            "This attestation summarizes imported current-head keyless evidence; it does not make the imported evidence itself reproducible.",
            "Verifier acceptance remains bootstrap-root only.",
            "Release readiness remains unproven.",
        ],
    }


def _emission_hashes(root: Path) -> Dict[str, str]:
    return {
        ACCEPTANCE_POLICY_REL: file_sha256((root / Path(ACCEPTANCE_POLICY_REL)).resolve()),
        DISTRIBUTION_POLICY_REL: file_sha256((root / Path(DISTRIBUTION_POLICY_REL)).resolve()),
        STATIC_RELEASE_MANIFEST_REL: file_sha256((root / Path(STATIC_RELEASE_MANIFEST_REL)).resolve()),
        STATIC_VERIFIER_SBOM_REL: file_sha256((root / Path(STATIC_VERIFIER_SBOM_REL)).resolve()),
        STATIC_VERIFIER_ATTESTATION_REL: file_sha256((root / Path(STATIC_VERIFIER_ATTESTATION_REL)).resolve()),
    }


def _stable_emission_matches(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Tuple[bool, List[str]]:
    failures: List[str] = []
    for rel, payload in payloads.items():
        on_disk = file_sha256((root / Path(rel)).resolve())
        rendered = hashlib.sha256(_render_stable_json(payload).encode("utf-8")).hexdigest()
        if on_disk != rendered:
            failures.append(f"sha_mismatch:{rel}")
    return not failures, failures


def build_ws14_receipt(
    *,
    root: Path,
    current_head: str,
    generated_utc: str,
    ws13_receipt: Dict[str, Any],
    acceptance_policy: Dict[str, Any],
    distribution_policy: Dict[str, Any],
    release_manifest: Dict[str, Any],
    verifier_sbom: Dict[str, Any],
    verifier_attestation: Dict[str, Any],
    dependency_closure: Sequence[str],
) -> Dict[str, Any]:
    keyless_status = _load_required_json(root, KEYLESS_STATUS_REL)
    log_monitor_receipt = _load_required_json(root, LOG_MONITOR_RECEIPT_REL)
    ws13_pass = str(ws13_receipt.get("status", "")).strip() == "PASS"
    ws13_head = str(ws13_receipt.get("compiled_against", "")).strip()
    ws13_boundary_preserved = bool(ws13_head) and ws13_head == current_head and _git_is_ancestor(root, ws13_head, current_head)
    current_surface_ok, current_surface_failures = _surface_check_pass(root, _load_ws13_inputs(root))
    dependency_failures = _release_dependency_failures(dependency_closure)
    public_ref_failures = _secret_public_ref_failures(root, _packaged_public_refs())
    bootstrap_roots = acceptance_policy.get("accepted_verifier_trust_roots") if isinstance(acceptance_policy.get("accepted_verifier_trust_roots"), list) else []
    pending_roots = acceptance_policy.get("pending_not_yet_accepted_trust_roots") if isinstance(acceptance_policy.get("pending_not_yet_accepted_trust_roots"), list) else []
    bootstrap_root_ok = len(bootstrap_roots) == 1 and str(bootstrap_roots[0].get("acceptance_state", "")).strip() == "ACTIVE_BOOTSTRAP_ACCEPTED"
    threshold_root_pending = len(pending_roots) == 1 and str(pending_roots[0].get("acceptance_state", "")).strip() == "PENDING_LATER_ACCEPTANCE_UPDATE"
    predicate_versions_explicit = bool(acceptance_policy.get("accepted_predicate_versions")) and bool(
        acceptance_policy.get("accepted_schema_versions")
    )
    freshness_rules = acceptance_policy.get("freshness_rules") if isinstance(acceptance_policy.get("freshness_rules"), dict) else {}
    freshness_explicit = bool(freshness_rules.get("current_head_match_required")) and bool(
        freshness_rules.get("bounded_current_head_evidence_rule")
    )
    revocation_rules = acceptance_policy.get("revocation_and_freeze_behavior") if isinstance(acceptance_policy.get("revocation_and_freeze_behavior"), dict) else {}
    revocation_explicit = bool(revocation_rules.get("log_monitor_policy_ref")) and bool(
        revocation_rules.get("emergency_rotation_path_ref")
    )
    secret_free_declared = bool(distribution_policy.get("no_private_secret_dependency")) and bool(
        acceptance_policy.get("private_secret_dependency_rules", {}).get("forbidden_inputs")
    )
    reproducibility_declared = (
        str(release_manifest.get("reproducibility_class", "")).strip() == "CLASS_A_STATIC_JSON_CURRENT_HEAD"
        and str(verifier_sbom.get("reproducibility_class", "")).strip() == "CLASS_A_STATIC_JSON_CURRENT_HEAD"
        and str(verifier_attestation.get("reproducibility_class", "")).strip() == "CLASS_A_STATIC_JSON_CURRENT_HEAD_EVIDENCE_SUMMARY"
    )
    stable_ok, stable_failures = _stable_emission_matches(
        root,
        {
            ACCEPTANCE_POLICY_REL: acceptance_policy,
            DISTRIBUTION_POLICY_REL: distribution_policy,
            STATIC_RELEASE_MANIFEST_REL: release_manifest,
            STATIC_VERIFIER_SBOM_REL: verifier_sbom,
            STATIC_VERIFIER_ATTESTATION_REL: verifier_attestation,
        },
    )
    keyless_status_pass = str(keyless_status.get("status", "")).strip() == "PASS"
    log_monitor_pass = str(log_monitor_receipt.get("status", "")).strip() == "PASS"

    blockers: List[str] = []
    if not ws13_pass:
        blockers.append("WS13_NOT_PASS")
    if not ws13_boundary_preserved:
        blockers.append("WS13_SUBJECT_HEAD_NOT_PRESERVED")
    if not current_surface_ok:
        blockers.append("DECLARED_CURRENT_HEAD_KEYLESS_SURFACE_NOT_PROVEN")
    if not keyless_status_pass:
        blockers.append("KEYLESS_STATUS_NOT_PASS")
    if not log_monitor_pass:
        blockers.append("LOG_MONITOR_NOT_PASS")
    if dependency_failures:
        blockers.append("STATIC_VERIFIER_DEPENDENCY_BOUNDARY_VIOLATED")
    if public_ref_failures:
        blockers.append("PUBLIC_VERIFIER_RELEASE_CONTAINS_SECRET_OR_MISSING_PUBLIC_INPUT")
    if not bootstrap_root_ok or not threshold_root_pending:
        blockers.append("VERIFIER_TRUST_ROOT_ACCEPTANCE_BOUNDARY_NOT_EXPLICIT")
    if not predicate_versions_explicit:
        blockers.append("VERIFIER_PREDICATE_OR_SCHEMA_VERSIONS_NOT_EXPLICIT")
    if not freshness_explicit or not revocation_explicit:
        blockers.append("VERIFIER_FRESHNESS_OR_REVOCATION_RULES_NOT_EXPLICIT")
    if not secret_free_declared:
        blockers.append("PRIVATE_SECRET_FREE_VERIFICATION_NOT_ENFORCED")
    if not reproducibility_declared or not stable_ok:
        blockers.append("STATIC_VERIFIER_REPRODUCIBILITY_CLASS_NOT_ENFORCED")

    status = "PASS" if not blockers else "PARTIAL"
    next_lawful = WS15_ID if status == "PASS" else WORKSTREAM_ID
    checks = [
        _check(ws13_pass, "ws13_receipt_pass", "WS13 must already be PASS before WS14 can lock verifier release and acceptance policy.", [WS13_RECEIPT_REL]),
        _check(
            ws13_boundary_preserved,
            "ws13_subject_head_preserved",
            "WS14 must preserve the frozen WS13 subject head while packaging the static verifier release.",
            [WS13_RECEIPT_REL, EXECUTION_DAG_REL],
            failures=[] if ws13_boundary_preserved else [f"current_head={current_head}", f"ws13_head={ws13_head}"],
        ),
        _check(
            current_surface_ok,
            "declared_current_head_keyless_surface_proven",
            "The imported current-head signed verifier surface, keyless receipt, and Sigstore bundle must agree on the same bounded WS11 surface.",
            [CI_SIGNED_SURFACE_REL, CI_KEYLESS_RECEIPT_REL, CI_KEYLESS_BUNDLE_REL, CI_TRUTH_DIAGNOSTIC_REL],
            failures=current_surface_failures,
        ),
        _check(
            keyless_status_pass,
            "keyless_status_receipt_pass",
            "The prior WS11 keyless status receipt must remain PASS while WS14 packages the static verifier release.",
            [KEYLESS_STATUS_REL],
        ),
        _check(
            log_monitor_pass,
            "log_monitor_plane_pass",
            "The log monitor plane must remain PASS while WS14 publishes verifier acceptance and revocation behavior.",
            [LOG_MONITOR_RECEIPT_REL, LOG_MONITOR_POLICY_REL],
        ),
        _check(
            not dependency_failures,
            "static_verifier_dependency_closure_within_allowed_roots",
            "Static verifier source closure must remain inside operator/canonicalize/verification helper roots and avoid forbidden runtime paths.",
            dependency_closure,
            failures=dependency_failures,
        ),
        _check(
            not public_ref_failures,
            "packaged_public_inputs_secret_free_and_present",
            "Packaged verifier release inputs must be public, present, and free of secret/HMAC/private path dependencies.",
            _packaged_public_refs(),
            failures=public_ref_failures,
        ),
        _check(
            bootstrap_root_ok,
            "bootstrap_root_only_acceptance_locked",
            "WS14 must explicitly accept only the bootstrap verifier trust root and must not silently widen threshold-root acceptance.",
            [ACCEPTANCE_POLICY_REL, TUF_ROOT_INITIALIZATION_REL, TRUST_ROOT_POLICY_REL],
        ),
        _check(
            threshold_root_pending,
            "threshold_root_acceptance_still_pending",
            "Threshold-root acceptance must remain pending after WS14 until a later explicit acceptance bundle is published.",
            [ACCEPTANCE_POLICY_REL, TRUST_ROOT_POLICY_REL],
        ),
        _check(
            predicate_versions_explicit,
            "accepted_predicate_and_schema_versions_explicit",
            "WS14 must lock accepted predicate versions and schema versions for declared verifier surfaces.",
            [ACCEPTANCE_POLICY_REL, SUPPLY_CHAIN_LAYOUT_REL],
        ),
        _check(
            freshness_explicit and revocation_explicit,
            "freshness_and_revocation_behavior_explicit",
            "WS14 must lock freshness, anomaly, freeze, and revocation handling for declared verifier surfaces.",
            [ACCEPTANCE_POLICY_REL, TRUTH_FRESHNESS_WINDOWS_REL, LOG_MONITOR_POLICY_REL, TRUST_ROOT_POLICY_REL],
        ),
        _check(
            secret_free_declared,
            "private_secret_dependency_forbidden",
            "WS14 must forbid private-secret dependency for the declared verifier release surfaces.",
            [ACCEPTANCE_POLICY_REL, DISTRIBUTION_POLICY_REL],
        ),
        _check(
            reproducibility_declared and stable_ok,
            "verifier_release_reproducibility_class_declared_and_enforced",
            "The static verifier release artifact set must declare and stably emit its reproducibility class without silently normalizing imported CLASS_C evidence into deterministic artifacts.",
            [STATIC_RELEASE_MANIFEST_REL, STATIC_VERIFIER_SBOM_REL, STATIC_VERIFIER_ATTESTATION_REL, ACCEPTANCE_POLICY_REL, DISTRIBUTION_POLICY_REL],
            failures=stable_failures,
        ),
    ]
    return {
        "artifact_id": Path(RECEIPT_REL).name,
        "blocked_by": blockers,
        "checks": checks,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "current_strongest_claim": (
            "WS14 defines a bounded static verifier release artifact set and explicit verifier acceptance/distribution policy for bootstrap-root-only verification of the imported current-head keyless public verifier manifest surface."
            if status == "PASS"
            else "WS14 has defined some static verifier release or acceptance-policy structure, but the bounded current-head verification or bootstrap-only acceptance boundary remains incomplete."
        ),
        "generated_utc": generated_utc,
        "limitations": [
            "WS14 does not widen verifier trust-root acceptance beyond the bootstrap root.",
            "WS14 remains bounded to the imported WS13 current-head signed public verifier manifest surface only.",
            "WS14 does not prove release readiness, release ceremony completion, or broader verifier coverage.",
            "The repo-root import fragility remains visible and is not erased by WS14.",
        ],
        "next_lawful_workstream": next_lawful,
        "pass_verdict": PASS_VERDICT if status == "PASS" else PARTIAL_VERDICT,
        "release_artifact_hashes": _emission_hashes(root),
        "reproducibility_class": {
            "acceptance_policy": "CLASS_A_STATIC_JSON_CURRENT_HEAD",
            "distribution_policy": "CLASS_A_STATIC_JSON_CURRENT_HEAD",
            "static_release_manifest": "CLASS_A_STATIC_JSON_CURRENT_HEAD",
            "static_verifier_sbom": "CLASS_A_STATIC_JSON_CURRENT_HEAD",
            "static_verifier_attestation": "CLASS_A_STATIC_JSON_CURRENT_HEAD_EVIDENCE_SUMMARY",
            "packaged_imported_evidence": "CLASS_C_IMPORTED_CURRENT_HEAD_EVIDENCE",
        },
        "schema_id": "kt.operator.public_verifier_release_receipt.v1",
        "status": status,
        "step_id": STEP_ID,
        "stronger_claim_not_made": [
            "Threshold-root verifier acceptance is active",
            "All verifier surfaces are keyless-backed",
            "WS14 proves release ceremony completion or product readiness",
        ],
        "tests_run": ["python -m pytest -q tests/operator/test_ws14_static_verifier_release_validate.py"],
        "validators_run": ["python -m tools.operator.ws14_static_verifier_release_validate"],
        "workstream_id": WORKSTREAM_ID,
    }


def _apply_control_plane(*, dag: Dict[str, Any], trust_root_policy: Dict[str, Any], signer_topology: Dict[str, Any], receipt: Dict[str, Any]) -> None:
    generated_utc = str(receipt.get("generated_utc", "")).strip()
    current_head = str(receipt.get("current_repo_head", "")).strip()
    ws14_pass = str(receipt.get("status", "")).strip() == "PASS"

    dag["generated_utc"] = generated_utc
    dag["current_repo_head"] = current_head
    dag["current_node"] = receipt["next_lawful_workstream"]
    dag["next_lawful_workstream"] = receipt["next_lawful_workstream"]
    dag["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. WS12 passed for bounded current-head supply-chain policy. WS13 passed for bounded artifact-class locking and determinism proof across local Windows and GitHub Actions Ubuntu on the same subject head. WS14 now packages a bounded static verifier release and acceptance policy without widening bootstrap-root verifier acceptance."
        if ws14_pass
        else "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. WS12 passed for bounded current-head supply-chain policy. WS13 passed for bounded artifact-class locking and determinism proof. WS14 remains current until the bounded static verifier release and acceptance-policy proof is complete."
    )
    dag["semantic_boundary"]["stronger_claim_not_made"] = [
        "The original planned 3-of-5 root topology was executed",
        "Threshold-root verifier acceptance is active",
        "Release readiness is proven",
        "WS15 has already been substantively started",
    ]
    ws14_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws15_node = next(node for node in dag["nodes"] if node["id"] == WS15_ID)
    if ws14_pass:
        ws14_node["status"] = "PASS"
        ws14_node["claim_boundary"] = "WS14 PASS proves only the bounded static verifier release artifact set and acceptance/distribution policy for the imported current-head keyless public verifier manifest surface, with bootstrap-root-only verifier acceptance."
        ws15_node["status"] = "UNLOCKED"
        ws15_node["unlock_basis"] = "WS14 PASS"
    else:
        ws14_node["status"] = "PARTIAL"
        ws14_node["claim_boundary"] = "WS14 remains partial until the bounded static verifier release artifact set and bootstrap-only acceptance-policy proof are complete."
        ws15_node["status"] = "LOCKED_PENDING_WS14_PASS"
        ws15_node.pop("unlock_basis", None)

    trust_root_policy["generated_utc"] = generated_utc
    trust_root_policy["current_repo_head"] = current_head
    trust_root_policy["closure_boundary"]["next_required_step"] = receipt["next_lawful_workstream"]
    trust_root_policy["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 remains executed under the reratified 3-of-3 root boundary only. WS11, WS12, and WS13 remain bounded. WS14 now publishes bootstrap-root-only verifier acceptance and bounded static verifier release packaging without widening threshold-root acceptance."
        if ws14_pass
        else "WS10 remains executed under the reratified 3-of-3 root boundary only. WS11, WS12, and WS13 remain bounded. WS14 is current until bootstrap-only verifier acceptance and static verifier release packaging are sealed."
    )
    trust_root_policy["semantic_boundary"]["verifier_acceptance_upgraded"] = False
    impact = trust_root_policy.get("verifier_acceptance_impact")
    if isinstance(impact, dict):
        impact["current_acceptance_state"] = (
            "BOOTSTRAP_ROOT_ONLY_WITH_WS14_ACCEPTANCE_POLICY_PUBLISHED"
            if ws14_pass
            else "BOOTSTRAP_ROOT_ONLY_PENDING_WS14_ACCEPTANCE_POLICY"
        )
        impact["current_boundary"] = (
            "WS14 publishes verifier acceptance and distribution policy, but active accepted root remains the bootstrap root only; threshold-root acceptance is still pending a later explicit acceptance bundle."
            if ws14_pass
            else "Verifier acceptance remains bootstrap-root only until WS14 seals the acceptance policy."
        )
        impact["post_pass_target_state"] = "THRESHOLD_ROOT_ACCEPTANCE_STILL_PENDING_LATER_EXPLICIT_BUNDLE"

    signer_topology["generated_utc"] = generated_utc
    signer_topology["current_repo_head"] = current_head
    signer_topology["semantic_boundary"]["lawful_current_claim"] = (
        "Root signer topology remains executed and reratified as 3-of-3 only. WS14 adds bounded static verifier packaging and bootstrap-root-only acceptance policy without widening non-root signer issuance."
        if ws14_pass
        else "Root signer topology remains executed and reratified as 3-of-3 only. WS14 is current and no verifier or release authority widening is lawful yet."
    )
    verifier_impact = signer_topology.get("verifier_acceptance_impact")
    if isinstance(verifier_impact, dict):
        verifier_impact["post_ws11_and_ws14"] = (
            "WS14 completed acceptance-policy packaging only; verifier still consumes the bootstrap root until a later explicit threshold-root acceptance bundle is published."
            if ws14_pass
            else "Verifier continues to trust only the predecessor bootstrap root while WS14 remains incomplete."
        )


def emit_ws14_static_verifier_release(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or repo_root()
    pre_dirty = _dirty_relpaths(_git_status_lines(repo))
    if pre_dirty and any(not _path_in_scope(path) for path in pre_dirty):
        raise RuntimeError("FAIL_CLOSED: WS14 requires the repo to be frozen except for the preserved WS13 boundary and WS14 in-scope files")

    current_head = _git_head(repo)
    generated_utc = utc_now_iso_z()
    ws13_receipt = _load_required_json(repo, WS13_RECEIPT_REL)
    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    trust_root_policy = _load_required_json(repo, TRUST_ROOT_POLICY_REL)
    signer_topology = _load_required_json(repo, SIGNER_TOPOLOGY_REL)

    dependency_closure = _local_dependency_closure(repo, PUBLIC_VERIFIER_SOURCE_REL)
    acceptance_policy = build_acceptance_policy(root=repo, current_head=current_head)
    distribution_policy = build_distribution_policy(current_head=current_head)
    _write_json(repo, ACCEPTANCE_POLICY_REL, acceptance_policy)
    _write_json(repo, DISTRIBUTION_POLICY_REL, distribution_policy)

    release_manifest = build_static_release_manifest(root=repo, current_head=current_head, dependency_closure=dependency_closure)
    verifier_sbom = build_static_verifier_sbom(root=repo, current_head=current_head, dependency_closure=dependency_closure)
    verifier_attestation = build_static_verifier_attestation(root=repo, current_head=current_head)
    _write_json(repo, STATIC_RELEASE_MANIFEST_REL, release_manifest)
    _write_json(repo, STATIC_VERIFIER_SBOM_REL, verifier_sbom)
    _write_json(repo, STATIC_VERIFIER_ATTESTATION_REL, verifier_attestation)

    receipt = build_ws14_receipt(
        root=repo,
        current_head=current_head,
        generated_utc=generated_utc,
        ws13_receipt=ws13_receipt,
        acceptance_policy=acceptance_policy,
        distribution_policy=distribution_policy,
        release_manifest=release_manifest,
        verifier_sbom=verifier_sbom,
        verifier_attestation=verifier_attestation,
        dependency_closure=dependency_closure,
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
    parser = argparse.ArgumentParser(description="WS14: release the bounded static verifier artifact set and lock acceptance policy.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    receipt = emit_ws14_static_verifier_release(root=repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
