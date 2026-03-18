from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK"
STEP_ID = "WS13_STEP_1_LOCK_ARTIFACT_CLASSES_AND_PROVE_REPRODUCIBILITY"
PASS_VERDICT = "DECLARED_ARTIFACT_CLASSES_LOCKED_AND_CURRENT_HEAD_DRIFT_PROOF_SEALED"
PARTIAL_VERDICT = "ARTIFACT_CLASS_POLICY_PRESENT_BUT_CURRENT_HEAD_DRIFT_PROOF_INCOMPLETE"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"
WS13_DIR_REL = f"{REPORT_ROOT_REL}/ws13_determinism"
LOCAL_DIR_REL = f"{WS13_DIR_REL}/local"
CI_DIR_REL = f"{WS13_DIR_REL}/ci"

CLASS_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_artifact_class_policy.json"
ENVELOPE_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_determinism_envelope_policy.json"
EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
TRUST_ROOT_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_trust_root_policy.json"
SIGNER_TOPOLOGY_REL = f"{GOVERNANCE_ROOT_REL}/kt_signer_topology.json"
SIGNER_IDENTITY_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/signer_identity_policy.json"
WS12_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_supply_chain_policy_receipt.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_envelope_receipt.json"

CI_TRUTH_DIAGNOSTIC_REL = f"{CI_DIR_REL}/kt_truth_barrier_remote_diagnostic.json"
CI_KEYLESS_RECEIPT_REL = f"{CI_DIR_REL}/kt_ws11_keyless_execution_receipt.json"
CI_KEYLESS_BUNDLE_REL = f"{CI_DIR_REL}/public_verifier_manifest.sigstore.json"
CI_SIGNED_SURFACE_REL = f"{CI_DIR_REL}/public_verifier_manifest.json"

REGISTRY_FILENAME = "kt_artifact_class_registry.json"
ENVELOPE_FILENAME = "kt_determinism_envelope_manifest.json"
SUBJECT_SET_FILENAME = "kt_determinism_subject_set.json"
PROBE_FILENAME = "environment_probe.json"

PLANNED_MUTATES = [
    ".github/workflows/ci_truth_barrier.yml",
    CLASS_POLICY_REL,
    ENVELOPE_POLICY_REL,
    EXECUTION_DAG_REL,
    TRUST_ROOT_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    RECEIPT_REL,
    LOCAL_DIR_REL,
    CI_DIR_REL,
    "KT_PROD_CLEANROOM/tools/operator/ws13_determinism_envelope_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ws13_determinism_envelope_validate.py",
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


def _path_in_scope(path: str) -> bool:
    normalized = str(Path(path).as_posix()).rstrip("/")
    for allowed in PLANNED_MUTATES:
        allowed_norm = str(Path(allowed).as_posix()).rstrip("/")
        if normalized == allowed_norm or normalized.startswith(f"{allowed_norm}/") or allowed_norm.startswith(f"{normalized}/"):
            return True
    return False


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS13 input: {rel}")
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


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _canonical_sha(obj: Any) -> str:
    import hashlib

    return hashlib.sha256(_canonical_json_bytes(obj)).hexdigest()


def _read_required_env(envelope_policy: Dict[str, Any]) -> Dict[str, str]:
    values = envelope_policy.get("required_environment_variables")
    if not isinstance(values, dict):
        raise RuntimeError("FAIL_CLOSED: determinism envelope policy missing required environment variables")
    return {str(k): str(v) for k, v in values.items()}


def _actual_env(required: Dict[str, str]) -> Dict[str, str]:
    return {key: str(os.environ.get(key, "")) for key in sorted(required)}


def _env_matches(required: Dict[str, str], actual: Dict[str, str]) -> Tuple[bool, Dict[str, str]]:
    mismatches = {key: actual.get(key, "") for key, expected in required.items() if actual.get(key, "") != expected}
    return not mismatches, mismatches


def _find_supported_environment(envelope_policy: Dict[str, Any], *, environment_class: str, environment_provenance: str) -> Dict[str, Any]:
    classes = envelope_policy.get("supported_environment_classes")
    if not isinstance(classes, list):
        raise RuntimeError("FAIL_CLOSED: determinism envelope policy missing supported environment classes")
    for row in classes:
        if not isinstance(row, dict):
            continue
        if str(row.get("environment_class", "")).strip() == environment_class and str(row.get("environment_provenance", "")).strip() == environment_provenance:
            return row
    raise RuntimeError(f"FAIL_CLOSED: unsupported WS13 environment class/provenance: {environment_class}/{environment_provenance}")


def _python_major_minor() -> str:
    return f"{platform.python_version_tuple()[0]}.{platform.python_version_tuple()[1]}"


def _environment_probe(*, current_head: str, environment_id: str, environment_class: str, environment_provenance: str, live_validation_index_rel: str, envelope_policy: Dict[str, Any]) -> Dict[str, Any]:
    required = _read_required_env(envelope_policy)
    actual = _actual_env(required)
    matched, mismatches = _env_matches(required, actual)
    supported = _find_supported_environment(envelope_policy, environment_class=environment_class, environment_provenance=environment_provenance)
    return {
        "artifact_id": PROBE_FILENAME,
        "environment_class": environment_class,
        "environment_id": environment_id,
        "environment_provenance": environment_provenance,
        "live_validation_index_path": str(Path(live_validation_index_rel).as_posix()),
        "platform": platform.platform(),
        "platform_prefix_expected": str(supported.get("platform_prefix", "")),
        "policy_env_match": matched,
        "policy_env_mismatches": mismatches,
        "python_implementation": platform.python_implementation(),
        "python_major_minor": _python_major_minor(),
        "python_major_minor_expected": str(supported.get("python_major_minor", "")),
        "python_version": platform.python_version(),
        "required_environment_variables": actual,
        "schema_id": "kt.operator.ws13.environment_probe.v1",
        "subject_head_commit": current_head,
    }


def _canonicalize_live_validation_index(index: Dict[str, Any]) -> Dict[str, Any]:
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    checks: List[Dict[str, Any]] = []
    raw_checks = index.get("checks") if isinstance(index.get("checks"), list) else []
    for row in raw_checks:
        if not isinstance(row, dict):
            continue
        checks.append(
            {
                "check_id": str(row.get("check_id", "")).strip(),
                "critical": bool(row.get("critical")),
                "scope": str(row.get("scope", "")).strip(),
                "status": str(row.get("status", "")).strip(),
                "summary": str(row.get("summary", "")).strip(),
            }
        )
    checks.sort(key=lambda row: row["check_id"])
    return {
        "checks": checks,
        "logical_surface": "current_truth_barrier_live_validation_index",
        "schema_id": "kt.operator.ws13.live_validation_index_canonical.v1",
        "worktree": {
            "git_dirty": bool(worktree.get("git_dirty")),
            "head_sha": str(worktree.get("head_sha", "")).strip(),
        },
    }


def _truth_index_current_head_pass(index: Dict[str, Any], *, current_head: str) -> bool:
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    checks = index.get("checks") if isinstance(index.get("checks"), list) else []
    critical_failures = [
        row
        for row in checks
        if isinstance(row, dict)
        and bool(row.get("critical"))
        and str(row.get("status", "")).strip() not in {"PASS", "SKIP"}
    ]
    return (
        str(worktree.get("head_sha", "")).strip() == current_head
        and not bool(worktree.get("git_dirty"))
        and not critical_failures
    )


def _surface_map_by_class(class_policy: Dict[str, Any], class_id: str) -> List[Dict[str, Any]]:
    classes = class_policy.get("classes") if isinstance(class_policy.get("classes"), list) else []
    for row in classes:
        if isinstance(row, dict) and str(row.get("class_id", "")).strip() == class_id:
            surfaces = row.get("surfaces")
            if not isinstance(surfaces, list):
                raise RuntimeError(f"FAIL_CLOSED: {class_id} missing surfaces list")
            return [surface for surface in surfaces if isinstance(surface, dict)]
    raise RuntimeError(f"FAIL_CLOSED: missing {class_id} in artifact class policy")


def build_artifact_class_registry(*, current_head: str, class_policy: Dict[str, Any], envelope_policy: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "artifact_classes": class_policy.get("classes", []),
        "artifact_id": REGISTRY_FILENAME,
        "determinism_envelope_policy_ref": ENVELOPE_POLICY_REL,
        "schema_id": "kt.operator.ws13.artifact_class_registry.v1",
        "subject_head_commit": current_head,
        "supported_environment_classes": envelope_policy.get("supported_environment_classes", []),
    }


def build_determinism_envelope_manifest(*, current_head: str, envelope_policy: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "artifact_id": ENVELOPE_FILENAME,
        "canonicalization_profiles": envelope_policy.get("class_b_canonicalization_profiles", []),
        "dependency_model": envelope_policy.get("deterministic_emitter_dependency_model", {}),
        "forbidden_drift": envelope_policy.get("forbidden_drift", []),
        "normalization_rules": envelope_policy.get("normalization_rules", {}),
        "required_environment_variables": envelope_policy.get("required_environment_variables", {}),
        "schema_id": "kt.operator.ws13.determinism_envelope_manifest.v1",
        "subject_head_commit": current_head,
        "supported_environment_classes": envelope_policy.get("supported_environment_classes", []),
        "truth_barrier_dependency_pins": envelope_policy.get("truth_barrier_dependency_pins", {}),
    }


def build_subject_set(
    *,
    root: Path,
    current_head: str,
    class_policy: Dict[str, Any],
    live_validation_index: Dict[str, Any],
    registry: Dict[str, Any],
    envelope_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    class_a_rows: List[Dict[str, str]] = []
    for surface in _surface_map_by_class(class_policy, "CLASS_A"):
        rel = str(surface.get("path", "")).strip()
        if not rel:
            raise RuntimeError("FAIL_CLOSED: CLASS_A surface missing path")
        class_a_rows.append(
            {
                "path": rel,
                "sha256": file_sha256((root / Path(rel)).resolve()),
                "surface_id": str(surface.get("surface_id", "")).strip(),
            }
        )
    class_a_rows.sort(key=lambda row: row["surface_id"])
    return {
        "artifact_id": SUBJECT_SET_FILENAME,
        "class_a_raw_sha256": class_a_rows,
        "class_b_canonical_sha256": {
            "canonical_hash": _canonical_sha(_canonicalize_live_validation_index(live_validation_index)),
            "canonicalization_profile_id": "live_validation_index_v1",
            "surface_id": "current_truth_barrier_live_validation_index",
        },
        "generated_class_a_sha256": {
            ENVELOPE_FILENAME: _canonical_sha(envelope_manifest),
            REGISTRY_FILENAME: _canonical_sha(registry),
        },
        "schema_id": "kt.operator.ws13.determinism_subject_set.v1",
        "subject_head_commit": current_head,
    }


def emit_environment_bundle(
    *,
    root: Path,
    out_dir_rel: str,
    environment_id: str,
    environment_class: str,
    environment_provenance: str,
    live_validation_index_rel: str,
) -> Dict[str, Any]:
    current_head = _git_head(root)
    class_policy = _load_required_json(root, CLASS_POLICY_REL)
    envelope_policy = _load_required_json(root, ENVELOPE_POLICY_REL)
    live_validation_index = _load_required_json(root, live_validation_index_rel)

    probe = _environment_probe(
        current_head=current_head,
        environment_id=environment_id,
        environment_class=environment_class,
        environment_provenance=environment_provenance,
        live_validation_index_rel=live_validation_index_rel,
        envelope_policy=envelope_policy,
    )
    registry = build_artifact_class_registry(current_head=current_head, class_policy=class_policy, envelope_policy=envelope_policy)
    envelope_manifest = build_determinism_envelope_manifest(current_head=current_head, envelope_policy=envelope_policy)
    subject_set = build_subject_set(
        root=root,
        current_head=current_head,
        class_policy=class_policy,
        live_validation_index=live_validation_index,
        registry=registry,
        envelope_manifest=envelope_manifest,
    )

    out_dir = (root / Path(out_dir_rel)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json_stable(out_dir / PROBE_FILENAME, probe)
    write_json_stable(out_dir / REGISTRY_FILENAME, registry)
    write_json_stable(out_dir / ENVELOPE_FILENAME, envelope_manifest)
    write_json_stable(out_dir / SUBJECT_SET_FILENAME, subject_set)
    return {"environment_probe": probe, "registry": registry, "subject_set": subject_set}


def _load_bundle(root: Path, dir_rel: str) -> Dict[str, Any]:
    return {
        "probe": _load_required_json(root, f"{dir_rel}/{PROBE_FILENAME}"),
        "registry": _load_required_json(root, f"{dir_rel}/{REGISTRY_FILENAME}"),
        "envelope": _load_required_json(root, f"{dir_rel}/{ENVELOPE_FILENAME}"),
        "subject_set": _load_required_json(root, f"{dir_rel}/{SUBJECT_SET_FILENAME}"),
    }


def _probe_matches_policy(probe: Dict[str, Any], envelope_policy: Dict[str, Any]) -> bool:
    supported = _find_supported_environment(
        envelope_policy,
        environment_class=str(probe.get("environment_class", "")).strip(),
        environment_provenance=str(probe.get("environment_provenance", "")).strip(),
    )
    return (
        bool(probe.get("policy_env_match"))
        and str(probe.get("python_major_minor", "")).strip() == str(supported.get("python_major_minor", "")).strip()
        and str(probe.get("platform", "")).startswith(str(supported.get("platform_prefix", "")).strip())
    )


def _ci_keyless_pass(root: Path, signer_identity_policy: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], Dict[str, Any]]:
    diagnostic = _load_required_json(root, CI_TRUTH_DIAGNOSTIC_REL)
    receipt = _load_required_json(root, CI_KEYLESS_RECEIPT_REL)
    bundle_path = (root / Path(CI_KEYLESS_BUNDLE_REL)).resolve()
    signed_surface_path = (root / Path(CI_SIGNED_SURFACE_REL)).resolve()
    expected_identity = str(signer_identity_policy.get("keyless_constraints", {}).get("certificate_identity", "")).strip()
    expected_issuer = str(signer_identity_policy.get("keyless_constraints", {}).get("certificate_oidc_issuer", "")).strip()
    ok = (
        str(diagnostic.get("status", "")).strip() == "PASS"
        and str(diagnostic.get("truth_barrier_step_outcome", "")).strip() == "success"
        and str(receipt.get("status", "")).strip() == "PASS"
        and str(receipt.get("verification_status", "")).strip() == "PASS"
        and str(receipt.get("executed_signer_mode", "")).strip() == "sigstore_keyless"
        and str(receipt.get("signed_surface_path", "")).strip() == PUBLIC_VERIFIER_MANIFEST_REL
        and signed_surface_path.exists()
        and str(receipt.get("signed_surface_sha256", "")).strip().lower() == file_sha256(signed_surface_path).lower()
        and bundle_path.exists()
        and str(receipt.get("certificate_identity", "")).strip() == expected_identity
        and str(receipt.get("certificate_oidc_issuer", "")).strip() == expected_issuer
        and str(diagnostic.get("run_id", "")).strip() == str(receipt.get("run_id", "")).strip()
        and str(receipt.get("branch_ref", "")).strip().endswith("/main")
    )
    return ok, diagnostic, receipt


def build_ws13_receipt(
    *,
    root: Path,
    current_head: str,
    generated_utc: str,
    ws12_receipt: Dict[str, Any],
    class_policy: Dict[str, Any],
    envelope_policy: Dict[str, Any],
    signer_identity_policy: Dict[str, Any],
    local_bundle: Dict[str, Any],
    ci_bundle: Dict[str, Any],
) -> Dict[str, Any]:
    ws12_pass = str(ws12_receipt.get("status", "")).strip() == "PASS"
    local_truth_index = _load_required_json(root, f"{LOCAL_DIR_REL}/live_validation_index.local.json")
    ci_truth_index = _load_required_json(root, f"{CI_DIR_REL}/live_validation_index.ci.json")
    local_truth_pass = _truth_index_current_head_pass(local_truth_index, current_head=current_head)
    ci_truth_pass = _truth_index_current_head_pass(ci_truth_index, current_head=current_head)
    local_probe_ok = _probe_matches_policy(local_bundle["probe"], envelope_policy)
    ci_probe_ok = _probe_matches_policy(ci_bundle["probe"], envelope_policy)
    independent_envs = (
        str(local_bundle["probe"].get("environment_id", "")).strip() != str(ci_bundle["probe"].get("environment_id", "")).strip()
        and str(local_bundle["probe"].get("environment_provenance", "")).strip() != str(ci_bundle["probe"].get("environment_provenance", "")).strip()
        and str(local_bundle["probe"].get("environment_class", "")).strip() != str(ci_bundle["probe"].get("environment_class", "")).strip()
    )
    registry_hashes_match = _canonical_sha(local_bundle["registry"]) == _canonical_sha(ci_bundle["registry"])
    envelope_hashes_match = _canonical_sha(local_bundle["envelope"]) == _canonical_sha(ci_bundle["envelope"])
    subject_set_hashes_match = _canonical_sha(local_bundle["subject_set"]) == _canonical_sha(ci_bundle["subject_set"])
    class_b_local = str(local_bundle["subject_set"].get("class_b_canonical_sha256", {}).get("canonical_hash", "")).strip()
    class_b_ci = str(ci_bundle["subject_set"].get("class_b_canonical_sha256", {}).get("canonical_hash", "")).strip()
    class_b_match = bool(class_b_local) and class_b_local == class_b_ci
    ci_keyless_ok, ci_diagnostic, ci_keyless_receipt = _ci_keyless_pass(root, signer_identity_policy)

    blockers: List[str] = []
    if not ws12_pass:
        blockers.append("WS12_NOT_PASS")
    if not local_truth_pass:
        blockers.append("LOCAL_TRUTH_BARRIER_NOT_PASSING_ON_CURRENT_HEAD")
    if not ci_truth_pass:
        blockers.append("CI_TRUTH_BARRIER_NOT_PASSING_ON_CURRENT_HEAD")
    if not local_probe_ok:
        blockers.append("LOCAL_ENVIRONMENT_OUTSIDE_DECLARED_ENVELOPE")
    if not ci_probe_ok:
        blockers.append("CI_ENVIRONMENT_OUTSIDE_DECLARED_ENVELOPE")
    if not independent_envs:
        blockers.append("INDEPENDENT_ENVIRONMENTS_NOT_PROVEN")
    if not registry_hashes_match:
        blockers.append("CLASS_REGISTRY_DRIFT_DETECTED")
    if not envelope_hashes_match:
        blockers.append("DETERMINISM_ENVELOPE_DRIFT_DETECTED")
    if not subject_set_hashes_match:
        blockers.append("SUBJECT_SET_HASH_MISMATCH")
    if not class_b_match:
        blockers.append("CLASS_B_CANONICAL_HASH_MISMATCH")
    if not ci_keyless_ok:
        blockers.append("CURRENT_HEAD_CI_KEYLESS_CARRY_FORWARD_NOT_PROVEN")

    status = "PASS" if not blockers else "PARTIAL"
    next_lawful = "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY" if status == "PASS" else WORKSTREAM_ID
    checks = [
        _check(ws12_pass, "ws12_receipt_pass", "WS12 must already be PASS before WS13 can lock the determinism envelope.", [WS12_RECEIPT_REL]),
        _check(local_truth_pass, "local_truth_barrier_pass_current_head", "Local truth barrier must pass on the current head for the WS13 local bundle.", [f"{LOCAL_DIR_REL}/live_validation_index.local.json"]),
        _check(ci_truth_pass, "ci_truth_barrier_pass_current_head", "CI truth barrier must pass on the current head for the WS13 CI bundle.", [f"{CI_DIR_REL}/live_validation_index.ci.json"]),
        _check(local_probe_ok, "local_environment_matches_declared_envelope", "Local environment must match the declared WS13 envelope and required environment variables.", [ENVELOPE_POLICY_REL, f"{LOCAL_DIR_REL}/{PROBE_FILENAME}"]),
        _check(ci_probe_ok, "ci_environment_matches_declared_envelope", "CI environment must match the declared WS13 envelope and required environment variables.", [ENVELOPE_POLICY_REL, f"{CI_DIR_REL}/{PROBE_FILENAME}"]),
        _check(independent_envs, "independent_environments_proven", "WS13 requires two independent environments with different provenance and environment class.", [f"{LOCAL_DIR_REL}/{PROBE_FILENAME}", f"{CI_DIR_REL}/{PROBE_FILENAME}"]),
        _check(registry_hashes_match, "artifact_class_registry_byte_identity", "The emitted artifact-class registry must be byte-identical across local and CI.", [f"{LOCAL_DIR_REL}/{REGISTRY_FILENAME}", f"{CI_DIR_REL}/{REGISTRY_FILENAME}"]),
        _check(envelope_hashes_match, "determinism_envelope_byte_identity", "The emitted determinism envelope manifest must be byte-identical across local and CI.", [f"{LOCAL_DIR_REL}/{ENVELOPE_FILENAME}", f"{CI_DIR_REL}/{ENVELOPE_FILENAME}"]),
        _check(subject_set_hashes_match, "subject_set_byte_identity", "The emitted determinism subject set must be byte-identical across local and CI.", [f"{LOCAL_DIR_REL}/{SUBJECT_SET_FILENAME}", f"{CI_DIR_REL}/{SUBJECT_SET_FILENAME}"]),
        _check(class_b_match, "class_b_canonical_equivalence", "The CLASS_B live-validation surface must canonicalize to the same SHA-256 across local and CI.", [f"{LOCAL_DIR_REL}/live_validation_index.local.json", f"{CI_DIR_REL}/live_validation_index.ci.json"]),
        _check(ci_keyless_ok, "current_head_ci_keyless_carry_forward", "Current-head CI evidence must still prove a real keyless path and bind the imported signed copy of the declared public verifier manifest surface.", [CI_TRUTH_DIAGNOSTIC_REL, CI_KEYLESS_RECEIPT_REL, CI_KEYLESS_BUNDLE_REL, CI_SIGNED_SURFACE_REL]),
    ]
    return {
        "artifact_class_assignments": {
            "class_a": _surface_map_by_class(class_policy, "CLASS_A"),
            "class_b": _surface_map_by_class(class_policy, "CLASS_B"),
            "class_c": _surface_map_by_class(class_policy, "CLASS_C"),
        },
        "artifact_id": Path(RECEIPT_REL).name,
        "blocked_by": blockers,
        "canonicalization_rules": envelope_policy.get("class_b_canonicalization_profiles", []),
        "checks": checks,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "current_strongest_claim": "WS13 proves that the declared CLASS_A and CLASS_B surfaces are locked on the same current head across a local Windows environment and a GitHub Actions Ubuntu environment, with current-head keyless carry-forward evidence still present for the bounded public verifier surface." if status == "PASS" else "WS13 has declared artifact classes and some current-head bundle evidence, but the determinism envelope or current-head drift proof remains incomplete, so no downstream unlock is lawful.",
        "determinism_envelope_definition": {
            "dependency_model_ref": ENVELOPE_POLICY_REL,
            "forbidden_drift": envelope_policy.get("forbidden_drift", []),
            "normalization_rules": envelope_policy.get("normalization_rules", {}),
            "required_environment_variables": envelope_policy.get("required_environment_variables", {}),
            "truth_barrier_dependency_pins": envelope_policy.get("truth_barrier_dependency_pins", {}),
        },
        "environments_used": {"ci": ci_bundle["probe"], "local": local_bundle["probe"]},
        "generated_utc": generated_utc,
        "hash_comparison_results": {
            "class_b_canonical_hash": {"ci": class_b_ci, "local": class_b_local, "status": "PASS" if class_b_match else "FAIL"},
            "deterministic_outputs": [
                {"artifact": REGISTRY_FILENAME, "ci_sha256": _canonical_sha(ci_bundle["registry"]), "local_sha256": _canonical_sha(local_bundle["registry"]), "status": "PASS" if registry_hashes_match else "FAIL"},
                {"artifact": ENVELOPE_FILENAME, "ci_sha256": _canonical_sha(ci_bundle["envelope"]), "local_sha256": _canonical_sha(local_bundle["envelope"]), "status": "PASS" if envelope_hashes_match else "FAIL"},
                {"artifact": SUBJECT_SET_FILENAME, "ci_sha256": _canonical_sha(ci_bundle["subject_set"]), "local_sha256": _canonical_sha(local_bundle["subject_set"]), "status": "PASS" if subject_set_hashes_match else "FAIL"},
            ],
        },
        "imported_current_head_ci_evidence": {
            "keyless_execution_receipt_ref": CI_KEYLESS_RECEIPT_REL,
            "keyless_sigstore_bundle_ref": CI_KEYLESS_BUNDLE_REL,
            "run_id": str(ci_keyless_receipt.get("run_id", "")).strip(),
            "signed_surface_import_ref": CI_SIGNED_SURFACE_REL,
            "signed_surface_path": str(ci_keyless_receipt.get("signed_surface_path", "")).strip(),
            "signed_surface_sha256": str(ci_keyless_receipt.get("signed_surface_sha256", "")).strip(),
            "truth_barrier_remote_diagnostic_ref": CI_TRUTH_DIAGNOSTIC_REL,
        },
        "limitations": [
            "WS13 PASS is bounded to the declared CLASS_A and CLASS_B surfaces only.",
            "CLASS_C surfaces remain intentionally non-reproducible and must not be overread as drift failures, including the current-head public verifier manifest carry-forward copy.",
            "The repo-root import fragility for package-root invocation remains visible and is not erased by WS13.",
            "WS13 PASS does not prove release readiness, verifier widening, or campaign completion.",
        ],
        "next_lawful_workstream": next_lawful,
        "pass_verdict": PASS_VERDICT if status == "PASS" else PARTIAL_VERDICT,
        "protected_touch_violations": [],
        "remaining_non_deterministic_surfaces": _surface_map_by_class(class_policy, "CLASS_C"),
        "schema_id": "kt.operator.ws13.determinism_envelope_receipt.v1",
        "status": status,
        "step_id": STEP_ID,
        "stronger_claim_not_made": [
            "All KT artifacts are now byte-identical across all environments",
            "WS13 fixes the repo-root import fragility",
            "WS13 proves release readiness or static verifier acceptance",
        ],
        "tests_run": ["python -m pytest -q tests/operator/test_ws13_determinism_envelope_validate.py"],
        "validators_run": ["python -m tools.operator.ws13_determinism_envelope_validate"],
        "workstream_id": WORKSTREAM_ID,
    }


def _apply_control_plane(*, dag: Dict[str, Any], trust_root_policy: Dict[str, Any], signer_topology: Dict[str, Any], receipt: Dict[str, Any]) -> None:
    generated_utc = str(receipt.get("generated_utc", "")).strip()
    current_head = str(receipt.get("current_repo_head", "")).strip()
    ws13_pass = str(receipt.get("status", "")).strip() == "PASS"

    dag["generated_utc"] = generated_utc
    dag["current_repo_head"] = current_head
    dag["current_node"] = receipt["next_lawful_workstream"]
    dag["next_lawful_workstream"] = receipt["next_lawful_workstream"]
    dag["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. WS12 passed for bounded current-head supply-chain policy. WS13 passed for bounded artifact-class locking and determinism proof across local Windows and GitHub Actions Ubuntu on the same subject head."
        if ws13_pass
        else "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. WS12 passed for bounded current-head supply-chain policy. WS13 remains current because the bounded determinism envelope or current-head drift proof is incomplete."
    )
    ws13_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws14_node = next(node for node in dag["nodes"] if node["id"] == "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY")
    if ws13_pass:
        ws13_node["status"] = "PASS"
        ws13_node["claim_boundary"] = "WS13 PASS proves only the declared CLASS_A and CLASS_B surfaces are locked and reproducible on the same subject head across the declared local and CI environments."
        ws14_node["status"] = "UNLOCKED"
        ws14_node["unlock_basis"] = "WS13 PASS"
    else:
        ws13_node["status"] = "PARTIAL_DRIFT_PENDING"
        ws13_node["claim_boundary"] = "WS13 remains partial until the declared current-head determinism bundle matches across local and CI."
        ws14_node["status"] = "LOCKED_PENDING_WS13_PASS"
        ws14_node.pop("unlock_basis", None)

    trust_root_policy["generated_utc"] = generated_utc
    trust_root_policy["current_repo_head"] = current_head
    trust_root_policy["closure_boundary"]["next_required_step"] = receipt["next_lawful_workstream"]
    trust_root_policy["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 remains executed under the reratified 3-of-3 root boundary only. WS11 and WS12 remain bounded. WS13 now locks the declared artifact classes and determinism envelope across local and CI without widening release or verifier claims."
        if ws13_pass
        else "WS10 remains executed under the reratified 3-of-3 root boundary only. WS11 and WS12 remain bounded. WS13 is current until current-head artifact drift proof is sealed."
    )

    signer_topology["generated_utc"] = generated_utc
    signer_topology["current_repo_head"] = current_head
    signer_topology["semantic_boundary"]["lawful_current_claim"] = (
        "Root signer topology remains executed and reratified as 3-of-3 only. WS13 adds bounded determinism locking for declared non-root artifact surfaces without widening issuance or release authority."
        if ws13_pass
        else "Root signer topology remains executed and reratified as 3-of-3 only. WS13 is current and no further authority widening is lawful yet."
    )


def emit_ws13_determinism_envelope(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or repo_root()
    pre_dirty = _dirty_relpaths(_git_status_lines(repo))
    if pre_dirty and any(not _path_in_scope(path) for path in pre_dirty):
        raise RuntimeError("FAIL_CLOSED: WS13 requires a clean or in-scope worktree before mutation")

    current_head = _git_head(repo)
    generated_utc = utc_now_iso_z()
    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    trust_root_policy = _load_required_json(repo, TRUST_ROOT_POLICY_REL)
    signer_topology = _load_required_json(repo, SIGNER_TOPOLOGY_REL)
    signer_identity_policy = _load_required_json(repo, SIGNER_IDENTITY_POLICY_REL)
    ws12_receipt = _load_required_json(repo, WS12_RECEIPT_REL)
    class_policy = _load_required_json(repo, CLASS_POLICY_REL)
    envelope_policy = _load_required_json(repo, ENVELOPE_POLICY_REL)
    local_bundle = _load_bundle(repo, LOCAL_DIR_REL)
    ci_bundle = _load_bundle(repo, CI_DIR_REL)

    receipt = build_ws13_receipt(
        root=repo,
        current_head=current_head,
        generated_utc=generated_utc,
        ws12_receipt=ws12_receipt,
        class_policy=class_policy,
        envelope_policy=envelope_policy,
        signer_identity_policy=signer_identity_policy,
        local_bundle=local_bundle,
        ci_bundle=ci_bundle,
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
    parser = argparse.ArgumentParser(description="WS13: lock artifact classes and prove the bounded determinism envelope.")
    parser.add_argument("--emit-bundle", action="store_true", help="Emit a deterministic WS13 bundle for one environment.")
    parser.add_argument("--out-dir", default="", help="Repo-relative output directory for the emitted environment bundle.")
    parser.add_argument("--environment-id", default="", help="Stable environment identifier for the emitted bundle.")
    parser.add_argument("--environment-class", default="", help="Declared environment class for the emitted bundle.")
    parser.add_argument("--environment-provenance", default="", help="Declared environment provenance for the emitted bundle.")
    parser.add_argument("--live-validation-index", default="", help="Repo-relative path to the live validation index used for bundle emission.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    if args.emit_bundle:
        if not all([args.out_dir, args.environment_id, args.environment_class, args.environment_provenance, args.live_validation_index]):
            raise SystemExit("FAIL_CLOSED: --emit-bundle requires --out-dir, --environment-id, --environment-class, --environment-provenance, and --live-validation-index")
        payload = emit_environment_bundle(
            root=root,
            out_dir_rel=args.out_dir,
            environment_id=args.environment_id,
            environment_class=args.environment_class,
            environment_provenance=args.environment_provenance,
            live_validation_index_rel=args.live_validation_index,
        )
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
        return 0

    receipt = emit_ws13_determinism_envelope(root=root)
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
