from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


FOUNDATION_ROOT_REL = "KT_PROD_CLEANROOM/governance/closure_foundation"
DETERMINISM_CONTRACT_REL = f"{FOUNDATION_ROOT_REL}/kt_determinism_contract.json"
TUF_ROOT_POLICY_REL = f"{FOUNDATION_ROOT_REL}/kt_tuf_root_policy.json"
PUBLIC_VERIFIER_CONTRACT_REL = f"{FOUNDATION_ROOT_REL}/kt_public_verifier_contract.json"
CLAIM_COMPILER_POLICY_REL = f"{FOUNDATION_ROOT_REL}/kt_claim_compiler_policy.json"
RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_closure_foundation_receipt.json"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/closure_foundation_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_closure_foundation_validate.py"

SUBJECT_ARTIFACT_REFS = [
    DETERMINISM_CONTRACT_REL,
    TUF_ROOT_POLICY_REL,
    PUBLIC_VERIFIER_CONTRACT_REL,
    CLAIM_COMPILER_POLICY_REL,
    TOOL_REL,
    TEST_REL,
]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_TOTAL_CLOSURE_CAMPAIGN_TO_ACTIVE_CANONICAL_RELEASE"
WORK_ORDER_SCHEMA_ID = "kt.work_order.total_closure_campaign.v1"
WORKSTREAM_ID = "WS0_CLOSURE_FOUNDATION_FREEZE"
WORKSTREAM_STEP_ID = "WS0_STEP_1_RATIFY_CLOSURE_FOUNDATION"

SIGNER_POLICY_REL = "KT_PROD_CLEANROOM/governance/signer_identity_policy.json"
PUBLIC_VERIFIER_RULES_REL = "KT_PROD_CLEANROOM/governance/public_verifier_rules.json"
CLAIM_CEILING_SUMMARY_REL = "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_summary.json"

REQUIRED_DETERMINISM_CONTROLS = {
    "canonical_runner_image_hash",
    "os_profile_matrix",
    "python_and_tool_versions_pinned",
    "canonical_json_serialization",
    "canonical_file_ordering",
    "normalized_path_separators",
    "explicit_newline_policy",
    "SOURCE_DATE_EPOCH_or_equivalent_timestamp_control",
    "deterministic_archive_creation",
    "network_policy_for_build_and_bundle",
}
REQUIRED_MINIMUM_ENVIRONMENTS = {"linux", "windows", "third_controlled_environment"}
REQUIRED_VERIFIER_FIELDS = {
    "verifier_id",
    "supported_proof_classes",
    "required_inputs",
    "offline_verification_capable",
    "subject_evidence_boundary_rules",
    "fail_closed_conditions",
}
REQUIRED_POLICY_FIELDS = {"policy_id", "version", "purpose", "invariants", "forbidden_states", "enforcement_layers"}

VALIDATORS_RUN = [
    "python -m tools.operator.closure_foundation_validate",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_closure_foundation_validate.py -q",
]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not older or not newer:
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    try:
        output = _git(root, "show", "--pretty=", "--name-only", commit)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_status_files(root: Path, paths: Sequence[str]) -> List[str]:
    existing = [str(Path(path).as_posix()) for path in paths]
    if not existing:
        return []
    try:
        output = _git(root, "status", "--short", "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    rows: List[str] = []
    for line in output.splitlines():
        value = str(line[3:] if len(line) > 3 else line).strip().replace("\\", "/")
        if value:
            rows.append(value)
    return rows


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return (
        normalized.startswith("kt_archive/")
        or "/archive/" in normalized
        or "/historical/" in normalized
        or normalized.startswith("kt_prod_cleanroom/06_archive_vault/")
    )


def _check_row(check: str, passed: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "check": check,
        "detail": detail,
        "refs": list(refs),
        "status": "PASS" if passed else "FAIL",
    }


def _policy_contract_ok(payload: Dict[str, Any]) -> bool:
    return REQUIRED_POLICY_FIELDS.issubset(set(payload.keys()))


def build_closure_foundation_report(root: Path) -> Dict[str, Any]:
    determinism = _load_required(root, DETERMINISM_CONTRACT_REL)
    tuf_policy = _load_required(root, TUF_ROOT_POLICY_REL)
    verifier_contract = _load_required(root, PUBLIC_VERIFIER_CONTRACT_REL)
    claim_policy = _load_required(root, CLAIM_COMPILER_POLICY_REL)
    signer_policy = _load_required(root, SIGNER_POLICY_REL)
    verifier_rules = _load_required(root, PUBLIC_VERIFIER_RULES_REL)
    ceiling_summary = _load_required(root, CLAIM_CEILING_SUMMARY_REL)

    checks: List[Dict[str, Any]] = []
    issues_found: List[str] = []

    determinism_controls_ok = set(determinism.get("required_controls", [])) == REQUIRED_DETERMINISM_CONTROLS
    checks.append(
        _check_row(
            "determinism_controls_complete",
            determinism_controls_ok,
            "Determinism contract must define the exact required control set from the governing packet.",
            [DETERMINISM_CONTRACT_REL],
        )
    )
    if not determinism_controls_ok:
        issues_found.append("determinism_controls_complete")

    determinism_envs_ok = set(determinism.get("minimum_environments", [])) == REQUIRED_MINIMUM_ENVIRONMENTS
    checks.append(
        _check_row(
            "determinism_environments_complete",
            determinism_envs_ok,
            "Determinism contract must define linux, windows, and one third controlled environment.",
            [DETERMINISM_CONTRACT_REL],
        )
    )
    if not determinism_envs_ok:
        issues_found.append("determinism_environments_complete")

    serialization_rules = determinism.get("serialization_rules", {})
    determinism_serialization_ok = (
        isinstance(serialization_rules, dict)
        and str(serialization_rules.get("json", "")).strip() == "canonical_json_serialization"
        and str(serialization_rules.get("canonical_file_ordering", "")).strip() == "byte-stable sorted relative paths"
        and str(serialization_rules.get("explicit_newline_policy", "")).strip() == "LF_ONLY"
    )
    checks.append(
        _check_row(
            "determinism_serialization_explicit",
            determinism_serialization_ok,
            "Determinism contract must explicitly pin canonical serialization, file ordering, and newline policy.",
            [DETERMINISM_CONTRACT_REL],
        )
    )
    if not determinism_serialization_ok:
        issues_found.append("determinism_serialization_explicit")

    tuf_contract_ok = _policy_contract_ok(tuf_policy)
    root_of_trust = tuf_policy.get("root_of_trust", {})
    root_keys = root_of_trust.get("root_keys", []) if isinstance(root_of_trust, dict) else []
    threshold = int(root_of_trust.get("threshold", 0)) if isinstance(root_of_trust, dict) else 0
    tuf_threshold_ok = bool(root_keys) and threshold >= 1 and threshold <= len(root_keys)
    checks.append(
        _check_row(
            "tuf_root_policy_explicit_and_threshold_backed",
            tuf_contract_ok and tuf_threshold_ok and bool(tuf_policy.get("rotation_rules")),
            "TUF root policy must define a trust root, positive threshold, and explicit rotation rules.",
            [TUF_ROOT_POLICY_REL],
        )
    )
    if not (tuf_contract_ok and tuf_threshold_ok and bool(tuf_policy.get("rotation_rules"))):
        issues_found.append("tuf_root_policy_explicit_and_threshold_backed")

    allowed_signers = {
        str(row.get("signer_id", "")).strip(): row
        for row in signer_policy.get("allowed_signers", [])
        if isinstance(row, dict)
    }
    root_key = root_keys[0] if root_keys else {}
    key_id = str(root_key.get("key_id", "")).strip()
    key_ref = str(root_key.get("public_key_ref", "")).strip()
    key_sha = str(root_key.get("public_key_sha256", "")).strip()
    actual_key_sha = file_sha256((root / Path(key_ref)).resolve()) if key_ref and (root / Path(key_ref)).exists() else ""
    signer = allowed_signers.get(key_id, {})
    tuf_signer_match_ok = (
        bool(signer)
        and key_ref == str(signer.get("public_key_ref", "")).strip()
        and key_sha == str(signer.get("public_key_sha256", "")).strip()
        and key_sha == actual_key_sha
    )
    checks.append(
        _check_row(
            "tuf_root_policy_matches_active_signer",
            tuf_signer_match_ok,
            "Root-of-trust policy must bind to the checked-in active signer and matching public-key hash.",
            [TUF_ROOT_POLICY_REL, SIGNER_POLICY_REL, key_ref] if key_ref else [TUF_ROOT_POLICY_REL, SIGNER_POLICY_REL],
        )
    )
    if not tuf_signer_match_ok:
        issues_found.append("tuf_root_policy_matches_active_signer")

    verifier_contract_ok = REQUIRED_VERIFIER_FIELDS.issubset(set(verifier_contract.keys()))
    verifier_fail_closed_ok = (
        verifier_contract_ok
        and bool(verifier_contract.get("offline_verification_capable"))
        and "subject_evidence_boundary_ambiguous" in verifier_contract.get("fail_closed_conditions", [])
        and "runtime_dependency_outside_allowed_contracts" in verifier_contract.get("fail_closed_conditions", [])
    )
    checks.append(
        _check_row(
            "public_verifier_contract_explicit_and_fail_closed",
            verifier_fail_closed_ok,
            "Public verifier contract must be explicit, offline-capable, and fail closed on boundary or dependency ambiguity.",
            [PUBLIC_VERIFIER_CONTRACT_REL, PUBLIC_VERIFIER_RULES_REL],
        )
    )
    if not verifier_fail_closed_ok:
        issues_found.append("public_verifier_contract_explicit_and_fail_closed")

    verifier_boundary_alignment_ok = set(verifier_contract.get("required_inputs", [])) >= {
        "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
        "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
        "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
        "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
    } and bool(verifier_rules.get("required_manifest_fields"))
    checks.append(
        _check_row(
            "public_verifier_contract_aligned_to_active_verifier_surfaces",
            verifier_boundary_alignment_ok,
            "Public verifier contract must bind to the current verifier surfaces rather than freeform runtime internals.",
            [PUBLIC_VERIFIER_CONTRACT_REL, PUBLIC_VERIFIER_RULES_REL],
        )
    )
    if not verifier_boundary_alignment_ok:
        issues_found.append("public_verifier_contract_aligned_to_active_verifier_surfaces")

    claim_policy_ok = _policy_contract_ok(claim_policy)
    downgrade_policy = claim_policy.get("ambiguity_downgrade_policy", {})
    claim_downgrade_ok = (
        claim_policy_ok
        and isinstance(downgrade_policy, dict)
        and str(downgrade_policy.get("default_class_on_ambiguity", "")).strip() == "LOWEST_ADMISSIBLE_TIER"
        and "subject_evidence_boundary_ambiguous" in downgrade_policy.get("downgrade_triggers", [])
        and "truth_source_ambiguous" in downgrade_policy.get("downgrade_triggers", [])
    )
    checks.append(
        _check_row(
            "claim_compiler_policy_downgrades_on_ambiguity",
            claim_downgrade_ok,
            "Claim compiler policy must explicitly downgrade on ambiguity rather than preserve stronger language.",
            [CLAIM_COMPILER_POLICY_REL],
        )
    )
    if not claim_downgrade_ok:
        issues_found.append("claim_compiler_policy_downgrades_on_ambiguity")

    always_on_surfaces = set(claim_policy.get("always_on_surfaces", []))
    claim_surfaces_ok = {
        "docs/generated/**",
        "KT_PROD_CLEANROOM/docs/commercial/**",
    }.issubset(always_on_surfaces)
    checks.append(
        _check_row(
            "claim_compiler_policy_covers_designated_public_surfaces",
            claim_surfaces_ok,
            "Claim compiler policy must cover generated doctrine and commercial public surfaces.",
            [CLAIM_COMPILER_POLICY_REL],
        )
    )
    if not claim_surfaces_ok:
        issues_found.append("claim_compiler_policy_covers_designated_public_surfaces")

    closure_boundary_ok = all(
        artifact.get("closure_boundary", {}).get("foundation_ratification_only") is True
        and artifact.get("closure_boundary", {}).get("opens_release_gates") == []
        and artifact.get("closure_boundary", {}).get("closes_existing_blockers") == []
        for artifact in (determinism, tuf_policy, verifier_contract, claim_policy)
    )
    checks.append(
        _check_row(
            "closure_foundation_does_not_upgrade_gates_or_blockers",
            closure_boundary_ok,
            "WS0 must ratify foundation law only; it may not claim blocker closure or gate opening.",
            [
                DETERMINISM_CONTRACT_REL,
                TUF_ROOT_POLICY_REL,
                PUBLIC_VERIFIER_CONTRACT_REL,
                CLAIM_COMPILER_POLICY_REL,
                CLAIM_CEILING_SUMMARY_REL,
            ],
        )
    )
    if not closure_boundary_ok:
        issues_found.append("closure_foundation_does_not_upgrade_gates_or_blockers")

    current_ceiling = str(ceiling_summary.get("highest_attained_proof_class", {}).get("proof_class_id", "")).strip()
    ceiling_alignment_ok = (
        str(determinism.get("current_proof_ceiling", "")).strip() == current_ceiling
        and str(verifier_contract.get("release_state", {}).get("current_proof_ceiling", "")).strip() == current_ceiling
    )
    checks.append(
        _check_row(
            "closure_foundation_anchored_to_current_proof_ceiling",
            ceiling_alignment_ok,
            "WS0 foundation artifacts must state the current proof ceiling instead of overclaiming later closure states.",
            [DETERMINISM_CONTRACT_REL, PUBLIC_VERIFIER_CONTRACT_REL, CLAIM_CEILING_SUMMARY_REL],
        )
    )
    if not ceiling_alignment_ok:
        issues_found.append("closure_foundation_anchored_to_current_proof_ceiling")

    evidence_head_commit = _git_head(root)
    subject_commit_from_history = _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS)
    subject_head_commit = subject_commit_from_history or evidence_head_commit
    actual_subject_touched: List[str] = []
    if subject_commit_from_history:
        subject_parent = _git_parent(root, subject_head_commit)
        actual_subject_touched = _git_diff_files(root, subject_parent, subject_head_commit, SUBJECT_ARTIFACT_REFS)
        if not actual_subject_touched:
            actual_subject_touched = _git_changed_files(root, subject_head_commit)
    working_tree_subject_touched = _git_status_files(root, SUBJECT_ARTIFACT_REFS)
    if working_tree_subject_touched:
        actual_subject_touched = sorted(set(actual_subject_touched) | set(working_tree_subject_touched))
    receipt_exists = (root / Path(RECEIPT_REL)).exists()
    actual_touched = sorted(set(actual_subject_touched + ([RECEIPT_REL] if receipt_exists else [])))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = sorted(path for path in actual_touched if _is_protected(path))
    expected_touched = set(PLANNED_MUTATES if receipt_exists else SUBJECT_ARTIFACT_REFS)
    touch_accounting_ok = not unexpected_touches and not protected_touch_violations and set(actual_touched) == expected_touched
    checks.append(
        _check_row(
            "post_touch_accounting_clean",
            touch_accounting_ok,
            "Actual touched files must match the lawful WS0 subject set before receipt emission, then the full set including the receipt after sealing.",
            PLANNED_MUTATES if receipt_exists else SUBJECT_ARTIFACT_REFS,
        )
    )
    if not touch_accounting_ok:
        issues_found.append("post_touch_accounting_clean")

    status = "PASS" if not issues_found else "FAIL_CLOSED"
    resolution = (
        "WS0 closure-foundation artifacts are ratified and no release or blocker state was upgraded."
        if status == "PASS"
        else "FAIL_CLOSED: closure-foundation artifacts remain insufficient for lawful campaign execution."
    )

    return {
        "artifact_id": "kt_closure_foundation_receipt.json",
        "checks": checks,
        "compiled_head_commit": subject_head_commit,
        "current_head_commit": evidence_head_commit,
        "evidence_head_commit": evidence_head_commit,
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS1_ACTIVE_ARCHIVE_CUTLINE_FREEZE",
        },
        "pass_verdict": "CLOSURE_FOUNDATION_RATIFIED" if status == "PASS" else "CLOSURE_FOUNDATION_REJECTED_FAIL_CLOSED",
        "planned_mutates": PLANNED_MUTATES,
        "protected_touch_violations": protected_touch_violations,
        "schema_id": "kt.operator.closure_foundation_receipt.v1",
        "status": status,
        "step_report": {
            "actions_taken": [
                "ratified determinism contract",
                "ratified TUF root policy",
                "ratified public verifier contract",
                "ratified claim compiler policy",
                "validated closure foundation boundaries and touch set",
            ],
            "files_touched": actual_touched,
            "issues_found": issues_found,
            "pass_fail_status": status,
            "protected_touch_violations": protected_touch_violations,
            "resolution": resolution,
            "step_id": WORKSTREAM_STEP_ID,
            "tests_run": TESTS_RUN,
            "timestamp": utc_now_iso_z(),
            "unexpected_touches": unexpected_touches,
            "validators_run": VALIDATORS_RUN,
            "workstream_id": WORKSTREAM_ID,
        },
        "subject_head_commit": subject_head_commit,
        "unexpected_touches": unexpected_touches,
        "validators_run": VALIDATORS_RUN,
        "workstream_id": WORKSTREAM_ID,
        "workstream_open_blockers_snapshot": list(ceiling_summary.get("unattained_proof_classes", [])),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the KT closure foundation workstream.")
    parser.add_argument("--output", default=RECEIPT_REL)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report = build_closure_foundation_report(root)
    output_path = Path(str(args.output)).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()
    write_json_stable(output_path, report)
    print(
        json.dumps(
            {
                "artifact_id": report["artifact_id"],
                "status": report["status"],
                "pass_verdict": report["pass_verdict"],
                "subject_head_commit": report["subject_head_commit"],
                "evidence_head_commit": report["evidence_head_commit"],
                "unexpected_touches": report["unexpected_touches"],
                "protected_touch_violations": report["protected_touch_violations"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
