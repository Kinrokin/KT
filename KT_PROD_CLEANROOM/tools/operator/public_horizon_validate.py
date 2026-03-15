from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS21_BOUNDED_PUBLIC_HORIZON_OPEN"
STEP_ID = "WS21_STEP_1_OPEN_VERIFIER_ONLY_PUBLIC_HORIZON"
PASS_VERDICT = "VERIFIER_ONLY_BOUNDED_PUBLIC_HORIZON_OPENED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
CONTRACT_REL = f"{REPORT_ROOT_REL}/kt_bounded_public_horizon_contract.json"
REPLAY_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_public_horizon_replay_bundle.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_horizon_receipt.json"

DEFAULT_WS18_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_build_verification_receipt.json"
DEFAULT_WS19_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_release_manifest.json"
DEFAULT_WS19_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"
DEFAULT_WS20_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_matrix.json"
DEFAULT_WS20_RECIPE_REL = f"{REPORT_ROOT_REL}/kt_independent_replay_recipe.md"
DEFAULT_WS20_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_receipt.json"
DEFAULT_PUBLIC_SHOWABILITY_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_showability_receipt.json"
DEFAULT_TOURNAMENT_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_tournament_readiness_receipt.json"
DEFAULT_H1_RECEIPT_REL = f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json"
DEFAULT_PUBLICATION_PROFILE_REL = "docs/generated/profiles/kt_publication_profile.json"
DEFAULT_COMPETITION_PROFILE_REL = "docs/generated/profiles/kt_competition_profile.json"
DEFAULT_FINAL_COMPLETION_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_final_completion_bundle.json"
DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
DEFAULT_RELEASE_LAW_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_release_law.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/public_horizon_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_public_horizon_validate.py"

OPENED_HORIZON_CHOICE = "bounded public showability"
OPENED_HORIZON_ID = "VERIFIER_ONLY_PUBLIC_VERIFICATION"
OPENED_HORIZON_STATUS = "OPEN"
STRONGER_CLAIM_NOT_MADE = (
    "WS21 opens only a verifier-only public verification horizon for the sealed detached verifier package and the bounded "
    "critical artifact set. It does not claim broader public showability or publication readiness, tournament readiness, "
    "H1 single-adapter activation, competition readiness, production deployment readiness, economic/commercial readiness, "
    "platform-enforced governance, or any broader outsider/public reproducibility than the WS20 same-host independent clean-environment matrix."
)
EXACT_SCOPE = (
    "External parties may inspect and replay the sealed detached verifier package, confirm detached-vs-repo-local parity, "
    "and verify the bounded critical artifact set named by the sealed WS18/WS19/WS20 substrate. No broader execution, "
    "publication, tournament, H1, production, or economic horizon is opened by this workstream."
)
LEGACY_PUBLIC_SHOWABILITY_BOUNDARY = (
    "This WS21 horizon uses the bounded public showability lane only in verifier-only form. "
    "It does not override the broader publication/showability gate, which remains blocked."
)
VALIDATORS_RUN = ["python -m tools.operator.public_horizon_validate"]
TESTS_RUN = ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_public_horizon_validate.py -q"]
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")
CREATED_FILES = [TOOL_REL, TEST_REL, CONTRACT_REL, REPLAY_BUNDLE_REL, RECEIPT_REL]
WORKSTREAM_FILES_TOUCHED = list(CREATED_FILES)
SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    CONTRACT_REL: "generated public horizon contract",
    REPLAY_BUNDLE_REL: "generated replay bundle index",
    RECEIPT_REL: "generated receipt",
}


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


def _dirty_relpaths(root: Path, status_lines: Sequence[str]) -> List[str]:
    rows: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if not rel:
            continue
        path = (root / Path(rel)).resolve()
        if path.exists() and path.is_dir():
            rows.extend(child.resolve().relative_to(root.resolve()).as_posix() for child in path.rglob("*") if child.is_file())
        else:
            rows.append(Path(rel).as_posix())
    return sorted(set(rows))


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS21 input: {rel}")
    return load_json(path)


def _load_required_text(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS21 text input: {rel}")
    return path.read_text(encoding="utf-8")


def _require_paths_exist(root: Path, refs: Sequence[str]) -> None:
    missing = [ref for ref in refs if not (root / Path(ref)).resolve().exists()]
    if missing:
        raise RuntimeError("FAIL_CLOSED: missing replay/public-horizon refs: " + ", ".join(sorted(set(missing))))


def _release_profile(release_law: Dict[str, Any], profile_id: str) -> Dict[str, Any]:
    profiles = release_law.get("release_profiles", [])
    if not isinstance(profiles, list):
        return {}
    for profile in profiles:
        if isinstance(profile, dict) and str(profile.get("profile_id", "")).strip() == profile_id:
            return profile
    return {}


def _normalize_relpaths(paths: Sequence[str]) -> List[str]:
    return sorted(set(str(path).replace("\\", "/") for path in paths if str(path).strip()))


def build_public_horizon_outputs_from_artifacts(
    *,
    current_repo_head: str,
    ws18_receipt: Dict[str, Any],
    ws19_manifest: Dict[str, Any],
    ws19_receipt: Dict[str, Any],
    ws20_matrix: Dict[str, Any],
    ws20_recipe_text: str,
    ws20_receipt: Dict[str, Any],
    public_showability_receipt: Dict[str, Any],
    tournament_receipt: Dict[str, Any],
    h1_receipt: Dict[str, Any],
    publication_profile: Dict[str, Any],
    competition_profile: Dict[str, Any],
    final_completion_bundle: Dict[str, Any],
    public_verifier_manifest: Dict[str, Any],
    release_law: Dict[str, Any],
    changed_files: Sequence[str],
    prewrite_scope_clean: bool,
) -> Dict[str, Dict[str, Any]]:
    changed = _normalize_relpaths(changed_files)
    unexpected = sorted(path for path in changed if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError("FAIL_CLOSED: unexpected subject touches detected: " + ", ".join(unexpected + protected))

    exact_subjects = ws18_receipt.get("questions", {}).get("exact_artifact_subjects_covered", [])
    if not isinstance(exact_subjects, list):
        exact_subjects = []
    subject_root_sha = str(ws18_receipt.get("summary", {}).get("artifact_subject_root_sha256", "")).strip()
    publication_surface_boundary = str(
        ws18_receipt.get("questions", {})
        .get("provenance_vsa_publication_subject_alignment", {})
        .get("publication_surface_boundary", "")
    ).strip()

    ws18_ok = (
        str(ws18_receipt.get("status", "")).strip() == "PASS"
        and str(ws18_receipt.get("pass_verdict", "")).strip() == "BUILD_PROVENANCE_AND_VSA_ALIGNED"
        and len(exact_subjects) >= 1
        and bool(subject_root_sha)
    )
    ws19_ok = (
        str(ws19_receipt.get("status", "")).strip() == "PASS"
        and str(ws19_receipt.get("pass_verdict", "")).strip() == "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN"
    )
    ws20_envs = ws20_matrix.get("environments", [])
    if not isinstance(ws20_envs, list):
        ws20_envs = []
    ws20_ok = (
        str(ws20_receipt.get("status", "")).strip() == "PASS"
        and str(ws20_receipt.get("pass_verdict", "")).strip() == "INDEPENDENT_EXTERNAL_REPRODUCTION_MATRIX_PROVEN"
        and str(ws20_matrix.get("status", "")).strip() == "PASS"
        and len(ws20_envs) >= 2
    )
    outside_repo_env_present = any(
        isinstance(row, dict) and not bool(row.get("package_root_inside_repo_root"))
        for row in ws20_envs
    )
    recipe_explicit = all(
        token in ws20_recipe_text
        for token in (
            "PowerShell recipe",
            "python -m tools.operator.public_verifier_detached_runtime",
            "Success criteria",
            "KT_HMAC_KEY_SIGNER_A",
            "KT_HMAC_KEY_SIGNER_B",
        )
    )
    subject_anchor_aligned = all(
        str(item).strip() == str(ws20_receipt.get("subject_head_commit", "")).strip()
        for item in (
            ws18_receipt.get("subject_head_commit", ""),
            ws19_receipt.get("subject_head_commit", ""),
            ws20_receipt.get("subject_head_commit", ""),
        )
    ) and all(
        str(item).strip() == str(ws20_receipt.get("evidence_head_commit", "")).strip()
        for item in (
            ws18_receipt.get("evidence_head_commit", ""),
            ws19_receipt.get("evidence_head_commit", ""),
            ws20_receipt.get("evidence_head_commit", ""),
        )
    )

    public_showability_blocked = (
        str(public_showability_receipt.get("status", "")).strip() == "BLOCKED"
        and str(public_showability_receipt.get("pass_verdict", "")).strip() == "PUBLIC_SHOWABILITY_BLOCKED"
    )
    tournament_blocked = (
        str(tournament_receipt.get("status", "")).strip() == "BLOCKED"
        and str(tournament_receipt.get("pass_verdict", "")).strip() == "TOURNAMENT_GATE_BLOCKED"
    )
    h1_blocked = (
        str(h1_receipt.get("status", "")).strip() == "BLOCKED"
        and str(h1_receipt.get("h1_gate_verdict", "")).strip() == "H1_BLOCKED"
        and h1_receipt.get("single_adapter_benchmarking_allowed") is False
    )
    publication_profile_blocked = str(publication_profile.get("current_status", "")).strip() == "BLOCKED"
    competition_profile_blocked = str(competition_profile.get("current_status", "")).strip() == "BLOCKED"
    offline_public_verification_lawful = "offline public verification using the released verifier bundle" in list(
        final_completion_bundle.get("lawful_now", [])
    )
    governance_ceiling_blocked = (
        str(public_verifier_manifest.get("status", "")).strip() == "PASS"
        and public_verifier_manifest.get("platform_governance_claim_admissible") is False
        and str(public_verifier_manifest.get("platform_governance_verdict", "")).strip()
        == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"
    )

    commercial_profile = _release_profile(release_law, "commercial_documentary_only")
    competition_release_profile = _release_profile(release_law, "competition_and_publication_grade")
    h1_release_profile = _release_profile(release_law, "h1_activation")

    economic_horizon_closed = (
        str(commercial_profile.get("current_admissibility_ceiling", "")).strip() == "documentary_only"
        and "documentary commercial/doctrine use bounded by the active claim compiler"
        in list(final_completion_bundle.get("lawful_now", []))
    )
    production_horizon_closed = governance_ceiling_blocked
    competition_horizon_closed = (
        competition_profile_blocked
        and tournament_blocked
        and str(competition_release_profile.get("current_admissibility_ceiling", "")).strip()
        == "competition_and_publication_on_bounded_surface_only"
    )
    h1_horizon_closed = h1_blocked and str(h1_release_profile.get("current_admissibility_ceiling", "")).strip() == "blocked"

    detached_package_root_ref = str(ws19_manifest.get("detached_package_root_ref", "")).strip()
    detached_entrypoint = str(ws19_manifest.get("detached_entrypoint", "")).strip()
    detached_package_root_sha256 = str(ws19_manifest.get("package_root_sha256", "")).strip()
    repo_local_parity_fields = list(ws19_manifest.get("repo_local_parity_fields", []))

    horizon_matrix = [
        {
            "horizon_id": OPENED_HORIZON_ID,
            "allowed_horizon_choice": OPENED_HORIZON_CHOICE,
            "status": OPENED_HORIZON_STATUS if ws19_ok and ws20_ok and recipe_explicit and outside_repo_env_present else "BLOCKED",
            "reason": (
                "WS19 detached verifier packaging and WS20 independent clean-environment replay make a verifier-only public validation surface externally inspectable."
                if ws19_ok and ws20_ok and recipe_explicit and outside_repo_env_present
                else "Verifier-only public validation remains blocked until detached packaging, independent replay, and explicit recipe evidence are all PASS."
            ),
            "receipt_refs": [DEFAULT_WS19_RECEIPT_REL, DEFAULT_WS20_RECEIPT_REL],
            "supporting_refs": [DEFAULT_WS19_MANIFEST_REL, DEFAULT_WS20_MATRIX_REL, DEFAULT_WS20_RECIPE_REL],
        },
        {
            "horizon_id": "BOUNDED_TOURNAMENT_LANE",
            "allowed_horizon_choice": "bounded tournament lane",
            "status": "BLOCKED",
            "reason": "Tournament remains blocked by the sealed tournament readiness receipt and competition profile.",
            "receipt_refs": [DEFAULT_TOURNAMENT_RECEIPT_REL, DEFAULT_COMPETITION_PROFILE_REL],
            "supporting_refs": [DEFAULT_PUBLIC_SHOWABILITY_RECEIPT_REL],
        },
        {
            "horizon_id": "BOUNDED_H1_SINGLE_ADAPTER_LANE",
            "allowed_horizon_choice": "bounded H1 single-adapter lane",
            "status": "BLOCKED",
            "reason": "H1 single-adapter activation remains blocked by the sealed H1 gate receipt and release-law H1 profile.",
            "receipt_refs": [DEFAULT_H1_RECEIPT_REL],
            "supporting_refs": [DEFAULT_RELEASE_LAW_REL],
        },
    ]
    exactly_one_horizon_open = sum(1 for row in horizon_matrix if row["status"] == "OPEN") == 1

    blocker_matrix = [
        {
            "surface_id": "BROADER_PUBLIC_SHOWABILITY",
            "status": "BLOCKED" if public_showability_blocked and publication_profile_blocked else "OPEN",
            "blocking_condition": "Broader publication/showability remains blocked and is not overridden by verifier-only replay.",
            "blocking_refs": [DEFAULT_PUBLIC_SHOWABILITY_RECEIPT_REL, DEFAULT_PUBLICATION_PROFILE_REL],
        },
        {
            "surface_id": "COMPETITION_HORIZON",
            "status": "BLOCKED" if competition_horizon_closed else "OPEN",
            "blocking_condition": "Competition and tournament surfaces remain blocked by the competition profile and tournament readiness receipt.",
            "blocking_refs": [DEFAULT_TOURNAMENT_RECEIPT_REL, DEFAULT_COMPETITION_PROFILE_REL, DEFAULT_RELEASE_LAW_REL],
        },
        {
            "surface_id": "PRODUCTION_HORIZON",
            "status": "BLOCKED" if production_horizon_closed else "OPEN",
            "blocking_condition": "Production remains closed while platform-enforced governance is not proven on main.",
            "blocking_refs": [DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL, DEFAULT_FINAL_COMPLETION_BUNDLE_REL],
        },
        {
            "surface_id": "ECONOMIC_HORIZON",
            "status": "BLOCKED" if economic_horizon_closed else "OPEN",
            "blocking_condition": "Economic/commercial horizon remains limited to documentary use and is not opened for live deployment or public market claims.",
            "blocking_refs": [DEFAULT_RELEASE_LAW_REL, DEFAULT_FINAL_COMPLETION_BUNDLE_REL],
        },
        {
            "surface_id": "H1_SINGLE_ADAPTER_HORIZON",
            "status": "BLOCKED" if h1_horizon_closed else "OPEN",
            "blocking_condition": "H1 remains blocked and cannot be inferred from public verification replay.",
            "blocking_refs": [DEFAULT_H1_RECEIPT_REL, DEFAULT_RELEASE_LAW_REL],
        },
    ]
    broader_surfaces_still_blocked = all(row["status"] == "BLOCKED" for row in blocker_matrix)

    contract = {
        "schema_id": "kt.operator.bounded_public_horizon_contract.v1",
        "artifact_id": Path(CONTRACT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws20_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws20_receipt.get("evidence_head_commit", "")).strip(),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "selected_horizon": {
            "allowed_horizon_choice": OPENED_HORIZON_CHOICE,
            "horizon_id": OPENED_HORIZON_ID,
            "status": horizon_matrix[0]["status"],
            "scope": EXACT_SCOPE,
            "legacy_boundary": LEGACY_PUBLIC_SHOWABILITY_BOUNDARY,
            "exact_artifact_subjects_covered": exact_subjects,
            "artifact_subject_root_sha256": subject_root_sha,
            "publication_surface_boundary": publication_surface_boundary,
            "replay_contract": {
                "detached_package_root_ref": detached_package_root_ref,
                "detached_package_root_sha256": detached_package_root_sha256,
                "detached_entrypoint": detached_entrypoint,
                "expected_result": "PASS",
                "expected_verification_scope": str(ws20_matrix.get("verification_scope", "")).strip(),
                "expected_repo_local_parity_fields": repo_local_parity_fields,
                "same_host_independent_environment_count": len(ws20_envs),
                "at_least_one_environment_outside_repo_root": outside_repo_env_present,
                "replay_recipe_ref": DEFAULT_WS20_RECIPE_REL,
                "supporting_receipt_refs": [DEFAULT_WS19_RECEIPT_REL, DEFAULT_WS20_RECEIPT_REL],
            },
            "allowed_actions": [
                "inspect the detached verifier release manifest and bounded trust inputs",
                "replay verifier-only validation using the detached package and explicit recipe",
                "compare detached verifier conclusions against the repo-local parity field set",
                "inspect the bounded critical artifact subject set and the subject/evidence boundary",
            ],
            "forbidden_inferences": [
                "broader publication readiness",
                "tournament readiness",
                "H1 single-adapter activation",
                "competition readiness",
                "production deployment readiness",
                "economic/commercial readiness",
                "platform-enforced governance",
            ],
        },
        "horizon_matrix": horizon_matrix,
        "blocker_matrix": blocker_matrix,
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
    }
    replay_bundle = {
        "schema_id": "kt.operator.public_horizon_replay_bundle.v1",
        "artifact_id": Path(REPLAY_BUNDLE_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws20_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws20_receipt.get("evidence_head_commit", "")).strip(),
        "opened_horizon_choice": OPENED_HORIZON_CHOICE,
        "opened_horizon_id": OPENED_HORIZON_ID,
        "verification_target": {
            "exact_artifact_subjects_covered": exact_subjects,
            "artifact_subject_root_sha256": subject_root_sha,
            "publication_surface_boundary": publication_surface_boundary,
        },
        "replay_surface": {
            "detached_package_root_ref": detached_package_root_ref,
            "detached_package_root_sha256": detached_package_root_sha256,
            "detached_entrypoint": detached_entrypoint,
            "replay_recipe_ref": DEFAULT_WS20_RECIPE_REL,
            "reproduction_matrix_ref": DEFAULT_WS20_MATRIX_REL,
            "detached_release_manifest_ref": DEFAULT_WS19_MANIFEST_REL,
            "detached_receipt_ref": DEFAULT_WS19_RECEIPT_REL,
            "external_reproduction_receipt_ref": DEFAULT_WS20_RECEIPT_REL,
            "public_verifier_manifest_ref": DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL,
            "environment_rows": [
                {
                    "environment_id": row.get("environment_id"),
                    "status": row.get("status"),
                    "package_root": row.get("package_root"),
                    "package_root_inside_repo_root": row.get("package_root_inside_repo_root"),
                    "detached_runtime_receipt_ref": row.get("detached_runtime_receipt_ref"),
                    "detached_public_verifier_report_ref": row.get("detached_public_verifier_report_ref"),
                }
                for row in ws20_envs
                if isinstance(row, dict)
            ],
            "externally_inspectable_or_replayable": True,
        },
        "public_auditor_steps": [
            "inspect the detached release manifest and confirm the bounded trust input set",
            "copy the detached package into a clean environment",
            "run the detached verifier entrypoint exactly as specified by the replay recipe",
            "confirm the detached runtime receipt reports PASS and detached_root_detected=true",
            "compare detached conclusions against the repo-local parity field set recorded in the release manifest",
        ],
        "supporting_refs": [
            DEFAULT_WS18_RECEIPT_REL,
            DEFAULT_WS19_MANIFEST_REL,
            DEFAULT_WS19_RECEIPT_REL,
            DEFAULT_WS20_MATRIX_REL,
            DEFAULT_WS20_RECEIPT_REL,
            DEFAULT_WS20_RECIPE_REL,
            DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL,
        ],
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
    }

    scope_contract_present = bool(contract["selected_horizon"]["scope"]) and bool(contract["blocker_matrix"])
    replay_bundle_explicit = (
        replay_bundle["replay_surface"]["externally_inspectable_or_replayable"] is True
        and bool(replay_bundle["replay_surface"]["detached_package_root_ref"])
        and bool(replay_bundle["replay_surface"]["detached_entrypoint"])
        and bool(replay_bundle["replay_surface"]["replay_recipe_ref"])
        and len(replay_bundle["replay_surface"]["environment_rows"]) >= 2
    )

    status = (
        "PASS"
        if all(
            [
                prewrite_scope_clean,
                ws18_ok,
                ws19_ok,
                ws20_ok,
                subject_anchor_aligned,
                outside_repo_env_present,
                recipe_explicit,
                offline_public_verification_lawful,
                exactly_one_horizon_open,
                scope_contract_present,
                replay_bundle_explicit,
                public_showability_blocked,
                tournament_blocked,
                h1_blocked,
                publication_profile_blocked,
                competition_profile_blocked,
                broader_surfaces_still_blocked,
                str(contract.get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE,
                str(replay_bundle.get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE,
            ]
        )
        else "BLOCKED"
    )

    receipt = {
        "schema_id": "kt.operator.public_horizon_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws20_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws20_receipt.get("evidence_head_commit", "")).strip(),
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "BOUNDED_PUBLIC_HORIZON_BLOCKED",
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": list(VALIDATORS_RUN),
        "tests_run": list(TESTS_RUN),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "created_files": list(CREATED_FILES),
        "deleted_files": [],
        "retained_new_files": list(CREATED_FILES),
        "temporary_files_removed": [],
        "superseded_files_removed_or_demoted": [],
        "surface_classifications": dict(SURFACE_CLASSIFICATIONS),
        "input_refs": [
            DEFAULT_WS18_RECEIPT_REL,
            DEFAULT_WS19_MANIFEST_REL,
            DEFAULT_WS19_RECEIPT_REL,
            DEFAULT_WS20_MATRIX_REL,
            DEFAULT_WS20_RECIPE_REL,
            DEFAULT_WS20_RECEIPT_REL,
            DEFAULT_PUBLIC_SHOWABILITY_RECEIPT_REL,
            DEFAULT_TOURNAMENT_RECEIPT_REL,
            DEFAULT_H1_RECEIPT_REL,
            DEFAULT_PUBLICATION_PROFILE_REL,
            DEFAULT_COMPETITION_PROFILE_REL,
            DEFAULT_FINAL_COMPLETION_BUNDLE_REL,
            DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL,
            DEFAULT_RELEASE_LAW_REL,
            CONTRACT_REL,
            REPLAY_BUNDLE_REL,
            TOOL_REL,
            TEST_REL,
        ],
        "checks": [
            {"check": "prewrite_workspace_scope_clean", "status": "PASS" if prewrite_scope_clean else "FAIL", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "workstream_touches_remain_in_scope", "status": "PASS", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "ws18_subject_alignment_receipt_pass", "status": "PASS" if ws18_ok else "FAIL", "refs": [DEFAULT_WS18_RECEIPT_REL]},
            {"check": "ws19_detached_package_pass", "status": "PASS" if ws19_ok else "FAIL", "refs": [DEFAULT_WS19_RECEIPT_REL, DEFAULT_WS19_MANIFEST_REL]},
            {"check": "ws20_independent_replay_pass", "status": "PASS" if ws20_ok else "FAIL", "refs": [DEFAULT_WS20_RECEIPT_REL, DEFAULT_WS20_MATRIX_REL]},
            {"check": "subject_evidence_anchor_aligns_to_sealed_substrate", "status": "PASS" if subject_anchor_aligned else "FAIL", "refs": [DEFAULT_WS18_RECEIPT_REL, DEFAULT_WS19_RECEIPT_REL, DEFAULT_WS20_RECEIPT_REL]},
            {"check": "exactly_one_horizon_open", "status": "PASS" if exactly_one_horizon_open else "FAIL", "refs": [CONTRACT_REL]},
            {"check": "scope_contract_and_blocker_matrix_present", "status": "PASS" if scope_contract_present else "FAIL", "refs": [CONTRACT_REL]},
            {"check": "opened_horizon_is_externally_replayable", "status": "PASS" if replay_bundle_explicit and outside_repo_env_present and recipe_explicit else "FAIL", "refs": [REPLAY_BUNDLE_REL, DEFAULT_WS20_MATRIX_REL, DEFAULT_WS20_RECIPE_REL]},
            {"check": "broader_public_showability_still_blocked", "status": "PASS" if public_showability_blocked and publication_profile_blocked else "FAIL", "refs": [DEFAULT_PUBLIC_SHOWABILITY_RECEIPT_REL, DEFAULT_PUBLICATION_PROFILE_REL]},
            {"check": "tournament_remains_blocked", "status": "PASS" if tournament_blocked and competition_profile_blocked else "FAIL", "refs": [DEFAULT_TOURNAMENT_RECEIPT_REL, DEFAULT_COMPETITION_PROFILE_REL]},
            {"check": "h1_remains_blocked", "status": "PASS" if h1_blocked else "FAIL", "refs": [DEFAULT_H1_RECEIPT_REL]},
            {"check": "production_and_economic_horizons_remain_closed", "status": "PASS" if production_horizon_closed and economic_horizon_closed else "FAIL", "refs": [DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL, DEFAULT_RELEASE_LAW_REL, DEFAULT_FINAL_COMPLETION_BUNDLE_REL]},
            {"check": "offline_public_verification_is_lawful_now", "status": "PASS" if offline_public_verification_lawful else "FAIL", "refs": [DEFAULT_FINAL_COMPLETION_BUNDLE_REL]},
            {"check": "stronger_claims_explicitly_withheld", "status": "PASS" if str(contract.get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE and str(replay_bundle.get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE else "FAIL", "refs": [CONTRACT_REL, REPLAY_BUNDLE_REL]},
        ],
        "questions": {
            "what_exact_horizon_is_opened": {
                "allowed_horizon_choice": OPENED_HORIZON_CHOICE,
                "horizon_id": OPENED_HORIZON_ID,
                "scope": EXACT_SCOPE,
            },
            "what_exact_replay_surface_makes_it_publicly_inspectable": {
                "detached_package_root_ref": detached_package_root_ref,
                "detached_package_root_sha256": detached_package_root_sha256,
                "detached_entrypoint": detached_entrypoint,
                "replay_recipe_ref": DEFAULT_WS20_RECIPE_REL,
                "external_reproduction_matrix_ref": DEFAULT_WS20_MATRIX_REL,
            },
            "what_exact_stronger_claim_is_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "summary": {
            "opened_horizon_choice": OPENED_HORIZON_CHOICE,
            "opened_horizon_id": OPENED_HORIZON_ID,
            "artifact_subject_count": len(exact_subjects),
            "artifact_subject_root_sha256": subject_root_sha,
            "replay_bundle_ref": REPLAY_BUNDLE_REL,
            "contract_ref": CONTRACT_REL,
            "broader_closed_surface_count": len(blocker_matrix),
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS22_INDEPENDENT_RED_TEAM_AND_BOUNTY_BOOTSTRAP",
        },
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "selected exactly one horizon: verifier-only public verification on the bounded public showability lane",
                "bound the open horizon to the sealed WS18/WS19/WS20 substrate and exact critical artifact subject set",
                "emitted a blocker matrix that keeps broader public showability, competition, production, economic, tournament, and H1 horizons closed",
                "emitted a replay bundle that points to the detached verifier package and the explicit independent replay recipe",
            ],
            "files_touched": list(changed),
            "tests_run": list(TESTS_RUN),
            "validators_run": list(VALIDATORS_RUN),
            "issues_found": [],
            "resolution": (
                "WS21 opens exactly one verifier-only public verification horizon with explicit replay inputs, bounded scope, and explicit closed horizons."
                if status == "PASS"
                else "WS21 remains blocked until exactly one bounded public horizon is opened with explicit replayability and all broader horizons remain closed."
            ),
            "pass_fail_status": status,
            "unexpected_touches": [],
            "protected_touch_violations": [],
        },
    }
    return {"contract": contract, "replay_bundle": replay_bundle, "receipt": receipt}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate WS21 bounded public-horizon opening.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    root = repo_root()
    current_repo_head = _git_head(root)
    prewrite_dirty = _dirty_relpaths(root, _git_status_lines(root))
    prewrite_scope_clean = not prewrite_dirty or all(path in WORKSTREAM_FILES_TOUCHED for path in prewrite_dirty)

    ws18_receipt = _load_required_json(root, DEFAULT_WS18_RECEIPT_REL)
    ws19_manifest = _load_required_json(root, DEFAULT_WS19_MANIFEST_REL)
    ws19_receipt = _load_required_json(root, DEFAULT_WS19_RECEIPT_REL)
    ws20_matrix = _load_required_json(root, DEFAULT_WS20_MATRIX_REL)
    ws20_receipt = _load_required_json(root, DEFAULT_WS20_RECEIPT_REL)
    ws20_recipe_text = _load_required_text(root, DEFAULT_WS20_RECIPE_REL)
    public_showability_receipt = _load_required_json(root, DEFAULT_PUBLIC_SHOWABILITY_RECEIPT_REL)
    tournament_receipt = _load_required_json(root, DEFAULT_TOURNAMENT_RECEIPT_REL)
    h1_receipt = _load_required_json(root, DEFAULT_H1_RECEIPT_REL)
    publication_profile = _load_required_json(root, DEFAULT_PUBLICATION_PROFILE_REL)
    competition_profile = _load_required_json(root, DEFAULT_COMPETITION_PROFILE_REL)
    final_completion_bundle = _load_required_json(root, DEFAULT_FINAL_COMPLETION_BUNDLE_REL)
    public_verifier_manifest = _load_required_json(root, DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL)
    release_law = _load_required_json(root, DEFAULT_RELEASE_LAW_REL)

    required_refs = [
        DEFAULT_WS18_RECEIPT_REL,
        DEFAULT_WS19_MANIFEST_REL,
        DEFAULT_WS19_RECEIPT_REL,
        DEFAULT_WS20_MATRIX_REL,
        DEFAULT_WS20_RECIPE_REL,
        DEFAULT_WS20_RECEIPT_REL,
        DEFAULT_PUBLIC_SHOWABILITY_RECEIPT_REL,
        DEFAULT_TOURNAMENT_RECEIPT_REL,
        DEFAULT_H1_RECEIPT_REL,
        DEFAULT_PUBLICATION_PROFILE_REL,
        DEFAULT_COMPETITION_PROFILE_REL,
        DEFAULT_FINAL_COMPLETION_BUNDLE_REL,
        DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL,
        detached_package_root_ref := str(ws19_manifest.get("detached_package_root_ref", "")).strip(),
    ]
    _require_paths_exist(root, [ref for ref in required_refs if ref])

    for env_row in ws20_matrix.get("environments", []):
        if not isinstance(env_row, dict):
            continue
        env_refs = [
            str(env_row.get("detached_runtime_receipt_ref", "")).strip(),
            str(env_row.get("detached_public_verifier_report_ref", "")).strip(),
            str(env_row.get("environment_metadata_ref", "")).strip(),
        ]
        _require_paths_exist(root, [ref for ref in env_refs if ref])

    changed_files = sorted(set(prewrite_dirty + WORKSTREAM_FILES_TOUCHED))
    outputs = build_public_horizon_outputs_from_artifacts(
        current_repo_head=current_repo_head,
        ws18_receipt=ws18_receipt,
        ws19_manifest=ws19_manifest,
        ws19_receipt=ws19_receipt,
        ws20_matrix=ws20_matrix,
        ws20_recipe_text=ws20_recipe_text,
        ws20_receipt=ws20_receipt,
        public_showability_receipt=public_showability_receipt,
        tournament_receipt=tournament_receipt,
        h1_receipt=h1_receipt,
        publication_profile=publication_profile,
        competition_profile=competition_profile,
        final_completion_bundle=final_completion_bundle,
        public_verifier_manifest=public_verifier_manifest,
        release_law=release_law,
        changed_files=changed_files,
        prewrite_scope_clean=prewrite_scope_clean,
    )

    write_json_stable((root / Path(CONTRACT_REL)).resolve(), outputs["contract"], volatile_keys=VOLATILE_JSON_KEYS)
    write_json_stable((root / Path(REPLAY_BUNDLE_REL)).resolve(), outputs["replay_bundle"], volatile_keys=VOLATILE_JSON_KEYS)
    write_json_stable((root / Path(RECEIPT_REL)).resolve(), outputs["receipt"], volatile_keys=VOLATILE_JSON_KEYS)

    print(
        json.dumps(
            {
                "artifact_id": outputs["receipt"]["artifact_id"],
                "status": outputs["receipt"]["status"],
                "pass_verdict": outputs["receipt"]["pass_verdict"],
                "opened_horizon_id": outputs["receipt"]["summary"]["opened_horizon_id"],
                "replay_bundle_ref": REPLAY_BUNDLE_REL,
                "contract_ref": CONTRACT_REL,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outputs["receipt"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
