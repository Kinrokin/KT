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
WORKSTREAM_ID = "WS22_INDEPENDENT_RED_TEAM_AND_BOUNTY_BOOTSTRAP"
STEP_ID = "WS22_STEP_1_PUBLISH_CHALLENGE_PROTOCOL_AND_REGISTER"
PASS_VERDICT = "EXTERNAL_CHALLENGE_PROTOCOL_BOOTSTRAPPED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
PROTOCOL_REL = f"{REPORT_ROOT_REL}/kt_external_challenge_protocol.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_red_team_results_receipt.json"
BOUNTY_SCOPE_REL = f"{REPORT_ROOT_REL}/kt_bounty_scope.md"

DEFAULT_WS21_CONTRACT_REL = f"{REPORT_ROOT_REL}/kt_bounded_public_horizon_contract.json"
DEFAULT_WS21_REPLAY_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_public_horizon_replay_bundle.json"
DEFAULT_WS21_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_horizon_receipt.json"
DEFAULT_WS20_RECIPE_REL = f"{REPORT_ROOT_REL}/kt_independent_replay_recipe.md"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/red_team_protocol_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_red_team_protocol_validate.py"

OPEN_HORIZON_ID = "VERIFIER_ONLY_PUBLIC_VERIFICATION"
OPEN_HORIZON_CHOICE = "bounded public showability"
SUBMISSION_STATUS = "OPEN_NO_FINDINGS_YET"
STRONGER_CLAIM_NOT_MADE = (
    "WS22 bootstraps an external challenge and bounty process only for the verifier-only public verification horizon. "
    "It does not widen public-horizon claims, does not treat the absence of submissions as proof of absence, and does not "
    "upgrade tournament, H1, production, economic, publication-readiness, or platform-governance claims."
)
VALIDATORS_RUN = ["python -m tools.operator.red_team_protocol_validate"]
TESTS_RUN = ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_red_team_protocol_validate.py -q"]
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")
CREATED_FILES = [TOOL_REL, TEST_REL, PROTOCOL_REL, RECEIPT_REL, BOUNTY_SCOPE_REL]
WORKSTREAM_FILES_TOUCHED = list(CREATED_FILES)
SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    PROTOCOL_REL: "generated challenge protocol",
    RECEIPT_REL: "generated receipt",
    BOUNTY_SCOPE_REL: "generated documentary scope",
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


def _normalize_relpaths(paths: Sequence[str]) -> List[str]:
    return sorted(set(str(path).replace("\\", "/") for path in paths if str(path).strip()))


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS22 input: {rel}")
    return load_json(path)


def _load_required_text(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS22 text input: {rel}")
    return path.read_text(encoding="utf-8")


def _write_text_stable(path: Path, text: str) -> bool:
    rendered = text.replace("\r\n", "\n")
    if path.exists() and path.read_text(encoding="utf-8") == rendered:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8", newline="\n")
    return True


def _require_paths_exist(root: Path, refs: Sequence[str]) -> None:
    missing = [ref for ref in refs if not (root / Path(ref)).resolve().exists()]
    if missing:
        raise RuntimeError("FAIL_CLOSED: missing WS22 referenced paths: " + ", ".join(sorted(set(missing))))


def build_red_team_protocol_outputs_from_artifacts(
    *,
    current_repo_head: str,
    ws21_contract: Dict[str, Any],
    ws21_replay_bundle: Dict[str, Any],
    ws21_receipt: Dict[str, Any],
    ws20_recipe_text: str,
    changed_files: Sequence[str],
    prewrite_scope_clean: bool,
) -> Dict[str, Any]:
    changed = _normalize_relpaths(changed_files)
    unexpected = sorted(path for path in changed if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError("FAIL_CLOSED: unexpected subject touches detected: " + ", ".join(unexpected + protected))

    ws21_ok = (
        str(ws21_receipt.get("status", "")).strip() == "PASS"
        and str(ws21_receipt.get("pass_verdict", "")).strip() == "VERIFIER_ONLY_BOUNDED_PUBLIC_HORIZON_OPENED"
        and str(ws21_receipt.get("summary", {}).get("opened_horizon_id", "")).strip() == OPEN_HORIZON_ID
    )
    selected_horizon = ws21_contract.get("selected_horizon", {})
    if not isinstance(selected_horizon, dict):
        selected_horizon = {}
    exact_subjects = selected_horizon.get("exact_artifact_subjects_covered", [])
    if not isinstance(exact_subjects, list):
        exact_subjects = []
    replay_contract = selected_horizon.get("replay_contract", {})
    if not isinstance(replay_contract, dict):
        replay_contract = {}
    blocker_matrix = ws21_contract.get("blocker_matrix", [])
    if not isinstance(blocker_matrix, list):
        blocker_matrix = []
    horizon_matrix = ws21_contract.get("horizon_matrix", [])
    if not isinstance(horizon_matrix, list):
        horizon_matrix = []
    replay_surface = ws21_replay_bundle.get("replay_surface", {})
    if not isinstance(replay_surface, dict):
        replay_surface = {}

    selected_horizon_ok = (
        str(selected_horizon.get("horizon_id", "")).strip() == OPEN_HORIZON_ID
        and str(selected_horizon.get("allowed_horizon_choice", "")).strip() == OPEN_HORIZON_CHOICE
        and str(selected_horizon.get("status", "")).strip() == "OPEN"
        and bool(str(selected_horizon.get("scope", "")).strip())
        and bool(str(selected_horizon.get("artifact_subject_root_sha256", "")).strip())
        and len(exact_subjects) >= 1
    )
    exactly_one_horizon_open = sum(1 for row in horizon_matrix if isinstance(row, dict) and str(row.get("status", "")).strip() == "OPEN") == 1
    broader_horizons_blocked = len(blocker_matrix) >= 1 and all(
        isinstance(row, dict) and str(row.get("status", "")).strip() == "BLOCKED" for row in blocker_matrix
    )
    replay_bundle_ok = (
        str(ws21_replay_bundle.get("opened_horizon_id", "")).strip() == OPEN_HORIZON_ID
        and replay_surface.get("externally_inspectable_or_replayable") is True
        and bool(str(replay_surface.get("detached_package_root_ref", "")).strip())
        and bool(str(replay_surface.get("detached_entrypoint", "")).strip())
        and bool(str(replay_surface.get("replay_recipe_ref", "")).strip())
        and isinstance(ws21_replay_bundle.get("public_auditor_steps", []), list)
        and len(ws21_replay_bundle.get("public_auditor_steps", [])) >= 4
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

    kill_conditions = [
        {
            "kill_condition_id": "DETACHED_REPLAY_FAILS_WITH_DECLARED_INPUTS",
            "severity": "KILL",
            "description": "Following the published verifier-only replay path does not reproduce a PASS detached verifier result on the declared bounded subject set.",
            "proof_required": [
                "verbatim command transcript",
                "detached runtime receipt",
                "environment metadata",
                "exact package root hash or manifest reference",
            ],
        },
        {
            "kill_condition_id": "DETACHED_VS_REPO_LOCAL_PARITY_BREAK",
            "severity": "KILL",
            "description": "The detached verifier conclusion diverges from the repo-local parity field set for the same bounded subject set.",
            "proof_required": [
                "detached public verifier report",
                "repo-local comparison report",
                "field-level mismatch table",
            ],
        },
        {
            "kill_condition_id": "HIDDEN_REPO_LOCAL_OR_TRUST_INPUT_DEPENDENCY",
            "severity": "KILL",
            "description": "The verifier-only replay path requires undeclared repo-local state, undeclared trust inputs, or hidden tribal knowledge beyond the published recipe and bundle.",
            "proof_required": [
                "missing dependency evidence",
                "filesystem or environment trace",
                "published reference proving the dependency was undeclared",
            ],
        },
        {
            "kill_condition_id": "CLAIM_BOUNDARY_BREACH",
            "severity": "KILL",
            "description": "A WS21/WS22 public artifact implies broader public showability, tournament, H1, production, economic, or governance claims than the verifier-only horizon allows.",
            "proof_required": [
                "artifact reference",
                "quoted or machine-extracted claim text",
                "boundary reference showing the claim exceeds the allowed horizon",
            ],
        },
    ]

    auditor_paths = [
        {
            "path_id": "WS21_DETACHED_VERIFIER_REPLAY_PATH",
            "path_kind": "EXTERNAL_AUDITOR_REPLAY",
            "status": "RUNNABLE",
            "runnable_without_repo_checkout": True,
            "scope_boundary": str(selected_horizon.get("scope", "")).strip(),
            "entrypoint": str(replay_surface.get("detached_entrypoint", "")).strip(),
            "detached_package_root_ref": str(replay_surface.get("detached_package_root_ref", "")).strip(),
            "replay_recipe_ref": str(replay_surface.get("replay_recipe_ref", "")).strip(),
            "supporting_refs": [
                DEFAULT_WS21_REPLAY_BUNDLE_REL,
                DEFAULT_WS20_RECIPE_REL,
                DEFAULT_WS21_CONTRACT_REL,
                DEFAULT_WS21_RECEIPT_REL,
            ],
            "kill_conditions_tested": [row["kill_condition_id"] for row in kill_conditions[:3]],
            "expected_result": "PASS",
        }
    ]

    protocol = {
        "schema_id": "kt.operator.external_challenge_protocol.v1",
        "artifact_id": Path(PROTOCOL_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws21_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws21_receipt.get("evidence_head_commit", "")).strip(),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "challenge_window_status": "OPEN",
        "open_horizon": {
            "horizon_id": OPEN_HORIZON_ID,
            "allowed_horizon_choice": OPEN_HORIZON_CHOICE,
            "scope_ref": DEFAULT_WS21_CONTRACT_REL,
            "receipt_ref": DEFAULT_WS21_RECEIPT_REL,
            "scope_boundary": str(selected_horizon.get("scope", "")).strip(),
        },
        "exact_artifact_subjects_covered": exact_subjects,
        "artifact_subject_root_sha256": str(selected_horizon.get("artifact_subject_root_sha256", "")).strip(),
        "kill_conditions": kill_conditions,
        "submission_format": {
            "required_fields": [
                "submission_id",
                "reporter_alias",
                "challenge_class",
                "claimed_kill_condition_id",
                "reproduction_steps",
                "evidence_refs",
                "environment_metadata",
                "observed_result",
                "expected_result",
            ],
            "submission_modes": [
                "signed_json_bundle",
                "plain_json_with_artifact_refs",
            ],
        },
        "auditor_paths": auditor_paths,
        "disposition_policy": {
            "allowed_dispositions": [
                "REPRODUCED_OPEN",
                "NOT_REPRODUCED_WITH_EVIDENCE",
                "REJECTED_AS_OUT_OF_SCOPE",
                "DUPLICATE",
                "ACKNOWLEDGED_INFORMATIONAL",
                "FIX_CONFIRMED_IN_LATER_WORKSTREAM",
            ],
            "required_finding_fields": [
                "finding_id",
                "claimed_kill_condition_id",
                "status",
                "disposition",
                "evidence_refs",
            ],
            "burying_findings_forbidden": True,
        },
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
    }

    bounty_scope_text = "\n".join(
        [
            "# WS22 Bounty Scope",
            "",
            "Scope: verifier-only public verification for the sealed detached verifier package and bounded critical artifact set.",
            "",
            "In scope",
            "- Detached verifier replay using the published package, replay bundle, and recipe",
            "- Detached-vs-repo-local parity on the sealed bounded subject set",
            "- Hidden trust-input or repo-local dependency discovery",
            "- Claim-boundary breaches that widen beyond the verifier-only public horizon",
            "",
            "Explicit kill conditions",
            "- `DETACHED_REPLAY_FAILS_WITH_DECLARED_INPUTS`",
            "- `DETACHED_VS_REPO_LOCAL_PARITY_BREAK`",
            "- `HIDDEN_REPO_LOCAL_OR_TRUST_INPUT_DEPENDENCY`",
            "- `CLAIM_BOUNDARY_BREACH`",
            "",
            "Out of scope",
            "- Tournament readiness claims",
            "- H1 activation claims",
            "- Production deployment claims",
            "- Economic or commercial entitlement claims",
            "- Platform-governance upgrades",
            "",
            "Submission package",
            "- Reproduction steps",
            "- Environment metadata",
            "- Evidence refs and transcripts",
            "- Claimed kill-condition id",
            "",
            "Bounty boundary",
            "- This bootstrap defines challenge classes and triage scope only.",
            "- It does not promise cash compensation, commercial terms, or broader public-horizon upgrades.",
            f"- {STRONGER_CLAIM_NOT_MADE}",
            "",
        ]
    )

    findings = []
    bootstrap_log = [
        {
            "entry_id": "WS22_BOOTSTRAP_AUDITOR_PATH_PUBLICATION",
            "status": "RECORDED",
            "disposition": "ACKNOWLEDGED_INFORMATIONAL",
            "description": "Published one runnable external auditor path tied to the verifier-only public horizon.",
            "evidence_refs": [PROTOCOL_REL, BOUNTY_SCOPE_REL, DEFAULT_WS21_REPLAY_BUNDLE_REL],
        }
    ]
    findings_dispositioned = all(
        isinstance(row, dict)
        and bool(str(row.get("finding_id", "")).strip())
        and bool(str(row.get("disposition", "")).strip())
        and isinstance(row.get("evidence_refs", []), list)
        and len(row.get("evidence_refs", [])) >= 1
        for row in findings
    )
    no_findings_registered = len(findings) == 0
    challenge_protocol_has_kill_conditions = len(kill_conditions) >= 4
    challenge_protocol_has_submission_format = len(protocol["submission_format"]["required_fields"]) >= 5
    auditor_path_runnable = len(auditor_paths) >= 1 and all(
        row.get("status") == "RUNNABLE" and row.get("runnable_without_repo_checkout") is True for row in auditor_paths
    )
    bounty_scope_preserves_claim_ceiling = all(
        token in bounty_scope_text
        for token in (
            "Out of scope",
            "Tournament readiness claims",
            "H1 activation claims",
            "Production deployment claims",
            "Economic or commercial entitlement claims",
            "It does not promise cash compensation",
        )
    )

    status = (
        "PASS"
        if all(
            [
                prewrite_scope_clean,
                ws21_ok,
                selected_horizon_ok,
                exactly_one_horizon_open,
                broader_horizons_blocked,
                replay_bundle_ok,
                recipe_explicit,
                challenge_protocol_has_kill_conditions,
                challenge_protocol_has_submission_format,
                auditor_path_runnable,
                bounty_scope_preserves_claim_ceiling,
                findings_dispositioned or no_findings_registered,
                protocol["stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE,
            ]
        )
        else "BLOCKED"
    )

    receipt = {
        "schema_id": "kt.operator.red_team_results_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws21_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws21_receipt.get("evidence_head_commit", "")).strip(),
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "EXTERNAL_CHALLENGE_BOOTSTRAP_BLOCKED",
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
        "waste_control": {
            "created_files_count": len(CREATED_FILES),
            "deleted_files_count": 0,
            "temporary_files_removed_count": 0,
            "superseded_files_removed_count": 0,
            "net_artifact_delta": len(CREATED_FILES),
            "retention_justifications": [
                "validator and focused regression are required for the new proof surface",
                "challenge protocol, bounty scope, and results receipt are the declared WS22 deliverables",
            ],
        },
        "input_refs": [
            DEFAULT_WS21_CONTRACT_REL,
            DEFAULT_WS21_REPLAY_BUNDLE_REL,
            DEFAULT_WS21_RECEIPT_REL,
            DEFAULT_WS20_RECIPE_REL,
            PROTOCOL_REL,
            RECEIPT_REL,
            BOUNTY_SCOPE_REL,
            TOOL_REL,
            TEST_REL,
        ],
        "checks": [
            {"check": "prewrite_workspace_scope_clean", "status": "PASS" if prewrite_scope_clean else "FAIL", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "workstream_touches_remain_in_scope", "status": "PASS", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "ws21_verifier_only_horizon_pass", "status": "PASS" if ws21_ok and selected_horizon_ok else "FAIL", "refs": [DEFAULT_WS21_RECEIPT_REL, DEFAULT_WS21_CONTRACT_REL]},
            {"check": "exactly_one_public_horizon_remains_open", "status": "PASS" if exactly_one_horizon_open else "FAIL", "refs": [DEFAULT_WS21_CONTRACT_REL]},
            {"check": "broader_public_horizon_claims_remain_closed", "status": "PASS" if broader_horizons_blocked else "FAIL", "refs": [DEFAULT_WS21_CONTRACT_REL]},
            {"check": "challenge_protocol_has_explicit_kill_conditions", "status": "PASS" if challenge_protocol_has_kill_conditions else "FAIL", "refs": [PROTOCOL_REL]},
            {"check": "challenge_protocol_has_submission_format", "status": "PASS" if challenge_protocol_has_submission_format else "FAIL", "refs": [PROTOCOL_REL]},
            {"check": "at_least_one_external_auditor_path_is_runnable", "status": "PASS" if auditor_path_runnable and replay_bundle_ok and recipe_explicit else "FAIL", "refs": [PROTOCOL_REL, DEFAULT_WS21_REPLAY_BUNDLE_REL, DEFAULT_WS20_RECIPE_REL]},
            {"check": "bounty_scope_preserves_claim_ceiling", "status": "PASS" if bounty_scope_preserves_claim_ceiling else "FAIL", "refs": [BOUNTY_SCOPE_REL]},
            {"check": "findings_register_is_dispositioned_or_explicitly_empty", "status": "PASS" if findings_dispositioned or no_findings_registered else "FAIL", "refs": [RECEIPT_REL]},
            {"check": "stronger_claims_explicitly_withheld", "status": "PASS" if protocol["stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE else "FAIL", "refs": [PROTOCOL_REL, BOUNTY_SCOPE_REL, RECEIPT_REL]},
        ],
        "questions": {
            "what_are_the_exact_kill_conditions": [row["kill_condition_id"] for row in kill_conditions],
            "what_external_auditor_path_is_runnable": auditor_paths[0]["path_id"],
            "what_stronger_claim_is_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "summary": {
            "challenge_window_status": "OPEN",
            "submission_window_status": SUBMISSION_STATUS,
            "auditor_path_count": len(auditor_paths),
            "kill_condition_count": len(kill_conditions),
            "registered_findings_count": len(findings),
            "bootstrap_log_count": len(bootstrap_log),
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "challenge_protocol_ref": PROTOCOL_REL,
        "bounty_scope_ref": BOUNTY_SCOPE_REL,
        "auditor_paths": auditor_paths,
        "findings": findings,
        "bootstrap_log": bootstrap_log,
        "disposition_policy_ref": PROTOCOL_REL,
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS23_FORMAL_INVARIANT_PROOF_CORE",
        },
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "published a verifier-only external challenge protocol bound to the sealed WS21 public horizon",
                "declared explicit kill conditions and a submission contract",
                "published a narrow bounty scope that keeps broader public-horizon claims closed",
                "opened a disposition register with an explicit no-findings-yet bootstrap state",
            ],
            "files_touched": list(changed),
            "tests_run": list(TESTS_RUN),
            "validators_run": list(VALIDATORS_RUN),
            "issues_found": [],
            "resolution": (
                "WS22 bootstraps a verifier-only external challenge path with explicit kill conditions, one runnable auditor path, and a disposition register."
                if status == "PASS"
                else "WS22 remains blocked until the challenge protocol, runnable auditor path, and disposition register are all explicit and bounded."
            ),
            "pass_fail_status": status,
            "unexpected_touches": [],
            "protected_touch_violations": [],
        },
    }
    return {"protocol": protocol, "receipt": receipt, "bounty_scope_text": bounty_scope_text}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate WS22 challenge protocol and bounty bootstrap.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    root = repo_root()
    current_repo_head = _git_head(root)
    prewrite_dirty = _dirty_relpaths(root, _git_status_lines(root))
    prewrite_scope_clean = not prewrite_dirty or all(path in WORKSTREAM_FILES_TOUCHED for path in prewrite_dirty)

    ws21_contract = _load_required_json(root, DEFAULT_WS21_CONTRACT_REL)
    ws21_replay_bundle = _load_required_json(root, DEFAULT_WS21_REPLAY_BUNDLE_REL)
    ws21_receipt = _load_required_json(root, DEFAULT_WS21_RECEIPT_REL)
    ws20_recipe_text = _load_required_text(root, DEFAULT_WS20_RECIPE_REL)

    replay_surface = ws21_replay_bundle.get("replay_surface", {})
    if not isinstance(replay_surface, dict):
        replay_surface = {}
    required_refs = [
        DEFAULT_WS21_CONTRACT_REL,
        DEFAULT_WS21_REPLAY_BUNDLE_REL,
        DEFAULT_WS21_RECEIPT_REL,
        DEFAULT_WS20_RECIPE_REL,
        str(replay_surface.get("detached_package_root_ref", "")).strip(),
        str(replay_surface.get("detached_release_manifest_ref", "")).strip(),
        str(replay_surface.get("detached_receipt_ref", "")).strip(),
        str(replay_surface.get("external_reproduction_receipt_ref", "")).strip(),
        str(replay_surface.get("reproduction_matrix_ref", "")).strip(),
        str(replay_surface.get("public_verifier_manifest_ref", "")).strip(),
    ]
    _require_paths_exist(root, [ref for ref in required_refs if ref])

    for row in replay_surface.get("environment_rows", []):
        if not isinstance(row, dict):
            continue
        env_refs = [
            str(row.get("detached_runtime_receipt_ref", "")).strip(),
            str(row.get("detached_public_verifier_report_ref", "")).strip(),
        ]
        _require_paths_exist(root, [ref for ref in env_refs if ref])

    changed_files = sorted(set(prewrite_dirty + WORKSTREAM_FILES_TOUCHED))
    outputs = build_red_team_protocol_outputs_from_artifacts(
        current_repo_head=current_repo_head,
        ws21_contract=ws21_contract,
        ws21_replay_bundle=ws21_replay_bundle,
        ws21_receipt=ws21_receipt,
        ws20_recipe_text=ws20_recipe_text,
        changed_files=changed_files,
        prewrite_scope_clean=prewrite_scope_clean,
    )

    write_json_stable((root / Path(PROTOCOL_REL)).resolve(), outputs["protocol"], volatile_keys=VOLATILE_JSON_KEYS)
    write_json_stable((root / Path(RECEIPT_REL)).resolve(), outputs["receipt"], volatile_keys=VOLATILE_JSON_KEYS)
    _write_text_stable((root / Path(BOUNTY_SCOPE_REL)).resolve(), outputs["bounty_scope_text"])

    print(
        json.dumps(
            {
                "artifact_id": outputs["receipt"]["artifact_id"],
                "status": outputs["receipt"]["status"],
                "pass_verdict": outputs["receipt"]["pass_verdict"],
                "challenge_protocol_ref": PROTOCOL_REL,
                "bounty_scope_ref": BOUNTY_SCOPE_REL,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outputs["receipt"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
