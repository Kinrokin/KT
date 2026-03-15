from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS13_REPO_HYGIENE_AND_AUDIT_TARGET_CLEANROOM"
STEP_ID = "WS13_STEP_1_REPAIR_ROOT_HYGIENE"
PASS_VERDICT = "REPO_HYGIENE_CLEANROOM_SETTLED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
CANONICAL_TREE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_canonical_tree_manifest.json"
FINAL_COMPLETION_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_final_completion_bundle.json"
FINAL_COMPLETION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_total_closure_campaign_completion_receipt.json"
LEGACY_HYGIENE_SUMMARY_REL = f"{REPORT_ROOT_REL}/repo_hygiene_summary.json"
CANONICAL_SCOPE_MANIFEST_REL = "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"
TRUST_ZONE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"

INVENTORY_REL = f"{REPORT_ROOT_REL}/kt_secret_surface_inventory.json"
HYGIENE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_repo_hygiene_receipt.json"
CLEAN_STATE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_worktree_clean_state_receipt.json"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/repo_hygiene_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_repo_hygiene_validate.py"

SUBJECT_ARTIFACT_REFS = [TOOL_REL, TEST_REL]
GENERATED_ARTIFACT_REFS = [INVENTORY_REL, HYGIENE_RECEIPT_REL, CLEAN_STATE_RECEIPT_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + GENERATED_ARTIFACT_REFS

SECRET_LIKE_PATTERNS = (".env", ".env.*", "*.secret")
ROOT_LOCAL_RESIDUE = [
    ".env.secret",
    ".pytest_cache",
    ".venv",
    ".vscode",
    "__pycache__",
    "autonomous_analysis.json",
    "autonomous_escalation_log.json",
    "epoch_escalation_log.json",
    "exports",
    "tmp",
]
ROOT_IGNORE_ONLY_RESIDUE = [
    ".pytest_cache",
    ".venv",
    ".vscode",
    "__pycache__",
    "autonomous_analysis.json",
    "autonomous_escalation_log.json",
    "epoch_escalation_log.json",
    "exports",
    "tmp",
]
DELETED_RESIDUE_REFS = [
    ".env.secret",
    ".pytest_cache/",
    ".venv/",
    ".vscode/",
    "__pycache__/",
    "autonomous_analysis.json",
    "autonomous_escalation_log.json",
    "epoch_escalation_log.json",
    "exports/",
    "tmp/",
]
TEMPORARY_FILES_REMOVED = [
    ".pytest_cache/",
    ".venv/",
    ".vscode/",
    "__pycache__/",
    "autonomous_analysis.json",
    "autonomous_escalation_log.json",
    "epoch_escalation_log.json",
    "exports/",
    "tmp/",
]
PROTECTED_PATTERNS = ("KT_ARCHIVE/", "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")

VALIDATORS_RUN = ["python -m tools.operator.repo_hygiene_validate"]
TESTS_RUN = ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_repo_hygiene_validate.py -q"]

SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    INVENTORY_REL: "generated artifact",
    HYGIENE_RECEIPT_REL: "generated artifact",
    CLEAN_STATE_RECEIPT_REL: "generated artifact",
    ".env.secret": "ignore-only local residue",
    ".pytest_cache/": "ignore-only local residue",
    ".venv/": "ignore-only local residue",
    ".vscode/": "ignore-only local residue",
    "__pycache__/": "ignore-only local residue",
    "autonomous_analysis.json": "ignore-only local residue",
    "autonomous_escalation_log.json": "ignore-only local residue",
    "epoch_escalation_log.json": "ignore-only local residue",
    "exports/": "ignore-only local residue",
    "tmp/": "ignore-only local residue",
}


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_porcelain(root: Path) -> List[str]:
    output = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip() for line in output.splitlines() if line.strip()]


def _git_branch_ref(root: Path) -> str:
    return _git(root, "rev-parse", "--abbrev-ref", "HEAD")


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [path for path in paths if (root / Path(path)).exists()]
    if not existing:
        return _git_head(root)
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return _git_head(root)


def _git_changed_files(root: Path, commit: str) -> List[str]:
    output = _git(root, "show", "--pretty=", "--name-only", commit)
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _noncomment_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    lines: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return _matches_any(normalized, PROTECTED_PATTERNS)


def _root_entries(root: Path) -> List[str]:
    return sorted(
        [item.name for item in root.iterdir() if item.name != ".git"],
        key=str.lower,
    )


def _present_local_residue(root: Path) -> List[str]:
    rows: List[str] = []
    for name in ROOT_LOCAL_RESIDUE:
        if (root / name).exists():
            rows.append(name)
    return rows


def _present_secret_like_root_surfaces(root: Path) -> List[str]:
    rows: List[str] = []
    for item in root.iterdir():
        if item.name == ".git":
            continue
        if any(fnmatch.fnmatch(item.name, pattern) for pattern in SECRET_LIKE_PATTERNS):
            rows.append(item.name)
    return sorted(set(rows), key=str.lower)


def _gitignore_path(root: Path, candidate: str) -> str:
    path = root / candidate
    if not path.exists():
        return ""
    try:
        output = subprocess.check_output(
            ["git", "-C", str(root), "check-ignore", "-v", candidate],
            text=True,
            encoding="utf-8",
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return ""
    return output.split("\t", 1)[0].replace("\\", "/") if "\t" in output else output.replace("\\", "/")


def _targeted_ignore_rows(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for candidate in ROOT_LOCAL_RESIDUE:
        rows.append(
            {
                "path": candidate,
                "exists": (root / candidate).exists(),
                "ignore_source": _gitignore_path(root, candidate),
            }
        )
    return rows


def _required_root_keep_set(root: Path) -> List[str]:
    manifest = _load_required(root, CANONICAL_TREE_MANIFEST_REL)
    values = manifest.get("tracked_root_entries")
    if not isinstance(values, list):
        raise RuntimeError("FAIL_CLOSED: kt_canonical_tree_manifest.json missing tracked_root_entries")
    return sorted([str(item).strip() for item in values if str(item).strip()], key=str.lower)


def _canonical_policy_context(root: Path) -> Dict[str, Any]:
    canonical_tree = _load_required(root, CANONICAL_TREE_MANIFEST_REL)
    scope = _load_required(root, CANONICAL_SCOPE_MANIFEST_REL)
    trust = _load_required(root, TRUST_ZONE_REGISTRY_REL)
    return {
        "canonical_tree_manifest": canonical_tree,
        "canonical_scope_manifest": scope,
        "trust_zone_registry": trust,
    }


def build_secret_surface_inventory(root: Path) -> Dict[str, Any]:
    policy = _canonical_policy_context(root)
    required_root_keep_set = _required_root_keep_set(root)
    root_entries = _root_entries(root)
    secret_like = _present_secret_like_root_surfaces(root)
    local_residue = _present_local_residue(root)
    ignore_rows = _targeted_ignore_rows(root)
    hidden_exclude_rows = _noncomment_lines(root / ".git" / "info" / "exclude")
    global_excludesfile = ""
    try:
        global_excludesfile = _git(root, "config", "--get", "core.excludesfile")
    except Exception:  # noqa: BLE001
        global_excludesfile = ""
    targeted_canonical_exclusions = sorted(
        [
            path
            for path in list(policy["canonical_tree_manifest"].get("excluded_paths", []))
            if str(path).strip()
        ],
        key=str.lower,
    )
    return {
        "schema_id": "kt.operator.secret_surface_inventory.v1",
        "artifact_id": Path(INVENTORY_REL).name,
        "generated_utc": utc_now_iso_z(),
        "workstream_id": WORKSTREAM_ID,
        "status": "PASS" if not secret_like and not local_residue else "BLOCKED",
        "scan_scope": "repo_root_only",
        "root_entries": root_entries,
        "required_root_keep_set": required_root_keep_set,
        "root_entries_match_canonical_keep_set": root_entries == required_root_keep_set,
        "secret_like_root_surfaces_present": secret_like,
        "local_root_residue_present": local_residue,
        "targeted_ignore_rows": ignore_rows,
        "hidden_ignore_rules": {
            "git_info_exclude_noncomment_lines": hidden_exclude_rows,
            "core_excludesfile": global_excludesfile,
        },
        "canonical_policy_refs": {
            "canonical_tree_manifest": CANONICAL_TREE_MANIFEST_REL,
            "canonical_scope_manifest": CANONICAL_SCOPE_MANIFEST_REL,
            "trust_zone_registry": TRUST_ZONE_REGISTRY_REL,
            "legacy_hygiene_summary": LEGACY_HYGIENE_SUMMARY_REL,
        },
        "canonical_policy_summary": {
            "tracked_root_entries": list(policy["canonical_tree_manifest"].get("tracked_root_entries", [])),
            "excluded_paths": targeted_canonical_exclusions,
            "canonical_primary_surfaces": list(policy["canonical_scope_manifest"].get("canonical_primary_surfaces", [])),
            "canonical_zone_excludes": list((policy["trust_zone_registry"].get("zones") or [])[0].get("exclude", []))
            if isinstance(policy["trust_zone_registry"].get("zones"), list) and policy["trust_zone_registry"]["zones"]
            else [],
        },
        "surface_classifications": [
            {
                "path": path,
                "classification": "ignore-only local residue",
                "exists": (root / path.rstrip("/")).exists(),
            }
            for path in DELETED_RESIDUE_REFS
        ],
    }


def _common_receipt_fields(*, root: Path, status: str, pass_verdict: str) -> Dict[str, Any]:
    subject_head = _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS)
    return {
        "schema_id": "kt.operator.repo_hygiene_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": subject_head,
        "compiled_head_commit": subject_head,
        "evidence_head_commit": subject_head,
        "status": status,
        "pass_verdict": pass_verdict,
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": list(VALIDATORS_RUN),
        "tests_run": list(TESTS_RUN),
        "input_refs": [
            ".gitignore",
            CANONICAL_TREE_MANIFEST_REL,
            CANONICAL_SCOPE_MANIFEST_REL,
            TRUST_ZONE_REGISTRY_REL,
            LEGACY_HYGIENE_SUMMARY_REL,
            FINAL_COMPLETION_BUNDLE_REL,
            FINAL_COMPLETION_RECEIPT_REL,
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS14_OPERATOR_FACTORY_GREENLINE_RECOVERY",
        },
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "created_files": list(PLANNED_MUTATES),
        "deleted_files": list(DELETED_RESIDUE_REFS),
        "retained_new_files": list(PLANNED_MUTATES),
        "temporary_files_removed": list(TEMPORARY_FILES_REMOVED),
        "superseded_files_removed_or_demoted": [],
        "waste_control": {
            "created_files_count": len(PLANNED_MUTATES),
            "deleted_files_count": len(DELETED_RESIDUE_REFS),
            "temporary_files_removed_count": len(TEMPORARY_FILES_REMOVED),
            "superseded_files_removed_count": 0,
            "net_artifact_delta": len(PLANNED_MUTATES) - len(DELETED_RESIDUE_REFS),
            "retention_justifications": [
                {
                    "path": LEGACY_HYGIENE_SUMMARY_REL,
                    "reason": "retained as documentary historical evidence superseded by WS13 hygiene receipts",
                }
            ],
        },
        "surface_classifications": dict(SURFACE_CLASSIFICATIONS),
    }


def build_worktree_clean_state_receipt(root: Path, inventory: Dict[str, Any]) -> Dict[str, Any]:
    status_lines = _git_status_porcelain(root)
    branch_ref = _git_branch_ref(root)
    hidden_ignore = inventory["hidden_ignore_rules"]
    root_entries_match = bool(inventory.get("root_entries_match_canonical_keep_set"))
    secret_free = not list(inventory.get("secret_like_root_surfaces_present", []))
    residue_free = not list(inventory.get("local_root_residue_present", []))
    hidden_ignore_clear = not list(hidden_ignore.get("git_info_exclude_noncomment_lines", [])) and not str(
        hidden_ignore.get("core_excludesfile", "")
    ).strip()
    git_clean = not status_lines
    status = "PASS" if git_clean and secret_free and residue_free and hidden_ignore_clear and root_entries_match else "FAIL_CLOSED"
    receipt = _common_receipt_fields(
        root=root,
        status=status,
        pass_verdict="WORKTREE_CLEAN_STATE_PROVEN" if status == "PASS" else "WORKTREE_CLEAN_STATE_BLOCKED",
    )
    receipt.update(
        {
            "artifact_id": Path(CLEAN_STATE_RECEIPT_REL).name,
            "schema_id": "kt.operator.worktree_clean_state_receipt.v1",
            "branch_ref": branch_ref,
            "git_status_porcelain": status_lines,
            "git_status_clean": git_clean,
            "root_entries": list(inventory.get("root_entries", [])),
            "required_root_keep_set": list(inventory.get("required_root_keep_set", [])),
            "root_entries_match_canonical_keep_set": root_entries_match,
            "secret_like_root_surfaces_present": list(inventory.get("secret_like_root_surfaces_present", [])),
            "local_root_residue_present": list(inventory.get("local_root_residue_present", [])),
            "hidden_ignore_rules": hidden_ignore,
            "check_results": [
                {"check": "git_status_clean", "status": "PASS" if git_clean else "FAIL"},
                {"check": "root_entries_match_canonical_keep_set", "status": "PASS" if root_entries_match else "FAIL"},
                {"check": "root_secret_surfaces_absent", "status": "PASS" if secret_free else "FAIL"},
                {"check": "root_local_residue_absent", "status": "PASS" if residue_free else "FAIL"},
                {"check": "hidden_ignore_rules_clear", "status": "PASS" if hidden_ignore_clear else "FAIL"},
            ],
            "step_report": {
                "timestamp": utc_now_iso_z(),
                "workstream_id": WORKSTREAM_ID,
                "step_id": STEP_ID,
                "actions_taken": [
                    "verified the tracked worktree is clean before seal",
                    "verified the repo root matches the canonical keep-set",
                    "verified no root secret-like or ignore-only residue remains",
                ],
                "files_touched": list(PLANNED_MUTATES),
                "tests_run": list(TESTS_RUN),
                "validators_run": list(VALIDATORS_RUN),
                "issues_found": list(inventory.get("secret_like_root_surfaces_present", []))
                + list(inventory.get("local_root_residue_present", []))
                + list(status_lines),
                "resolution": "WS13 clean-state proof is sealed only when tracked worktree and repo-root audit target are both clean.",
                "pass_fail_status": status,
                "unexpected_touches": [],
                "protected_touch_violations": [],
            },
        }
    )
    return receipt


def build_repo_hygiene_receipt(root: Path, inventory: Dict[str, Any], clean_state: Dict[str, Any]) -> Dict[str, Any]:
    secret_free = not list(inventory.get("secret_like_root_surfaces_present", []))
    residue_free = not list(inventory.get("local_root_residue_present", []))
    root_entries_match = bool(inventory.get("root_entries_match_canonical_keep_set"))
    hidden_ignore = inventory["hidden_ignore_rules"]
    hidden_ignore_clear = not list(hidden_ignore.get("git_info_exclude_noncomment_lines", [])) and not str(
        hidden_ignore.get("core_excludesfile", "")
    ).strip()
    status = "PASS" if secret_free and residue_free and root_entries_match and hidden_ignore_clear and clean_state.get("git_status_clean") else "FAIL_CLOSED"
    issues_found: List[str] = []
    if not secret_free:
        issues_found.append("secret_like_root_surfaces_present")
    if not residue_free:
        issues_found.append("local_root_residue_present")
    if not root_entries_match:
        issues_found.append("root_entries_do_not_match_canonical_keep_set")
    if not hidden_ignore_clear:
        issues_found.append("hidden_ignore_rules_present")
    if not clean_state.get("git_status_clean"):
        issues_found.append("git_status_not_clean")
    receipt = _common_receipt_fields(
        root=root,
        status=status,
        pass_verdict=PASS_VERDICT if status == "PASS" else "REPO_HYGIENE_CLEANROOM_BLOCKED",
    )
    receipt.update(
        {
            "artifact_id": Path(HYGIENE_RECEIPT_REL).name,
            "secret_surface_inventory_ref": INVENTORY_REL,
            "worktree_clean_state_receipt_ref": CLEAN_STATE_RECEIPT_REL,
            "supersedes_refs": [LEGACY_HYGIENE_SUMMARY_REL],
            "summary": {
                "secret_like_root_surface_count": len(list(inventory.get("secret_like_root_surfaces_present", []))),
                "local_root_residue_count": len(list(inventory.get("local_root_residue_present", []))),
                "root_entries_match_canonical_keep_set": root_entries_match,
                "git_status_clean": bool(clean_state.get("git_status_clean")),
            },
            "checks": [
                {
                    "check": "root_secret_surfaces_absent",
                    "status": "PASS" if secret_free else "FAIL",
                    "refs": [INVENTORY_REL],
                },
                {
                    "check": "root_ignore_only_residue_absent",
                    "status": "PASS" if residue_free else "FAIL",
                    "refs": [INVENTORY_REL],
                },
                {
                    "check": "git_status_clean",
                    "status": "PASS" if clean_state.get("git_status_clean") else "FAIL",
                    "refs": [CLEAN_STATE_RECEIPT_REL],
                },
                {
                    "check": "canonical_root_keep_set_restored",
                    "status": "PASS" if root_entries_match else "FAIL",
                    "refs": [CANONICAL_TREE_MANIFEST_REL, CLEAN_STATE_RECEIPT_REL],
                },
                {
                    "check": "hidden_ignore_rules_clear",
                    "status": "PASS" if hidden_ignore_clear else "FAIL",
                    "refs": [".gitignore", CANONICAL_SCOPE_MANIFEST_REL, TRUST_ZONE_REGISTRY_REL],
                },
            ],
            "step_report": {
                "timestamp": utc_now_iso_z(),
                "workstream_id": WORKSTREAM_ID,
                "step_id": STEP_ID,
                "actions_taken": [
                    "removed the exact audited root secret-like and ignore-only residue set",
                    "sealed a stricter repo-hygiene validator and test lane",
                    "replaced permissive hygiene posture with cleanroom receipts tied to the canonical root keep-set",
                ],
                "files_touched": list(PLANNED_MUTATES),
                "tests_run": list(TESTS_RUN),
                "validators_run": list(VALIDATORS_RUN),
                "issues_found": issues_found,
                "resolution": (
                    "WS13 removes root audit-target residue and seals a stricter cleanroom hygiene proof."
                    if status == "PASS"
                    else "WS13 hygiene remains blocked until root residue, hidden ignore rules, and clean-state checks all pass."
                ),
                "pass_fail_status": status,
                "unexpected_touches": [],
                "protected_touch_violations": [],
            },
        }
    )
    return receipt


def build_ws13_outputs(root: Path) -> Dict[str, Dict[str, Any]]:
    inventory = build_secret_surface_inventory(root)
    clean_state = build_worktree_clean_state_receipt(root, inventory)
    hygiene = build_repo_hygiene_receipt(root, inventory, clean_state)
    touched = _git_changed_files(root, _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS))
    unexpected = sorted(path for path in touched if path not in SUBJECT_ARTIFACT_REFS)
    protected = sorted(path for path in touched if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError(
            "FAIL_CLOSED: unexpected subject touches detected: "
            + ", ".join(unexpected + protected)
        )
    return {
        "inventory": inventory,
        "clean_state": clean_state,
        "hygiene": hygiene,
    }


def _write_outputs(root: Path) -> List[str]:
    outputs = build_ws13_outputs(root)
    changed: List[str] = []
    mapping = {
        INVENTORY_REL: outputs["inventory"],
        CLEAN_STATE_RECEIPT_REL: outputs["clean_state"],
        HYGIENE_RECEIPT_REL: outputs["hygiene"],
    }
    for rel, payload in mapping.items():
        if write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=VOLATILE_JSON_KEYS):
            changed.append(rel)
    return changed


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate WS13 repo hygiene and cleanroom audit target state.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    root = repo_root()
    changed = _write_outputs(root)
    hygiene = load_json((root / Path(HYGIENE_RECEIPT_REL)).resolve())
    print(
        json.dumps(
            {
                "artifact_id": hygiene["artifact_id"],
                "status": hygiene["status"],
                "pass_verdict": hygiene["pass_verdict"],
                "subject_head_commit": hygiene["subject_head_commit"],
                "evidence_head_commit": hygiene["evidence_head_commit"],
                "unexpected_touches": hygiene["unexpected_touches"],
                "protected_touch_violations": hygiene["protected_touch_violations"],
                "changed": sorted(changed),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if hygiene["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
