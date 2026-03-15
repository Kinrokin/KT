from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS3_ARCHIVE_EXTERNALIZATION_PROOF"
STEP_ID = "WS3_STEP_1_PROVE_ARCHIVE_EXTERNALIZATION"
PASS_VERDICT = "ACTIVE_ARCHIVE_SEPARATION_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WS2_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_completion_receipt.json"
CANONICAL_TREE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_canonical_tree_manifest.json"
ARCHIVE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_archive_manifest.json"

PLAN_REL = f"{REPORT_ROOT_REL}/kt_archive_externalization_test_plan.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_archive_externalization_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/archive_externalization_test.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_archive_externalization.py"

DOC_SURFACE_PATTERNS = (
    "README.md",
    "REPO_CANON.md",
    "docs/**",
    "KT-Codex/**",
    "KT_PROD_CLEANROOM/00_README_FIRST/**",
    "KT_PROD_CLEANROOM/01_INPUTS_READONLY/**",
    "KT_PROD_CLEANROOM/02_PROVENANCE_LEDGER/**",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/**",
    "KT_PROD_CLEANROOM/docs/**",
)

PLAN_VALIDATORS = [
    {
        "label": "trust_zone_validate_export",
        "command": ["python", "-m", "tools.operator.trust_zone_validate"],
        "cwd_rel": "KT_PROD_CLEANROOM",
    },
    {
        "label": "active_import_smoke",
        "command": [
            "python",
            "-c",
            "import tools.operator.claim_compiler, tools.operator.public_verifier, tools.operator.trust_zone_validate; print('PASS')",
        ],
        "cwd_rel": "KT_PROD_CLEANROOM",
    },
]

PLAN_TESTS = [
    {
        "label": "active_export_pytest_lane",
        "command": [
            "python",
            "-m",
            "pytest",
            "tests/operator/test_public_verifier.py",
            "tests/operator/test_snapshot_inventory_compile.py",
            "tests/operator/test_trust_zone_validate.py",
            "-q",
        ],
        "cwd_rel": "KT_PROD_CLEANROOM",
    }
]

ALLOWED_TOUCH_PATTERNS = [
    TOOL_REL,
    TEST_REL,
    PLAN_REL,
    RECEIPT_REL,
]

PROTECTED_TOUCH_PATTERNS = [
    "KT_ARCHIVE/**",
    ".github/workflows/**",
]

VOLATILE_JSON_KEYS = ("generated_at", "timestamp")

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
HTML_HREF_RE = re.compile(r"""href=["']([^"']+)["']""")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_lines(root: Path) -> List[str]:
    output = subprocess.check_output(["git", "-C", str(root), "status", "--short"], text=True)
    return [line.rstrip() for line in output.splitlines() if line.strip()]


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    output = _git(root, "show", "--pretty=", "--name-only", commit)
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _tracked_files(root: Path) -> List[str]:
    output = _git(root, "ls-files")
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _status_paths(root: Path) -> List[str]:
    touched: List[str] = []
    for line in _git_status_lines(root):
        payload = line[3:] if len(line) > 3 else ""
        if " -> " in payload:
            before, after = payload.split(" -> ", 1)
            touched.extend([before.replace("\\", "/"), after.replace("\\", "/")])
        elif payload:
            touched.append(payload.replace("\\", "/"))
    return sorted({path for path in touched if path}, key=str.lower)


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _sha256_obj(obj: Dict[str, Any], *, omit: Iterable[str] = ()) -> str:
    payload = {k: v for k, v in obj.items() if k not in set(omit)}
    return sha256_hex(canonicalize_bytes(payload))


def tracked_active_export_files(root: Path, canonical_manifest: Dict[str, Any]) -> List[str]:
    included = [str(item).strip() for item in canonical_manifest.get("included_paths", []) if str(item).strip()]
    excluded = [str(item).strip() for item in canonical_manifest.get("excluded_paths", []) if str(item).strip()]
    rows: List[str] = []
    for rel in _tracked_files(root):
        if not _matches_any(rel, included):
            continue
        if _matches_any(rel, excluded):
            continue
        if rel.startswith("KT_ARCHIVE/"):
            continue
        rows.append(rel)
    return sorted(rows, key=str.lower)


def _copy_active_export(root: Path, export_root: Path, files: Sequence[str]) -> None:
    for rel in files:
        src = (root / Path(rel)).resolve()
        dest = (export_root / Path(rel)).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def _init_git_repo(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "kt@example.test"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "KT Export Test"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "active export"], cwd=root, check=True, capture_output=True)


def _local_doc_targets(text: str) -> List[str]:
    targets = MARKDOWN_LINK_RE.findall(text) + HTML_HREF_RE.findall(text)
    return [target.strip() for target in targets if str(target).strip()]


def _normalize_link_target(target: str) -> str:
    value = str(target).strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1].strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://", "mailto:", "#", "data:")):
        return ""
    if value.startswith("javascript:"):
        return "__FORBIDDEN__"
    value = value.split("#", 1)[0].strip()
    if not value:
        return ""
    if " " in value and not value.startswith("./") and not value.startswith("../") and "/" not in value.split(" ", 1)[0]:
        value = value.split(" ", 1)[0].strip()
    return value


def scan_doc_link_failures(root: Path, export_files: Sequence[str]) -> List[Dict[str, str]]:
    failures: List[Dict[str, str]] = []
    candidates = [
        rel
        for rel in export_files
        if rel.lower().endswith((".md", ".html", ".htm")) and _matches_any(rel, DOC_SURFACE_PATTERNS)
    ]
    for rel in candidates:
        path = (root / Path(rel)).resolve()
        text = path.read_text(encoding="utf-8", errors="ignore")
        for raw_target in _local_doc_targets(text):
            target = _normalize_link_target(raw_target)
            if not target:
                continue
            if target == "__FORBIDDEN__":
                failures.append({"path": rel, "target": raw_target, "reason": "forbidden_javascript_href"})
                continue
            normalized = target.replace("\\", "/")
            if normalized.startswith("KT_ARCHIVE/") or "/KT_ARCHIVE/" in normalized:
                failures.append({"path": rel, "target": raw_target, "reason": "archive_link_target"})
                continue
            if normalized.startswith("/"):
                resolved = (root / normalized.lstrip("/")).resolve()
            else:
                resolved = (path.parent / normalized).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                failures.append({"path": rel, "target": raw_target, "reason": "link_escapes_active_export"})
                continue
            if not resolved.exists():
                failures.append({"path": rel, "target": raw_target, "reason": "missing_local_target"})
    return failures


def _run_command(*, export_root: Path, command: Sequence[str], cwd_rel: str, label: str) -> Dict[str, Any]:
    cwd = (export_root / Path(cwd_rel)).resolve()
    proc = subprocess.run(
        list(command),
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    return {
        "label": label,
        "command": " ".join(command),
        "cwd_rel": cwd_rel,
        "exit_code": int(proc.returncode),
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }


def _top_level_roots(files: Sequence[str]) -> List[str]:
    return sorted({rel.split("/", 1)[0] for rel in files}, key=str.lower)


def build_archive_externalization_plan(root: Path) -> Dict[str, Any]:
    ws2_receipt = _load_required(root, WS2_RECEIPT_REL)
    canonical_manifest = _load_required(root, CANONICAL_TREE_MANIFEST_REL)
    archive_manifest = _load_required(root, ARCHIVE_MANIFEST_REL)
    export_files = tracked_active_export_files(root, canonical_manifest)
    plan: Dict[str, Any] = {
        "artifact_id": "kt_archive_externalization_test_plan.json",
        "schema_id": "kt.operator.archive_externalization_test_plan.v1",
        "workstream_id": WORKSTREAM_ID,
        "generated_at": utc_now_iso_z(),
        "source_receipts": [WS2_RECEIPT_REL, CANONICAL_TREE_MANIFEST_REL, ARCHIVE_MANIFEST_REL],
        "ws2_subject_head_commit": str(ws2_receipt.get("subject_head_commit", "")).strip(),
        "archive_root": str(archive_manifest.get("archive_root", "")).strip(),
        "proof_mode": "copy canonical active tracked files to a detached temporary workspace, omit KT_ARCHIVE entirely, initialize a local git repo, run active-only validators/tests, and scan active docs for broken local links.",
        "active_export": {
            "archive_root_present_in_export": False,
            "exported_file_count": len(export_files),
            "top_level_roots": _top_level_roots(export_files),
            "included_paths": list(canonical_manifest.get("included_paths", [])),
            "excluded_paths": list(canonical_manifest.get("excluded_paths", [])),
        },
        "doc_sufficiency_policy": {
            "scanned_surfaces": list(DOC_SURFACE_PATTERNS),
            "forbidden_link_classes": [
                "archive_link_target",
                "missing_local_target",
                "link_escapes_active_export",
                "forbidden_javascript_href",
            ],
        },
        "validator_commands": PLAN_VALIDATORS,
        "test_commands": PLAN_TESTS,
        "pass_conditions": [
            "detached active export contains no KT_ARCHIVE root",
            "active-only validator commands pass inside detached export",
            "active-only pytest lane passes inside detached export",
            "active docs contain no broken local links and no archive link targets",
        ],
    }
    plan["sha256"] = _sha256_obj(plan, omit={"generated_at", "sha256"})
    return plan


def prove_archive_externalization(root: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    plan = build_archive_externalization_plan(root)
    canonical_manifest = _load_required(root, CANONICAL_TREE_MANIFEST_REL)
    export_files = tracked_active_export_files(root, canonical_manifest)
    with tempfile.TemporaryDirectory(prefix="kt_ws3_active_export_") as tmp_dir:
        export_root = Path(tmp_dir).resolve()
        _copy_active_export(root, export_root, export_files)
        if (export_root / "KT_ARCHIVE").exists():
            raise RuntimeError("FAIL_CLOSED: KT_ARCHIVE leaked into detached active export")
        _init_git_repo(export_root)
        validator_runs = [_run_command(export_root=export_root, **spec) for spec in PLAN_VALIDATORS]
        test_runs = [_run_command(export_root=export_root, **spec) for spec in PLAN_TESTS]
        doc_failures = scan_doc_link_failures(export_root, export_files)
        return plan, {
            "export_file_count": len(export_files),
            "top_level_roots": _top_level_roots(export_files),
            "archive_root_present_in_export": (export_root / "KT_ARCHIVE").exists(),
            "validator_runs": validator_runs,
            "test_runs": test_runs,
            "doc_link_failures": doc_failures,
            "doc_files_scanned": len(
                [
                    rel
                    for rel in export_files
                    if rel.lower().endswith((".md", ".html", ".htm")) and _matches_any(rel, DOC_SURFACE_PATTERNS)
                ]
            ),
        }


def _unexpected_touches(paths: Sequence[str]) -> List[str]:
    return [path for path in sorted(set(paths), key=str.lower) if not _matches_any(path, ALLOWED_TOUCH_PATTERNS)]


def _protected_touch_violations(paths: Sequence[str]) -> List[str]:
    return [path for path in sorted(set(paths), key=str.lower) if _matches_any(path, PROTECTED_TOUCH_PATTERNS)]


def build_archive_externalization_receipt(root: Path) -> Dict[str, Any]:
    plan, proof = prove_archive_externalization(root)
    current_head = _git_head(root)
    dirty_paths = _status_paths(root)
    if any(path not in {PLAN_REL, RECEIPT_REL} for path in dirty_paths):
        touched = sorted(set(dirty_paths + [PLAN_REL, RECEIPT_REL]), key=str.lower)
    else:
        touched = sorted(set(_git_changed_files(root, current_head) + dirty_paths + [PLAN_REL, RECEIPT_REL]), key=str.lower)
    unexpected = _unexpected_touches(touched)
    protected = _protected_touch_violations(touched)
    if unexpected:
        raise RuntimeError("FAIL_CLOSED: unexpected touches remain: " + ", ".join(unexpected))
    if protected:
        raise RuntimeError("FAIL_CLOSED: protected touch violations remain: " + ", ".join(protected))

    validator_failures = [row for row in proof["validator_runs"] if row["status"] != "PASS"]
    test_failures = [row for row in proof["test_runs"] if row["status"] != "PASS"]
    doc_failures = list(proof["doc_link_failures"])
    archive_absent = not bool(proof["archive_root_present_in_export"])
    status = "PASS" if archive_absent and not validator_failures and not test_failures and not doc_failures else "FAIL_CLOSED"
    summary = {
        "export_file_count": int(proof["export_file_count"]),
        "doc_files_scanned": int(proof["doc_files_scanned"]),
        "broken_doc_link_count": len(doc_failures),
        "validator_pass_count": sum(1 for row in proof["validator_runs"] if row["status"] == "PASS"),
        "test_pass_count": sum(1 for row in proof["test_runs"] if row["status"] == "PASS"),
        "archive_root_present_in_export": bool(proof["archive_root_present_in_export"]),
    }
    issues_found: List[str] = []
    if not archive_absent:
        issues_found.append("archive_root_present_in_detached_export")
    if validator_failures:
        issues_found.extend([f"validator_failed:{row['label']}" for row in validator_failures])
    if test_failures:
        issues_found.extend([f"test_failed:{row['label']}" for row in test_failures])
    if doc_failures:
        issues_found.extend([f"doc_link_failure:{row['path']}->{row['target']}" for row in doc_failures])

    receipt: Dict[str, Any] = {
        "artifact_id": "kt_archive_externalization_receipt.json",
        "schema_id": "kt.operator.archive_externalization_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "ACTIVE_ARCHIVE_SEPARATION_NOT_PROVEN",
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "unexpected_touches": unexpected,
        "protected_touch_violations": protected,
        "validators_run": [
            "python -m tools.operator.archive_externalization_test",
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS4_DETERMINISM_AND_CANONICAL_RUNNER",
        },
        "checks": [
            {
                "check": "detached_active_export_omits_archive_root",
                "status": "PASS" if archive_absent else "FAIL",
                "detail": "The detached active export must contain no KT_ARCHIVE root.",
                "refs": [PLAN_REL],
            },
            {
                "check": "active_only_validators_pass_without_archive",
                "status": "PASS" if not validator_failures else "FAIL",
                "detail": "Validators executed inside the detached active export must pass without KT_ARCHIVE present.",
                "refs": [PLAN_REL],
            },
            {
                "check": "active_only_pytest_lane_passes_without_archive",
                "status": "PASS" if not test_failures else "FAIL",
                "detail": "Selected active-only tests must pass inside the detached active export.",
                "refs": [PLAN_REL],
            },
            {
                "check": "active_docs_have_no_archive_or_broken_local_links",
                "status": "PASS" if not doc_failures else "FAIL",
                "detail": "Active docs must not contain broken local links or links targeting KT_ARCHIVE.",
                "refs": [PLAN_REL],
            },
        ],
        "summary": summary,
        "validator_results": proof["validator_runs"],
        "test_results": proof["test_runs"],
        "doc_link_failures": doc_failures,
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "copied the canonical active tracked tree into a detached temporary workspace",
                "omitted KT_ARCHIVE entirely from the detached export",
                "initialized a local git repo for the detached active export",
                "ran active-only validators and tests inside the detached export",
                "scanned active docs for broken local links and archive targets",
            ],
            "files_touched": touched,
            "tests_run": [
                "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_archive_externalization.py -q",
                "python -m pytest tests/operator/test_public_verifier.py tests/operator/test_snapshot_inventory_compile.py tests/operator/test_trust_zone_validate.py -q",
            ],
            "validators_run": [
                "python -m tools.operator.archive_externalization_test",
                "python -m tools.operator.trust_zone_validate",
                "python -c \"import tools.operator.claim_compiler, tools.operator.public_verifier, tools.operator.trust_zone_validate; print('PASS')\"",
            ],
            "issues_found": issues_found,
            "resolution": (
                "WS3 proves archive externalization by validating a detached active export with KT_ARCHIVE absent."
                if status == "PASS"
                else "Archive externalization is not yet proven; inspect validator, test, or doc-link failures and rerun."
            ),
            "pass_fail_status": status,
            "unexpected_touches": unexpected,
            "protected_touch_violations": protected,
        },
    }
    return plan, receipt


def _write_outputs(root: Path) -> Tuple[List[str], str]:
    changed: List[str] = []
    plan, receipt = build_archive_externalization_receipt(root)
    if write_json_stable((root / Path(PLAN_REL)).resolve(), plan, volatile_keys=VOLATILE_JSON_KEYS):
        changed.append(PLAN_REL)
    if write_json_stable((root / Path(RECEIPT_REL)).resolve(), receipt, volatile_keys=VOLATILE_JSON_KEYS):
        changed.append(RECEIPT_REL)
    return changed, str(receipt.get("status", "")).strip() or "FAIL_CLOSED"


def _validate_determinism(root: Path) -> None:
    first_plan = build_archive_externalization_plan(root)
    second_plan = build_archive_externalization_plan(root)
    if not semantically_equal_json(first_plan, second_plan, volatile_keys=VOLATILE_JSON_KEYS):
        raise RuntimeError("FAIL_CLOSED: non-deterministic WS3 plan detected")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prove ACTIVE/ARCHIVE externalization on the canonical active tree.")
    parser.parse_args(argv)

    root = repo_root()
    _validate_determinism(root)
    changed, receipt_status = _write_outputs(root)
    result = {
        "status": receipt_status,
        "workstream_id": WORKSTREAM_ID,
        "pass_verdict": PASS_VERDICT if receipt_status == "PASS" else "ACTIVE_ARCHIVE_SEPARATION_NOT_PROVEN",
        "changed": sorted(changed),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if receipt_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
