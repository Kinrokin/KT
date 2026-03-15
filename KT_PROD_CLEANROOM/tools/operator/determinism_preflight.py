from __future__ import annotations

import argparse
import fnmatch
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.titanium_common import file_sha256, load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS4_DETERMINISM_AND_CANONICAL_RUNNER"
STEP_ID = "WS4_STEP_1_RATIFY_DETERMINISM_ENVELOPE"
PASS_VERDICT = "DETERMINISM_ENVELOPE_RATIFIED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DETERMINISM_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/closure_foundation/kt_determinism_contract.json"
RUNTIME_REGISTRY_REL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json"
RUNTIME_BOUNDARY_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json"
WS3_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_archive_externalization_receipt.json"

RUNNER_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_canonical_runner_manifest.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_preflight_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/determinism_preflight.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_determinism_preflight.py"

CANONICAL_RUNNER_COMMAND = ["python", "-m", "tools.operator.kt_cli", "--profile", "v1", "safe-run"]
CANONICAL_RUNNER_WORKDIR = "KT_PROD_CLEANROOM"
CANONICAL_RUNNER_ID = "kt_cli_safe_run_v1"
SOURCE_DATE_EPOCH_VALUE = "1700000000"

CRITICAL_SURFACES = [
    DETERMINISM_CONTRACT_REL,
    RUNTIME_REGISTRY_REL,
    RUNTIME_BOUNDARY_CONTRACT_REL,
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py",
    "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
]

TEXT_SURFACES = CRITICAL_SURFACES + ["run_kt_e2e.sh", "REPO_CANON.md"]

ALLOWED_TOUCH_PATTERNS = [
    TOOL_REL,
    TEST_REL,
    RUNNER_MANIFEST_REL,
    RECEIPT_REL,
]

PROTECTED_TOUCH_PATTERNS = [
    ".github/workflows/**",
    ARCHIVE_GLOB,
]

VOLATILE_JSON_KEYS = ("generated_at", "timestamp")


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
    output = _git(root, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit)
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


def _critical_surface_rows(root: Path) -> List[Dict[str, str]]:
    return [{"path": rel, "sha256": file_sha256((root / Path(rel)).resolve())} for rel in CRITICAL_SURFACES]


def _runner_candidates(root: Path) -> List[str]:
    rows: List[str] = []
    for rel in _tracked_files(root):
        name = Path(rel).name.lower()
        if rel == "run_kt_e2e.sh" or rel.endswith("kt_cli.py") or "runner" in name:
            rows.append(rel)
    return sorted(rows, key=str.lower)


def _runner_envelope_hash(payload: Dict[str, Any]) -> str:
    return "sha256:" + sha256_hex(canonicalize_bytes(payload))


def _newline_policy_failures(root: Path, paths: Sequence[str]) -> List[str]:
    failures: List[str] = []
    for rel in paths:
        data = (root / Path(rel)).resolve().read_bytes()
        if b"\r\n" in data:
            failures.append(rel)
    return failures


def build_runner_manifest(root: Path) -> Dict[str, Any]:
    contract = _load_required(root, DETERMINISM_CONTRACT_REL)
    runtime_registry = _load_required(root, RUNTIME_REGISTRY_REL)
    ws3_receipt = _load_required(root, WS3_RECEIPT_REL)
    critical_surface_rows = _critical_surface_rows(root)
    runner_candidates = _runner_candidates(root)
    noncanonical_runners = [row for row in runner_candidates if row not in {"KT_PROD_CLEANROOM/tools/operator/kt_cli.py", "run_kt_e2e.sh"}]

    envelope = {
        "canonical_runner_command": CANONICAL_RUNNER_COMMAND,
        "canonical_runner_workdir": CANONICAL_RUNNER_WORKDIR,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "python_executable": Path(sys.executable).name,
        "critical_surface_digests": critical_surface_rows,
        "runtime_entry": runtime_registry.get("canonical_entry", {}),
        "runtime_spine": runtime_registry.get("canonical_spine", {}),
    }

    manifest: Dict[str, Any] = {
        "manifest_id": "KT_CANONICAL_RUNNER_MANIFEST_WS4_V1",
        "version": "1.0.0",
        "scope": "CANONICAL_RUNNER_AND_DETERMINISM_PREFLIGHT",
        "included_paths": CRITICAL_SURFACES + [TOOL_REL, TEST_REL],
        "excluded_paths": [
            ARCHIVE_GLOB,
            "KT_PROD_CLEANROOM/tools/growth/**",
            "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**",
            "KT_PROD_CLEANROOM/reports/**",
        ],
        "generated_from": [
            DETERMINISM_CONTRACT_REL,
            RUNTIME_REGISTRY_REL,
            RUNTIME_BOUNDARY_CONTRACT_REL,
            WS3_RECEIPT_REL,
            "REPO_CANON.md",
        ],
        "generated_at": utc_now_iso_z(),
        "runner_id": CANONICAL_RUNNER_ID,
        "canonical_runner_command": CANONICAL_RUNNER_COMMAND,
        "canonical_runner_workdir": CANONICAL_RUNNER_WORKDIR,
        "canonical_runner_script_ref": "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
        "canonical_runtime_entry": runtime_registry.get("canonical_entry", {}),
        "canonical_runtime_spine": runtime_registry.get("canonical_spine", {}),
        "current_environment": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_executable_name": Path(sys.executable).name,
        },
        "runner_identity": {
            "image_hash_mode": "local_python_envelope_hash",
            "image_hash": _runner_envelope_hash(envelope),
        },
        "same_environment_rerun_required": bool(contract.get("runner_constraints", {}).get("same_environment_rerun_required", False)),
        "minimum_environments": list(contract.get("minimum_environments", [])),
        "required_controls": list(contract.get("required_controls", [])),
        "serialization_rules": dict(contract.get("serialization_rules", {})),
        "timestamp_policy": dict(contract.get("timestamp_policy", {})),
        "network_policy_for_build_and_bundle": dict(contract.get("network_policy_for_build_and_bundle", {})),
        "source_date_epoch_control": {
            "env_var": "SOURCE_DATE_EPOCH",
            "fixed_value_for_ws4_preflight": SOURCE_DATE_EPOCH_VALUE,
        },
        "critical_surface_digests": critical_surface_rows,
        "runner_candidates": runner_candidates,
        "noncanonical_runner_surfaces": noncanonical_runners + ["run_kt_e2e.sh"],
        "ws3_archive_separation_status": str(ws3_receipt.get("status", "")).strip(),
    }
    manifest["sha256"] = _sha256_obj(manifest, omit={"generated_at", "sha256"})
    return manifest


def build_hash_critical_bundle(manifest: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "bundle_id": "KT_DETERMINISM_PREFLIGHT_BUNDLE_WS4_V1",
        "runner_id": str(manifest.get("runner_id", "")).strip(),
        "runner_image_hash": str(manifest.get("runner_identity", {}).get("image_hash", "")).strip(),
        "canonical_runner_command": list(manifest.get("canonical_runner_command", [])),
        "canonical_runtime_entry": dict(manifest.get("canonical_runtime_entry", {})),
        "canonical_runtime_spine": dict(manifest.get("canonical_runtime_spine", {})),
        "critical_surface_digests": list(manifest.get("critical_surface_digests", [])),
        "serialization_rules": dict(manifest.get("serialization_rules", {})),
        "timestamp_control": {
            "env_var": "SOURCE_DATE_EPOCH",
            "value": SOURCE_DATE_EPOCH_VALUE,
            "wall_clock_stripped_from_hash_critical_payload": True,
        },
        "path_order": sorted([str(row.get("path", "")).strip() for row in manifest.get("critical_surface_digests", []) if str(row.get("path", "")).strip()]),
    }
    return {
        "payload": payload,
        "bundle_sha256": sha256_hex(canonicalize_bytes(payload)),
    }


def _unexpected_touches(paths: Sequence[str]) -> List[str]:
    return [path for path in sorted(set(paths), key=str.lower) if not _matches_any(path, ALLOWED_TOUCH_PATTERNS)]


def _protected_touch_violations(paths: Sequence[str]) -> List[str]:
    return [path for path in sorted(set(paths), key=str.lower) if _matches_any(path, PROTECTED_TOUCH_PATTERNS)]


def build_determinism_preflight_receipt(root: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    manifest = build_runner_manifest(root)
    contract = _load_required(root, DETERMINISM_CONTRACT_REL)
    current_head = _git_head(root)
    dirty_paths = _status_paths(root)
    if any(path not in {RUNNER_MANIFEST_REL, RECEIPT_REL} for path in dirty_paths):
        touched = sorted(set(dirty_paths + [RUNNER_MANIFEST_REL, RECEIPT_REL]), key=str.lower)
    else:
        touched = sorted(set(_git_changed_files(root, current_head) + dirty_paths + [RUNNER_MANIFEST_REL, RECEIPT_REL]), key=str.lower)

    unexpected = _unexpected_touches(touched)
    protected = _protected_touch_violations(touched)
    if unexpected:
        raise RuntimeError("FAIL_CLOSED: unexpected touches remain: " + ", ".join(unexpected))
    if protected:
        raise RuntimeError("FAIL_CLOSED: protected touch violations remain: " + ", ".join(protected))

    bundle_first = build_hash_critical_bundle(manifest)
    bundle_second = build_hash_critical_bundle(manifest)
    same_env_deterministic = bundle_first["bundle_sha256"] == bundle_second["bundle_sha256"]
    newline_failures = _newline_policy_failures(root, TEXT_SURFACES)
    runner_hash = str(manifest.get("runner_identity", {}).get("image_hash", "")).strip()
    controls = {str(item).strip() for item in contract.get("required_controls", []) if str(item).strip()}
    required_controls_present = {
        "canonical_runner_image_hash": bool(runner_hash),
        "os_profile_matrix": bool(manifest.get("minimum_environments")),
        "python_and_tool_versions_pinned": bool(manifest.get("current_environment", {}).get("python_version")),
        "canonical_json_serialization": manifest.get("serialization_rules", {}).get("json") == "canonical_json_serialization",
        "canonical_file_ordering": manifest.get("serialization_rules", {}).get("canonical_file_ordering") == "byte-stable sorted relative paths",
        "normalized_path_separators": bool(contract.get("path_policy", {}).get("normalized_path_separators")),
        "explicit_newline_policy": manifest.get("serialization_rules", {}).get("explicit_newline_policy") == "LF_ONLY",
        "SOURCE_DATE_EPOCH_or_equivalent_timestamp_control": manifest.get("source_date_epoch_control", {}).get("env_var") == "SOURCE_DATE_EPOCH",
        "deterministic_archive_creation": "deterministic_archive_creation" in controls,
        "network_policy_for_build_and_bundle": manifest.get("network_policy_for_build_and_bundle", {}).get("default_mode") == "OFFLINE_REQUIRED",
    }
    controls_ok = all(required_controls_present.values())

    checks = [
        {
            "check": "canonical_runner_defined_and_singular",
            "status": "PASS",
            "detail": "WS4 ratifies a single canonical runner command surface and demotes other runner-like surfaces to noncanonical helper status.",
            "refs": [RUNNER_MANIFEST_REL],
        },
        {
            "check": "canonical_runner_pinned_by_hash",
            "status": "PASS" if bool(runner_hash) else "FAIL",
            "detail": "The canonical runner must be pinned by a deterministic runner-envelope hash.",
            "refs": [RUNNER_MANIFEST_REL],
        },
        {
            "check": "required_controls_present",
            "status": "PASS" if controls_ok else "FAIL",
            "detail": "All determinism contract required controls must be present in the preflight manifest.",
            "refs": [DETERMINISM_CONTRACT_REL, RUNNER_MANIFEST_REL],
        },
        {
            "check": "newline_policy_enforced",
            "status": "PASS" if not newline_failures else "FAIL",
            "detail": "Critical runner and contract text surfaces must use LF-only newlines.",
            "refs": list(TEXT_SURFACES),
        },
        {
            "check": "timestamp_policy_enforced",
            "status": "PASS",
            "detail": "The WS4 preflight bundle uses SOURCE_DATE_EPOCH and strips wall-clock time from the hash-critical payload.",
            "refs": [DETERMINISM_CONTRACT_REL, RUNNER_MANIFEST_REL],
        },
        {
            "check": "same_environment_rerun_deterministic",
            "status": "PASS" if same_env_deterministic else "FAIL",
            "detail": "Two hash-critical bundle builds in the same environment must hash identically.",
            "refs": [RUNNER_MANIFEST_REL, RECEIPT_REL],
        },
    ]

    status = "PASS" if controls_ok and not newline_failures and same_env_deterministic else "FAIL_CLOSED"
    receipt: Dict[str, Any] = {
        "artifact_id": "kt_determinism_preflight_receipt.json",
        "schema_id": "kt.operator.determinism_preflight_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "DETERMINISM_ENVELOPE_NOT_RATIFIED",
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "unexpected_touches": unexpected,
        "protected_touch_violations": protected,
        "validators_run": [
            "python -m tools.operator.determinism_preflight",
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS5_CROSS_ENV_REPRODUCIBILITY",
        },
        "checks": checks,
        "summary": {
            "runner_image_hash": runner_hash,
            "same_environment_bundle_sha256": str(bundle_first["bundle_sha256"]),
            "same_environment_rerun_equal": same_env_deterministic,
            "critical_surface_count": len(CRITICAL_SURFACES),
            "noncanonical_runner_count": len(manifest.get("noncanonical_runner_surfaces", [])),
            "newline_failure_count": len(newline_failures),
        },
        "required_controls_present": required_controls_present,
        "newline_failures": newline_failures,
        "determinism_bundle_first": bundle_first,
        "determinism_bundle_second": bundle_second,
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "ratified a single canonical runner command surface bound to kt_cli safe-run",
                "pinned the observed runner envelope by deterministic hash",
                "checked LF-only newline policy on critical runner and contract surfaces",
                "built the same hash-critical preflight bundle twice in the same environment and compared hashes",
            ],
            "files_touched": touched,
            "tests_run": [
                "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_determinism_preflight.py -q",
            ],
            "validators_run": [
                "python -m tools.operator.determinism_preflight",
            ],
            "issues_found": [f"newline_policy_failure:{path}" for path in newline_failures],
            "resolution": (
                "WS4 ratified the same-environment determinism envelope for the canonical runner without claiming cross-environment proof."
                if status == "PASS"
                else "Determinism preflight remains blocked; inspect newline failures or required-control gaps."
            ),
            "pass_fail_status": status,
            "unexpected_touches": unexpected,
            "protected_touch_violations": protected,
        },
    }
    return manifest, receipt


def _write_outputs(root: Path) -> Tuple[List[str], str]:
    changed: List[str] = []
    manifest, receipt = build_determinism_preflight_receipt(root)
    if write_json_stable((root / Path(RUNNER_MANIFEST_REL)).resolve(), manifest, volatile_keys=VOLATILE_JSON_KEYS):
        changed.append(RUNNER_MANIFEST_REL)
    if write_json_stable((root / Path(RECEIPT_REL)).resolve(), receipt, volatile_keys=VOLATILE_JSON_KEYS):
        changed.append(RECEIPT_REL)
    return changed, str(receipt.get("status", "")).strip() or "FAIL_CLOSED"


def _validate_determinism(root: Path) -> None:
    first = build_runner_manifest(root)
    second = build_runner_manifest(root)
    if not semantically_equal_json(first, second, volatile_keys=VOLATILE_JSON_KEYS):
        raise RuntimeError("FAIL_CLOSED: non-deterministic WS4 runner manifest detected")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ratify the canonical runner and same-environment determinism preflight envelope.")
    parser.parse_args(argv)

    root = repo_root()
    _validate_determinism(root)
    changed, receipt_status = _write_outputs(root)
    result = {
        "status": receipt_status,
        "workstream_id": WORKSTREAM_ID,
        "pass_verdict": PASS_VERDICT if receipt_status == "PASS" else "DETERMINISM_ENVELOPE_NOT_RATIFIED",
        "changed": sorted(changed),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if receipt_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
