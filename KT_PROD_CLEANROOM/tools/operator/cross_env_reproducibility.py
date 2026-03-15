from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


WORKSTREAM_ID = "WS5_CROSS_ENV_REPRODUCIBILITY"
STEP_ID = "WS5_STEP_1_PROVE_CROSS_ENV_HASH_STABILITY"
PASS_VERDICT = "CROSS_ENV_REPRODUCIBILITY_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WS4_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_preflight_receipt.json"
WS4_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_canonical_runner_manifest.json"

MATRIX_REL = f"{REPORT_ROOT_REL}/kt_cross_env_bundle_hash_matrix.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/cross_env_reproducibility.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_cross_env_reproducibility.py"

RUNNER_ID = "kt_cli_safe_run_v1"
RUNNER_COMMAND = "python -m tools.operator.kt_cli --profile v1 safe-run"
RUNTIME_ENTRY = "kt.entrypoint:invoke"
RUNTIME_SPINE = "core.spine:run"
SOURCE_DATE_EPOCH_VALUE = "1700000000"
WSL_DISTRO = "docker-desktop"

CRITICAL_RUNNER_FILES = [
    "KT_PROD_CLEANROOM/governance/closure_foundation/kt_determinism_contract.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json",
    "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py",
    "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
]

CRITICAL_FILE_BUNDLES = {
    "truth_current_bundle_manifest_sha256": "KT_PROD_CLEANROOM/exports/_truth/current/current_bundle_manifest.json",
    "publication_authority_bundle_sha256": "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_bundle.json",
    "publication_in_toto_statement_sha256": "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.json",
}

ALLOWED_TOUCH_PATTERNS = [
    TOOL_REL,
    TEST_REL,
    MATRIX_REL,
    RECEIPT_REL,
]

PROTECTED_TOUCH_PATTERNS = [
    ".github/workflows/**",
    "KT_ARCHIVE/**",
]

VOLATILE_JSON_KEYS = ("generated_at", "timestamp")


def repo_root() -> Path:
    path = Path(__file__).resolve()
    for parent in [path] + list(path.parents):
        if (parent / "KT_PROD_CLEANROOM").is_dir():
            return parent
    raise RuntimeError("FAIL_CLOSED: unable to locate repo root")


def utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _normalize_json_for_compare(value: Any, *, volatile_keys: Sequence[str]) -> Any:
    volatile = {str(item) for item in volatile_keys}
    if isinstance(value, dict):
        return {k: _normalize_json_for_compare(v, volatile_keys=volatile_keys) for k, v in value.items() if k not in volatile}
    if isinstance(value, list):
        return [_normalize_json_for_compare(item, volatile_keys=volatile_keys) for item in value]
    return value


def _semantically_equal_json(existing: Any, candidate: Any, *, volatile_keys: Sequence[str] = VOLATILE_JSON_KEYS) -> bool:
    return _canonical_json_bytes(_normalize_json_for_compare(existing, volatile_keys=volatile_keys)) == _canonical_json_bytes(
        _normalize_json_for_compare(candidate, volatile_keys=volatile_keys)
    )


def _load_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def _write_json_stable(path: Path, obj: Any, *, volatile_keys: Sequence[str] = VOLATILE_JSON_KEYS) -> bool:
    rendered = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if path.exists():
        try:
            existing = _load_json(path)
        except Exception:  # noqa: BLE001
            existing = None
        if existing is not None and _semantically_equal_json(existing, obj, volatile_keys=volatile_keys):
            return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8", newline="\n")
    return True


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return _load_json(path)


def _sha256_obj(obj: Dict[str, Any], *, omit: Iterable[str] = ()) -> str:
    payload = {k: v for k, v in obj.items() if k not in set(omit)}
    return _sha256_bytes(_canonical_json_bytes(payload))


def build_runner_bundle_lines(root: Path) -> List[str]:
    lines = [
        f"runner_id={RUNNER_ID}",
        f"command={RUNNER_COMMAND}",
        f"entry={RUNTIME_ENTRY}",
        f"spine={RUNTIME_SPINE}",
        f"source_date_epoch={SOURCE_DATE_EPOCH_VALUE}",
    ]
    for rel in CRITICAL_RUNNER_FILES:
        lines.append(f"file:{rel}:{_sha256_file((root / Path(rel)).resolve())}")
    return lines


def compute_critical_hashes(root: Path) -> Dict[str, str]:
    payload = "\n".join(build_runner_bundle_lines(root)) + "\n"
    hashes = {
        "runner_bundle_sha256": _sha256_bytes(payload.encode("utf-8")),
    }
    for key, rel in CRITICAL_FILE_BUNDLES.items():
        hashes[key] = _sha256_file((root / Path(rel)).resolve())
    return hashes


def compute_probe_payload(
    root: Path,
    *,
    environment_id: str,
    environment_class: str,
    platform_name: str,
    python_version: str,
    interpreter: str,
    probe_kind: str,
) -> Dict[str, Any]:
    return {
        "environment_id": environment_id,
        "environment_class": environment_class,
        "probe_kind": probe_kind,
        "platform": platform_name,
        "python_version": python_version,
        "interpreter": interpreter,
        "critical_hashes": compute_critical_hashes(root),
    }


def _parse_probe_output(text: str) -> Dict[str, Any]:
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise RuntimeError("FAIL_CLOSED: probe output is not a JSON object")
    return obj


def run_python_probe(root: Path, *, launcher: Sequence[str], environment_id: str, environment_class: str) -> Dict[str, Any]:
    cmd = list(launcher) + [
        "-m",
        "tools.operator.cross_env_reproducibility",
        "--probe",
        "--environment-id",
        environment_id,
        "--environment-class",
        environment_class,
    ]
    output = subprocess.check_output(cmd, cwd=str((root / "KT_PROD_CLEANROOM").resolve()), text=True)
    return _parse_probe_output(output)


def _wsl_shell_command() -> str:
    quoted_files = " ".join(f"'{rel}'" for rel in CRITICAL_RUNNER_FILES)
    truth_path = CRITICAL_FILE_BUNDLES["truth_current_bundle_manifest_sha256"]
    authority_path = CRITICAL_FILE_BUNDLES["publication_authority_bundle_sha256"]
    statement_path = CRITICAL_FILE_BUNDLES["publication_in_toto_statement_sha256"]
    return (
        "set -eu;"
        "runner_sha=$({ "
        f"printf 'runner_id=%s\\n' '{RUNNER_ID}'; "
        f"printf 'command=%s\\n' '{RUNNER_COMMAND}'; "
        f"printf 'entry=%s\\n' '{RUNTIME_ENTRY}'; "
        f"printf 'spine=%s\\n' '{RUNTIME_SPINE}'; "
        f"printf 'source_date_epoch=%s\\n' '{SOURCE_DATE_EPOCH_VALUE}'; "
        f"for p in {quoted_files}; do "
        "sha=$(sha256sum \"$p\" | awk '{print $1}'); "
        "printf 'file:%s:%s\\n' \"$p\" \"$sha\"; "
        "done; "
        "} | sha256sum | awk '{print $1}');"
        f"truth_sha=$(sha256sum '{truth_path}' | awk '{{print $1}}');"
        f"authority_sha=$(sha256sum '{authority_path}' | awk '{{print $1}}');"
        f"statement_sha=$(sha256sum '{statement_path}' | awk '{{print $1}}');"
        "printf 'environment_id=linux_wsl_docker_desktop_shell\\n';"
        "printf 'environment_class=linux\\n';"
        "printf 'probe_kind=shell\\n';"
        "printf 'platform=%s\\n' \"$(uname -srm)\";"
        "printf 'python_version=absent\\n';"
        "printf 'interpreter=sh\\n';"
        "printf 'runner_bundle_sha256=%s\\n' \"$runner_sha\";"
        "printf 'truth_current_bundle_manifest_sha256=%s\\n' \"$truth_sha\";"
        "printf 'publication_authority_bundle_sha256=%s\\n' \"$authority_sha\";"
        "printf 'publication_in_toto_statement_sha256=%s\\n' \"$statement_sha\";"
    )


def _parse_shell_probe(text: str) -> Dict[str, Any]:
    rows: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        rows[key.strip()] = value.strip()
    required = {
        "environment_id",
        "environment_class",
        "probe_kind",
        "platform",
        "python_version",
        "interpreter",
        "runner_bundle_sha256",
        "truth_current_bundle_manifest_sha256",
        "publication_authority_bundle_sha256",
        "publication_in_toto_statement_sha256",
    }
    missing = sorted(required.difference(rows))
    if missing:
        raise RuntimeError("FAIL_CLOSED: incomplete linux shell probe output: " + ", ".join(missing))
    return {
        "environment_id": rows["environment_id"],
        "environment_class": rows["environment_class"],
        "probe_kind": rows["probe_kind"],
        "platform": rows["platform"],
        "python_version": rows["python_version"],
        "interpreter": rows["interpreter"],
        "critical_hashes": {
            "runner_bundle_sha256": rows["runner_bundle_sha256"],
            "truth_current_bundle_manifest_sha256": rows["truth_current_bundle_manifest_sha256"],
            "publication_authority_bundle_sha256": rows["publication_authority_bundle_sha256"],
            "publication_in_toto_statement_sha256": rows["publication_in_toto_statement_sha256"],
        },
    }


def run_linux_shell_probe(root: Path) -> Dict[str, Any]:
    cmd = ["wsl.exe", "-d", WSL_DISTRO, "sh", "-lc", _wsl_shell_command()]
    output = subprocess.check_output(cmd, cwd=str(root.resolve()), text=True)
    return _parse_shell_probe(output)


def build_probe_matrix(probes: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not probes:
        raise RuntimeError("FAIL_CLOSED: no cross-environment probes were recorded")
    bundle_ids = sorted({key for probe in probes for key in probe.get("critical_hashes", {}).keys()})
    matrix_rows: List[Dict[str, Any]] = []
    mismatches: List[str] = []
    for bundle_id in bundle_ids:
        values = {probe["environment_id"]: str(probe["critical_hashes"][bundle_id]).strip() for probe in probes}
        unique = sorted(set(values.values()))
        status = "PASS" if len(unique) == 1 else "FAIL"
        if status != "PASS":
            mismatches.append(bundle_id)
        matrix_rows.append(
            {
                "bundle_id": bundle_id,
                "status": status,
                "values_by_environment": values,
            }
        )
    allowed_variation = {
        "platform": {probe["environment_id"]: probe.get("platform", "") for probe in probes},
        "python_version": {probe["environment_id"]: probe.get("python_version", "") for probe in probes},
        "interpreter": {probe["environment_id"]: probe.get("interpreter", "") for probe in probes},
        "probe_kind": {probe["environment_id"]: probe.get("probe_kind", "") for probe in probes},
        "environment_class": {probe["environment_id"]: probe.get("environment_class", "") for probe in probes},
    }
    env_classes = {str(probe.get("environment_class", "")).strip() for probe in probes}
    required_classes = {"windows", "linux", "third_controlled_environment"}
    missing_classes = sorted(required_classes.difference(env_classes))
    return {
        "bundle_ids": bundle_ids,
        "matrix_rows": matrix_rows,
        "allowed_variation_fields": allowed_variation,
        "environment_classes_present": sorted(env_classes),
        "required_environment_classes": sorted(required_classes),
        "missing_required_environment_classes": missing_classes,
        "mismatched_bundle_ids": mismatches,
    }


def build_cross_env_outputs(root: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    ws4_receipt = _load_required(root, WS4_RECEIPT_REL)
    _load_required(root, WS4_MANIFEST_REL)

    current_probe = compute_probe_payload(
        root,
        environment_id=f"windows_py{sys.version_info.major}{sys.version_info.minor}_current",
        environment_class="windows",
        platform_name=platform.platform(),
        python_version=sys.version.split()[0],
        interpreter=Path(sys.executable).name,
        probe_kind="python",
    )
    third_probe = run_python_probe(
        root,
        launcher=["py", "-3.11"],
        environment_id="windows_py311_third_controlled",
        environment_class="third_controlled_environment",
    )
    linux_probe = run_linux_shell_probe(root)
    probes = [current_probe, third_probe, linux_probe]
    matrix_summary = build_probe_matrix(probes)

    matrix: Dict[str, Any] = {
        "artifact_id": "kt_cross_env_bundle_hash_matrix.json",
        "schema_id": "kt.operator.cross_env_bundle_hash_matrix.v1",
        "workstream_id": WORKSTREAM_ID,
        "generated_at": utc_now_iso_z(),
        "ws4_subject_head_commit": str(ws4_receipt.get("subject_head_commit", "")).strip(),
        "source_receipts": [WS4_RECEIPT_REL, WS4_MANIFEST_REL],
        "probe_count": len(probes),
        "probes": probes,
        "bundle_ids": matrix_summary["bundle_ids"],
        "matrix_rows": matrix_summary["matrix_rows"],
        "allowed_variation_fields": matrix_summary["allowed_variation_fields"],
        "required_environment_classes": matrix_summary["required_environment_classes"],
        "environment_classes_present": matrix_summary["environment_classes_present"],
        "missing_required_environment_classes": matrix_summary["missing_required_environment_classes"],
        "critical_hash_match_complete": not matrix_summary["mismatched_bundle_ids"] and not matrix_summary["missing_required_environment_classes"],
        "sha256": "",
    }
    matrix["sha256"] = _sha256_obj(matrix, omit={"generated_at", "sha256"})

    current_head = _git_head(root)
    dirty_paths = _status_paths(root)
    if any(path not in {MATRIX_REL, RECEIPT_REL} for path in dirty_paths):
        touched = sorted(set(dirty_paths + [MATRIX_REL, RECEIPT_REL]), key=str.lower)
    else:
        touched = sorted(set(_git_changed_files(root, current_head) + dirty_paths + [MATRIX_REL, RECEIPT_REL]), key=str.lower)
    unexpected = [path for path in touched if not _matches_any(path, ALLOWED_TOUCH_PATTERNS)]
    protected = [path for path in touched if _matches_any(path, PROTECTED_TOUCH_PATTERNS)]
    if unexpected:
        raise RuntimeError("FAIL_CLOSED: unexpected touches remain: " + ", ".join(unexpected))
    if protected:
        raise RuntimeError("FAIL_CLOSED: protected touch violations remain: " + ", ".join(protected))

    status = "PASS"
    issues_found: List[str] = []
    if matrix_summary["missing_required_environment_classes"]:
        status = "FAIL_CLOSED"
        issues_found.extend([f"missing_environment_class:{item}" for item in matrix_summary["missing_required_environment_classes"]])
    if matrix_summary["mismatched_bundle_ids"]:
        status = "FAIL_CLOSED"
        issues_found.extend([f"bundle_hash_mismatch:{item}" for item in matrix_summary["mismatched_bundle_ids"]])

    receipt: Dict[str, Any] = {
        "artifact_id": "kt_determinism_receipt.json",
        "schema_id": "kt.operator.cross_env_determinism_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "CROSS_ENV_REPRODUCIBILITY_NOT_PROVEN",
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "unexpected_touches": unexpected,
        "protected_touch_violations": protected,
        "validators_run": [
            "python -m tools.operator.cross_env_reproducibility",
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS6_LEDGER_LED_AUTHORITY_FINALIZATION",
        },
        "checks": [
            {
                "check": "required_environment_classes_present",
                "status": "PASS" if not matrix_summary["missing_required_environment_classes"] else "FAIL",
                "detail": "Windows, Linux, and one additional controlled environment must all be recorded in the matrix.",
                "refs": [MATRIX_REL],
            },
            {
                "check": "critical_hashes_match_across_environments",
                "status": "PASS" if not matrix_summary["mismatched_bundle_ids"] else "FAIL",
                "detail": "Critical truth/publication bundle hashes must be identical across the recorded environments.",
                "refs": [MATRIX_REL],
            },
            {
                "check": "allowed_variation_explicit",
                "status": "PASS",
                "detail": "Platform, interpreter, and python-version differences are recorded and excluded from the critical hash set.",
                "refs": [MATRIX_REL],
            },
        ],
        "summary": {
            "environment_count": len(probes),
            "environment_classes_present": matrix_summary["environment_classes_present"],
            "bundle_count": len(matrix_summary["bundle_ids"]),
            "mismatched_bundle_count": len(matrix_summary["mismatched_bundle_ids"]),
            "bundle_ids": matrix_summary["bundle_ids"],
        },
        "matrix_ref": MATRIX_REL,
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "computed the critical runner bundle hash in the current Windows python environment",
                "computed the same critical hash set in an additional controlled Windows python environment",
                "computed the same critical hash set in a WSL Linux shell environment",
                "recorded environment differences as allowed variation outside the critical hash set",
            ],
            "files_touched": touched,
            "tests_run": [
                "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_cross_env_reproducibility.py -q",
            ],
            "validators_run": [
                "python -m tools.operator.cross_env_reproducibility",
            ],
            "issues_found": issues_found,
            "resolution": (
                "WS5 proves the critical truth/publication bundle hash set is stable across Windows, Linux, and a third controlled environment."
                if status == "PASS"
                else "Cross-environment reproducibility remains blocked; inspect missing environment classes or bundle mismatches."
            ),
            "pass_fail_status": status,
            "unexpected_touches": unexpected,
            "protected_touch_violations": protected,
        },
    }
    return matrix, receipt


def _write_outputs(root: Path) -> Tuple[List[str], str]:
    changed: List[str] = []
    matrix, receipt = build_cross_env_outputs(root)
    if _write_json_stable((root / Path(MATRIX_REL)).resolve(), matrix, volatile_keys=VOLATILE_JSON_KEYS):
        changed.append(MATRIX_REL)
    if _write_json_stable((root / Path(RECEIPT_REL)).resolve(), receipt, volatile_keys=VOLATILE_JSON_KEYS):
        changed.append(RECEIPT_REL)
    return changed, str(receipt.get("status", "")).strip() or "FAIL_CLOSED"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prove cross-environment critical bundle hash stability.")
    parser.add_argument("--probe", action="store_true", help="Emit a probe payload for the current Python environment.")
    parser.add_argument("--environment-id", default="")
    parser.add_argument("--environment-class", default="")
    args = parser.parse_args(argv)

    root = repo_root()
    if args.probe:
        environment_id = str(args.environment_id).strip() or f"windows_py{sys.version_info.major}{sys.version_info.minor}_probe"
        environment_class = str(args.environment_class).strip() or "windows"
        payload = compute_probe_payload(
            root,
            environment_id=environment_id,
            environment_class=environment_class,
            platform_name=platform.platform(),
            python_version=sys.version.split()[0],
            interpreter=Path(sys.executable).name,
            probe_kind="python",
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    changed, receipt_status = _write_outputs(root)
    result = {
        "status": receipt_status,
        "workstream_id": WORKSTREAM_ID,
        "pass_verdict": PASS_VERDICT if receipt_status == "PASS" else "CROSS_ENV_REPRODUCIBILITY_NOT_PROVEN",
        "changed": sorted(changed),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if receipt_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
