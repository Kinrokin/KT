from __future__ import annotations

import argparse
import fnmatch
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.public_verifier import build_public_verifier_report
from tools.operator.public_verifier_detached_validate import PARITY_FIELDS
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS20_INDEPENDENT_EXTERNAL_REPRODUCTION"
STEP_ID = "WS20_STEP_1_PROVE_TWO_CLEAN_ENVIRONMENT_VERIFICATION"
PASS_VERDICT = "INDEPENDENT_EXTERNAL_REPRODUCTION_MATRIX_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
MATRIX_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_matrix.json"
RECIPE_REL = f"{REPORT_ROOT_REL}/kt_independent_replay_recipe.md"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_receipt.json"

DEFAULT_WS19_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_release_manifest.json"
DEFAULT_WS19_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/external_reproduction_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_external_reproduction_validate.py"

WS20_PROOF_ROOT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS20_external_reproduction_proof"
ENV_A_PACKAGE_REL = f"{WS20_PROOF_ROOT_REL}/env_a/package"
ENV_A_REPORT_REF = f"{WS20_PROOF_ROOT_REL}/reports/env_a_public_verifier_report.json"
ENV_A_RECEIPT_REF = f"{WS20_PROOF_ROOT_REL}/reports/env_a_runtime_receipt.json"
ENV_A_METADATA_REF = f"{WS20_PROOF_ROOT_REL}/reports/env_a_environment_metadata.json"
ENV_B_REPORT_REF = f"{WS20_PROOF_ROOT_REL}/reports/env_b_public_verifier_report.json"
ENV_B_RECEIPT_REF = f"{WS20_PROOF_ROOT_REL}/reports/env_b_runtime_receipt.json"
ENV_B_METADATA_REF = f"{WS20_PROOF_ROOT_REL}/reports/env_b_environment_metadata.json"

STRONGER_CLAIM_NOT_MADE = (
    "WS20 proves only same-host independent clean-environment verification of the sealed detached verifier package. "
    "It does not claim cross-host or third-party reproduction, full artifact reconstruction beyond attested-subject verification, "
    "public horizon opening, or any WS21 public-release claim."
)
VALIDATORS_RUN = ["python -m tools.operator.external_reproduction_validate"]
TESTS_RUN = ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_external_reproduction_validate.py -q"]
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")
CREATED_FILES = [TOOL_REL, TEST_REL, MATRIX_REL, RECIPE_REL, RECEIPT_REL]
WORKSTREAM_FILES_TOUCHED = list(CREATED_FILES)
SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    MATRIX_REL: "generated reproduction matrix",
    RECIPE_REL: "generated replay recipe",
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
        raise RuntimeError(f"FAIL_CLOSED: missing required WS20 input: {rel}")
    return load_json(path)


def _relative_or_absolute(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:  # noqa: BLE001
        return path.resolve().as_posix()


def _parity_map(expected: Dict[str, Any], actual: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        field: {
            "expected": expected.get(field),
            "actual": actual.get(field),
            "match": expected.get(field) == actual.get(field),
        }
        for field in PARITY_FIELDS
    }


def _copy_package(source_package_root: Path, target_package_root: Path) -> None:
    if target_package_root.exists():
        shutil.rmtree(target_package_root)
    target_package_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_package_root, target_package_root)


def _detached_env(package_root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    env["GIT_CEILING_DIRECTORIES"] = str(package_root)
    return env


def _collect_environment_metadata(*, package_root: Path, label: str, output_path: Path) -> Dict[str, Any]:
    cwd = (package_root / "KT_PROD_CLEANROOM").resolve()
    snippet = (
        "import json, platform, sys; "
        "from pathlib import Path; "
        "from tools.operator.titanium_common import operator_fingerprint; "
        "row = operator_fingerprint(); "
        "row.update({"
        "'platform': platform.platform(), "
        "'python_version': platform.python_version(), "
        "'python_executable': sys.executable, "
        "'cwd': str(Path().resolve())"
        "}); "
        "print(json.dumps(row, sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-c", snippet],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_detached_env(package_root),
        check=True,
    )
    metadata = json.loads(result.stdout)
    metadata["environment_id"] = label
    metadata["package_root"] = package_root.resolve().as_posix()
    metadata["inside_repo_root"] = False
    metadata["repo_checkout_present"] = (package_root / ".git").exists()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    return metadata


def _run_external_environment(
    *,
    root: Path,
    environment_id: str,
    source_package_root: Path,
    target_package_root: Path,
    report_output: Path,
    receipt_output: Path,
    metadata_output: Path,
    expected_report: Dict[str, Any],
) -> Dict[str, Any]:
    _copy_package(source_package_root, target_package_root)
    metadata = _collect_environment_metadata(package_root=target_package_root, label=environment_id, output_path=metadata_output)
    metadata["inside_repo_root"] = str(target_package_root.resolve()).startswith(str(root.resolve()))
    cwd = (target_package_root / "KT_PROD_CLEANROOM").resolve()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.public_verifier_detached_runtime",
            "--report-output",
            str(report_output),
            "--receipt-output",
            str(receipt_output),
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_detached_env(target_package_root),
        check=False,
    )
    if result.returncode != 0 or not report_output.exists() or not receipt_output.exists():
        raise RuntimeError(
            "FAIL_CLOSED: external environment detached verifier run failed\n"
            f"environment_id={environment_id}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    report = load_json(report_output)
    receipt = load_json(receipt_output)
    parity = _parity_map(expected_report, report)
    return {
        "environment_id": environment_id,
        "status": "PASS"
        if str(receipt.get("status", "")).strip() == "PASS"
        and receipt.get("detached_environment", {}).get("detached_root_detected") is True
        and receipt.get("detached_environment", {}).get("git_head_available") is False
        and all(row["match"] for row in parity.values())
        else "FAIL",
        "verification_mode": "DETACHED_ATTESTED_SUBJECT_SET_VERIFICATION",
        "package_root": _relative_or_absolute(root, target_package_root),
        "package_root_inside_repo_root": bool(metadata.get("inside_repo_root")),
        "detached_runtime_receipt_ref": _relative_or_absolute(root, receipt_output),
        "detached_public_verifier_report_ref": _relative_or_absolute(root, report_output),
        "environment_metadata_ref": _relative_or_absolute(root, metadata_output),
        "environment_metadata": metadata,
        "detached_runtime_status": str(receipt.get("status", "")).strip(),
        "detached_environment": dict(receipt.get("detached_environment", {})),
        "conclusion_parity": parity,
    }


def _build_recipe(*, source_package_root_ref: str, env_a_root_ref: str, env_b_root_hint: str) -> str:
    lines = [
        "# WS20 Independent Replay Recipe",
        "",
        "Scope: verify the sealed detached verifier package in two clean environments without relying on the original repo checkout.",
        "",
        "Prerequisites",
        "- `KT_HMAC_KEY_SIGNER_A` and `KT_HMAC_KEY_SIGNER_B` must already be set to the WS17/WS19 trust-root values.",
        "- Python must be available on PATH.",
        "",
        "Source package",
        f"- Copy from `{source_package_root_ref}`.",
        "",
        "PowerShell recipe",
        "```powershell",
        f"$envA = Resolve-Path '{env_a_root_ref}'",
        f"$envB = '{env_b_root_hint}'",
        "Remove-Item $envA -Recurse -Force -ErrorAction SilentlyContinue",
        "Remove-Item $envB -Recurse -Force -ErrorAction SilentlyContinue",
        "New-Item -ItemType Directory -Force -Path $envA | Out-Null",
        "New-Item -ItemType Directory -Force -Path $envB | Out-Null",
        f"Copy-Item -Recurse -Force '{source_package_root_ref}\\*' $envA",
        f"Copy-Item -Recurse -Force '{source_package_root_ref}\\*' $envB",
        "Push-Location (Join-Path $envA 'KT_PROD_CLEANROOM')",
        "python -m tools.operator.public_verifier_detached_runtime --report-output reports\\external_env_a_report.json --receipt-output reports\\external_env_a_receipt.json",
        "Pop-Location",
        "Push-Location (Join-Path $envB 'KT_PROD_CLEANROOM')",
        "python -m tools.operator.public_verifier_detached_runtime --report-output reports\\external_env_b_report.json --receipt-output reports\\external_env_b_receipt.json",
        "Pop-Location",
        "```",
        "",
        "Success criteria",
        "- Both detached runtime receipts report `status: PASS`.",
        "- Both detached public verifier reports match the repo-local parity field set from WS19.",
        "- The environments stay detached from any repo checkout.",
        "",
        "Stronger claim not made",
        f"- {STRONGER_CLAIM_NOT_MADE}",
        "",
    ]
    return "\n".join(lines)


def build_external_reproduction_outputs_from_artifacts(
    *,
    current_repo_head: str,
    ws19_receipt: Dict[str, Any],
    matrix: Dict[str, Any],
    recipe_text: str,
    changed_files: Sequence[str],
    prewrite_scope_clean: bool,
) -> Dict[str, Dict[str, Any]]:
    changed = sorted(set(str(path).replace("\\", "/") for path in changed_files))
    unexpected = sorted(path for path in changed if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError("FAIL_CLOSED: unexpected subject touches detected: " + ", ".join(unexpected + protected))

    environments = list(matrix.get("environments", [])) if isinstance(matrix.get("environments"), list) else []
    distinct_roots = {str(row.get("package_root", "")).strip() for row in environments if isinstance(row, dict)}
    successful_envs = [row for row in environments if isinstance(row, dict) and str(row.get("status", "")).strip() == "PASS"]
    metadata_ok = all(
        isinstance(row, dict)
        and isinstance(row.get("environment_metadata"), dict)
        and str(row["environment_metadata"].get("python_executable", "")).strip()
        and str(row["environment_metadata"].get("mve_environment_fingerprint", "")).strip()
        and str(row["environment_metadata"].get("runtime_fingerprint", "")).strip()
        for row in environments
    )
    at_least_one_outside_repo = any(
        isinstance(row, dict) and not bool(row.get("package_root_inside_repo_root"))
        for row in environments
    )
    recipe_explicit = all(
        token in recipe_text
        for token in (
            "KT_HMAC_KEY_SIGNER_A",
            "KT_HMAC_KEY_SIGNER_B",
            "python -m tools.operator.public_verifier_detached_runtime",
            "PowerShell recipe",
            "Success criteria",
        )
    )
    ws19_ok = (
        str(ws19_receipt.get("status", "")).strip() == "PASS"
        and str(ws19_receipt.get("pass_verdict", "")).strip() == "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN"
    )
    stronger_claim_ok = str(matrix.get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE and STRONGER_CLAIM_NOT_MADE in recipe_text
    status = "PASS" if all(
        [
            prewrite_scope_clean,
            ws19_ok,
            len(environments) >= 2,
            len(distinct_roots) >= 2,
            len(successful_envs) >= 2,
            metadata_ok,
            at_least_one_outside_repo,
            recipe_explicit,
            stronger_claim_ok,
        ]
    ) else "BLOCKED"

    receipt = {
        "schema_id": "kt.operator.external_reproduction_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws19_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws19_receipt.get("evidence_head_commit", "")).strip(),
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "INDEPENDENT_EXTERNAL_REPRODUCTION_BLOCKED",
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
            DEFAULT_WS19_MANIFEST_REL,
            DEFAULT_WS19_RECEIPT_REL,
            MATRIX_REL,
            RECIPE_REL,
            TOOL_REL,
            TEST_REL,
        ],
        "checks": [
            {"check": "prewrite_workspace_scope_clean", "status": "PASS" if prewrite_scope_clean else "FAIL", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "workstream_touches_remain_in_scope", "status": "PASS", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "ws19_detached_package_pass", "status": "PASS" if ws19_ok else "FAIL", "refs": [DEFAULT_WS19_RECEIPT_REL]},
            {"check": "two_independent_clean_environments_recorded", "status": "PASS" if len(environments) >= 2 and len(distinct_roots) >= 2 else "FAIL", "refs": [MATRIX_REL]},
            {"check": "one_environment_runs_outside_repo_root", "status": "PASS" if at_least_one_outside_repo else "FAIL", "refs": [MATRIX_REL]},
            {"check": "both_environments_verify_attested_subjects", "status": "PASS" if len(successful_envs) >= 2 else "FAIL", "refs": [MATRIX_REL]},
            {"check": "environment_metadata_recorded", "status": "PASS" if metadata_ok else "FAIL", "refs": [MATRIX_REL]},
            {"check": "replay_recipe_is_explicit", "status": "PASS" if recipe_explicit else "FAIL", "refs": [RECIPE_REL]},
            {"check": "stronger_claims_explicitly_withheld", "status": "PASS" if stronger_claim_ok else "FAIL", "refs": [MATRIX_REL, RECIPE_REL]},
        ],
        "summary": {
            "environment_count": len(environments),
            "successful_environment_count": len(successful_envs),
            "matrix_ref": MATRIX_REL,
            "recipe_ref": RECIPE_REL,
            "source_package_root_ref": str(matrix.get("source_package_root_ref", "")).strip(),
            "verification_scope": str(matrix.get("verification_scope", "")).strip(),
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS21_BOUNDED_PUBLIC_HORIZON_OPEN",
        },
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "defined two independent clean environments using separate detached package copies",
                "verified the sealed detached verifier package in both environments and recorded environment metadata",
                "emitted an explicit replay recipe and reproduction matrix without widening into public horizon claims",
            ],
            "files_touched": list(changed),
            "tests_run": list(TESTS_RUN),
            "validators_run": list(VALIDATORS_RUN),
            "issues_found": [],
            "resolution": (
                "WS20 proves same-host independent clean-environment verification of the sealed detached verifier package with an explicit replay recipe."
                if status == "PASS"
                else "WS20 remains blocked until two independent clean environments verify the sealed detached verifier package with recorded metadata and an explicit replay recipe."
            ),
            "pass_fail_status": status,
            "unexpected_touches": [],
            "protected_touch_violations": [],
        },
    }
    return {"receipt": receipt}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate WS20 independent clean-environment detached verification.")
    parser.add_argument("--proof-root", default=WS20_PROOF_ROOT_REL)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    current_repo_head = _git_head(root)
    prewrite_dirty = _dirty_relpaths(root, _git_status_lines(root))
    prewrite_scope_clean = not prewrite_dirty or all(path in WORKSTREAM_FILES_TOUCHED for path in prewrite_dirty)

    ws19_manifest = _load_required_json(root, DEFAULT_WS19_MANIFEST_REL)
    ws19_receipt = _load_required_json(root, DEFAULT_WS19_RECEIPT_REL)
    if str(ws19_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: WS19 detached verifier package is not sealed PASS")

    source_package_root = (root / Path(str(ws19_manifest.get("detached_package_root_ref", "")).strip())).resolve()
    if not source_package_root.exists():
        raise RuntimeError(f"FAIL_CLOSED: WS19 detached package root missing: {source_package_root.as_posix()}")

    proof_root = (root / Path(str(args.proof_root))).resolve()
    if proof_root.exists():
        shutil.rmtree(proof_root)
    (proof_root / "reports").mkdir(parents=True, exist_ok=True)

    repo_local_report = build_public_verifier_report(root=root)
    env_a_package_root = (proof_root / "env_a" / "package").resolve()
    env_b_parent = Path(tempfile.mkdtemp(prefix="KT_WS20_external_env_b_")).resolve()
    env_b_package_root = (env_b_parent / "package").resolve()

    env_a = _run_external_environment(
        root=root,
        environment_id="clean_env_repo_copy",
        source_package_root=source_package_root,
        target_package_root=env_a_package_root,
        report_output=(proof_root / "reports" / "env_a_public_verifier_report.json").resolve(),
        receipt_output=(proof_root / "reports" / "env_a_runtime_receipt.json").resolve(),
        metadata_output=(proof_root / "reports" / "env_a_environment_metadata.json").resolve(),
        expected_report=repo_local_report,
    )
    env_b = _run_external_environment(
        root=root,
        environment_id="clean_env_temp_copy",
        source_package_root=source_package_root,
        target_package_root=env_b_package_root,
        report_output=(proof_root / "reports" / "env_b_public_verifier_report.json").resolve(),
        receipt_output=(proof_root / "reports" / "env_b_runtime_receipt.json").resolve(),
        metadata_output=(proof_root / "reports" / "env_b_environment_metadata.json").resolve(),
        expected_report=repo_local_report,
    )

    matrix = {
        "schema_id": "kt.operator.external_reproduction_matrix.v1",
        "artifact_id": Path(MATRIX_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws19_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws19_receipt.get("evidence_head_commit", "")).strip(),
        "status": "PASS" if env_a["status"] == "PASS" and env_b["status"] == "PASS" else "BLOCKED",
        "source_package_root_ref": str(ws19_manifest.get("detached_package_root_ref", "")).strip(),
        "verification_scope": "TWO_CLEAN_ENVIRONMENTS_VERIFY_THE_SEALED_DETACHED_VERIFIER_PACKAGE",
        "verification_target": {
            "subject_head_commit": str(ws19_receipt.get("subject_head_commit", "")).strip(),
            "publication_surface_boundary": str(ws19_receipt.get("summary", {}).get("publication_surface_boundary", "")).strip(),
            "repo_local_parity_fields": list(PARITY_FIELDS),
        },
        "environment_metadata_host": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
        },
        "environments": [env_a, env_b],
        "replay_recipe_ref": RECIPE_REL,
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
    }

    recipe_text = _build_recipe(
        source_package_root_ref=str(ws19_manifest.get("detached_package_root_ref", "")).strip(),
        env_a_root_ref=ENV_A_PACKAGE_REL,
        env_b_root_hint=env_b_package_root.as_posix(),
    )

    write_json_stable((root / Path(MATRIX_REL)).resolve(), matrix, volatile_keys=VOLATILE_JSON_KEYS)
    (root / Path(RECIPE_REL)).resolve().write_text(recipe_text, encoding="utf-8", newline="\n")

    changed_before_receipt = _dirty_relpaths(root, _git_status_lines(root))
    outputs = build_external_reproduction_outputs_from_artifacts(
        current_repo_head=current_repo_head,
        ws19_receipt=ws19_receipt,
        matrix=matrix,
        recipe_text=recipe_text,
        changed_files=[*changed_before_receipt, RECEIPT_REL],
        prewrite_scope_clean=prewrite_scope_clean,
    )
    write_json_stable((root / Path(RECEIPT_REL)).resolve(), outputs["receipt"], volatile_keys=VOLATILE_JSON_KEYS)

    print(
        json.dumps(
            {
                "artifact_id": outputs["receipt"]["artifact_id"],
                "status": outputs["receipt"]["status"],
                "pass_verdict": outputs["receipt"]["pass_verdict"],
                "subject_head_commit": outputs["receipt"]["subject_head_commit"],
                "matrix_ref": MATRIX_REL,
                "recipe_ref": RECIPE_REL,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outputs["receipt"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
