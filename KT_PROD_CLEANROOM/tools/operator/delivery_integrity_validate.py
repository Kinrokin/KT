from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.delivery.delivery_contract_validator import validate_delivery_contract
from tools.operator.titanium_common import (
    file_sha256,
    load_json,
    repo_root,
    utc_now_iso_z,
    write_json_stable,
)


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS15_DELIVERY_INTEGRITY_RESTORATION"
STEP_ID = "WS15_STEP_1_RESTORE_CANONICAL_DELIVERY_INTEGRITY"
PASS_VERDICT = "DELIVERY_INTEGRITY_RESTORED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DELIVERY_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_delivery_integrity_receipt.json"
CANONICAL_PACK_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_canonical_delivery_pack_manifest.json"
AUTHORITY_GRADE_POST_REPAIR_REL = f"{REPORT_ROOT_REL}/kt_authority_grade_post_repair.json"

WS14_EVIDENCE_HEAD = "017d93d2eeffc42ce10b387f3cee457d171cfd93"
BASELINE_AUTHORITY_GRADE_REL = (
    "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/20260315T134001784952Z_authority-grade/reports/authority_grade.json"
)
DEFAULT_CANONICAL_RUN_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_canonical_hmac_seal"
DEFAULT_AUTHORITY_GRADE_REL = (
    "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_authority_grade_seal/reports/authority_grade.json"
)

VALIDATORS_RUN = [
    "python -m tools.operator.delivery_integrity_validate",
    "python -m tools.operator.authority_grade",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_delivery_integrity_validate.py -q",
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_authority_grade.py -q",
]
PROTECTED_PATTERNS = ("KT_ARCHIVE/**", "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")

SUBJECT_TOUCH_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/authority_grade.py",
    "KT_PROD_CLEANROOM/tests/operator/test_authority_grade.py",
    "KT_PROD_CLEANROOM/tools/operator/delivery_integrity_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_delivery_integrity_validate.py",
]
GENERATED_ARTIFACT_REFS = [
    DELIVERY_RECEIPT_REL,
    CANONICAL_PACK_MANIFEST_REL,
    AUTHORITY_GRADE_POST_REPAIR_REL,
]
CREATED_FILES = [
    "KT_PROD_CLEANROOM/tools/operator/delivery_integrity_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_delivery_integrity_validate.py",
    DELIVERY_RECEIPT_REL,
    CANONICAL_PACK_MANIFEST_REL,
    AUTHORITY_GRADE_POST_REPAIR_REL,
]
WORKSTREAM_FILES_TOUCHED = SUBJECT_TOUCH_REFS + GENERATED_ARTIFACT_REFS
SURFACE_CLASSIFICATIONS = {
    "KT_PROD_CLEANROOM/tools/operator/authority_grade.py": "canonical active file",
    "KT_PROD_CLEANROOM/tests/operator/test_authority_grade.py": "validator/test file",
    "KT_PROD_CLEANROOM/tools/operator/delivery_integrity_validate.py": "canonical active file",
    "KT_PROD_CLEANROOM/tests/operator/test_delivery_integrity_validate.py": "validator/test file",
    DELIVERY_RECEIPT_REL: "generated artifact",
    CANONICAL_PACK_MANIFEST_REL: "generated artifact",
    AUTHORITY_GRADE_POST_REPAIR_REL: "generated artifact",
}


def _git(root: Path, *args: str) -> str:
    import subprocess

    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_porcelain(root: Path) -> List[str]:
    import subprocess

    output = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip() for line in output.splitlines() if line.strip()]


def _git_changed_since(root: Path, base_ref: str) -> List[str]:
    output = _git(root, "diff", "--name-only", f"{base_ref}..HEAD")
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _is_protected(path: str) -> bool:
    import fnmatch

    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _extract_delivery_blockers(report: Dict[str, Any]) -> List[str]:
    return sorted(
        [str(item) for item in report.get("blockers", []) if str(item).startswith("DELIVERY_INTEGRITY_FAIL:")],
        key=str.lower,
    )


def _common_fields(*, subject_head: str, status: str, pass_verdict: str) -> Dict[str, Any]:
    return {
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
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "created_files": list(CREATED_FILES),
        "deleted_files": [],
        "retained_new_files": list(CREATED_FILES),
        "temporary_files_removed": [],
        "superseded_files_removed_or_demoted": [],
        "waste_control": {
            "created_files_count": len(CREATED_FILES),
            "deleted_files_count": 0,
            "temporary_files_removed_count": 0,
            "superseded_files_removed_count": 0,
            "net_artifact_delta": len(CREATED_FILES),
            "retention_justifications": [
                {
                    "path": BASELINE_AUTHORITY_GRADE_REL,
                    "reason": "retained as documentary historical baseline for the WS15 delivery-integrity delta",
                },
                {
                    "path": DEFAULT_CANONICAL_RUN_REL,
                    "reason": "retained under the approved operator run root as current canonical delivery evidence",
                },
                {
                    "path": DEFAULT_AUTHORITY_GRADE_REL,
                    "reason": "retained under the approved operator run root as current authority-grade evidence",
                },
            ],
        },
        "surface_classifications": dict(SURFACE_CLASSIFICATIONS),
    }


def load_canonical_delivery_facts(root: Path, canonical_run_rel: str) -> Dict[str, Any]:
    canonical_run = (root / Path(canonical_run_rel)).resolve()
    delivery_dir = (canonical_run / "delivery").resolve()
    contract = validate_delivery_contract(delivery_dir, require_real_path_receipt=True)

    delivery_manifest = load_json(delivery_dir / "delivery_manifest.json")
    pack_dir = Path(str(contract.get("pack_dir", ""))).resolve()
    pack_manifest_path = (pack_dir / "delivery_pack_manifest.json").resolve()
    pack_manifest = load_json(pack_manifest_path)
    secret_scan_report = load_json((canonical_run / "evidence" / "secret_scan_report.json").resolve())
    delivery_lint_report = load_json((delivery_dir / "delivery_lint_report.json").resolve())

    zip_info = delivery_manifest.get("delivery_zip", {})
    if not isinstance(zip_info, dict):
        raise RuntimeError("FAIL_CLOSED: delivery_manifest.delivery_zip missing/invalid")
    zip_path_raw = str(zip_info.get("path", "")).strip()
    if not zip_path_raw:
        raise RuntimeError("FAIL_CLOSED: delivery_manifest.delivery_zip.path missing")
    zip_path = Path(zip_path_raw).expanduser()
    if not zip_path.is_absolute():
        zip_path = (canonical_run / zip_path).resolve()
    zip_path = zip_path.resolve()
    if not zip_path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing canonical delivery zip: {zip_path.as_posix()}")
    zip_sha_claim = str(zip_info.get("sha256", "")).strip()
    zip_sha_actual = file_sha256(zip_path)
    if zip_sha_claim and zip_sha_claim != zip_sha_actual:
        raise RuntimeError("FAIL_CLOSED: canonical delivery zip sha256 mismatch")

    sha_receipts = sorted([p.name for p in delivery_dir.glob("*.sha256") if p.is_file()], key=str.lower)
    if not sha_receipts:
        raise RuntimeError("FAIL_CLOSED: missing canonical delivery sha256 sidecar")

    files = pack_manifest.get("files")
    if not isinstance(files, list):
        raise RuntimeError("FAIL_CLOSED: delivery_pack_manifest.files missing")

    return {
        "contract_status": str(contract.get("status", "")).strip(),
        "canonical_run_ref": canonical_run_rel,
        "operator_delivery_dir": str(delivery_dir.as_posix()),
        "pack_dir": str(pack_dir.as_posix()),
        "delivery_manifest_ref": str((delivery_dir / "delivery_manifest.json").relative_to(root).as_posix()),
        "pack_manifest_ref": str(pack_manifest_path.relative_to(root).as_posix()),
        "zip_path": str(zip_path.relative_to(root).as_posix()),
        "zip_sha256": zip_sha_actual,
        "sha256_receipts": sha_receipts,
        "secret_scan_status": str(secret_scan_report.get("status", "")).strip(),
        "delivery_lint_status": str(delivery_lint_report.get("status", "")).strip(),
        "delivery_pack_file_count": len(files),
        "delivery_pack_id": str(pack_manifest.get("delivery_pack_id", "")).strip(),
        "bundle_root_hash": str(pack_manifest.get("bundle_root_hash", "")).strip(),
        "run_id": str(delivery_manifest.get("run_id", "")).strip(),
        "head": str(delivery_manifest.get("head", "")).strip(),
        "lane": str(delivery_manifest.get("lane", "")).strip(),
    }


def build_delivery_integrity_outputs_from_artifacts(
    *,
    baseline_report: Dict[str, Any],
    current_report: Dict[str, Any],
    canonical_facts: Dict[str, Any],
    subject_head: str,
    changed_files: Sequence[str],
    prewrite_git_clean: bool,
    baseline_authority_ref: str,
    current_authority_ref: str,
) -> Dict[str, Dict[str, Any]]:
    unexpected = sorted(path for path in changed_files if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed_files if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError(
            "FAIL_CLOSED: unexpected subject touches detected: "
            + ", ".join(unexpected + protected)
        )

    baseline_delivery_blockers = _extract_delivery_blockers(baseline_report)
    current_delivery_blockers = _extract_delivery_blockers(current_report)
    current_grade = str(current_report.get("grade", "")).strip()
    current_status = str(current_report.get("status", "")).strip()
    baseline_grade = str(baseline_report.get("grade", "")).strip()
    baseline_status = str(baseline_report.get("status", "")).strip()

    canonical_manifest = _common_fields(
        subject_head=subject_head,
        status="PASS" if str(canonical_facts.get("contract_status", "")) == "PASS" else "BLOCKED",
        pass_verdict="CANONICAL_DELIVERY_PACK_MANIFEST_EMITTED"
        if str(canonical_facts.get("contract_status", "")) == "PASS"
        else "CANONICAL_DELIVERY_PACK_MANIFEST_BLOCKED",
    )
    canonical_manifest.update(
        {
            "schema_id": "kt.operator.canonical_delivery_pack_manifest.v1",
            "artifact_id": Path(CANONICAL_PACK_MANIFEST_REL).name,
            "input_refs": [
                str(canonical_facts.get("canonical_run_ref", "")),
                str(canonical_facts.get("delivery_manifest_ref", "")),
                str(canonical_facts.get("pack_manifest_ref", "")),
            ],
            "next_lawful_step": {
                "status_after_workstream": "UNLOCKED"
                if str(canonical_facts.get("contract_status", "")) == "PASS"
                else "BLOCKED",
                "workstream_id": "WS16_HERMETIC_BUILD_ENVELOPE",
            },
            "artifact_subjects": [
                {
                    "kind": "operator_delivery_manifest",
                    "path": str(canonical_facts.get("delivery_manifest_ref", "")),
                },
                {
                    "kind": "canonical_delivery_pack_manifest",
                    "path": str(canonical_facts.get("pack_manifest_ref", "")),
                },
                {
                    "kind": "canonical_delivery_zip",
                    "path": str(canonical_facts.get("zip_path", "")),
                },
            ],
            "hashes": {
                "delivery_pack_id": str(canonical_facts.get("delivery_pack_id", "")),
                "bundle_root_hash": str(canonical_facts.get("bundle_root_hash", "")),
                "zip_sha256": str(canonical_facts.get("zip_sha256", "")),
            },
            "source_commit": str(canonical_facts.get("head", "")).strip(),
            "builder_or_generator": "python -m tools.operator.kt_cli --profile v1 certify --lane canonical_hmac",
            "policy_refs": [
                "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
                "KT_PROD_CLEANROOM/tools/delivery/delivery_contract_validator.py",
                "KT_PROD_CLEANROOM/tools/delivery/generate_delivery_pack.py",
            ],
            "verification_refs": [
                str(canonical_facts.get("delivery_manifest_ref", "")),
                str(canonical_facts.get("pack_manifest_ref", "")),
                current_authority_ref,
            ],
            "summary": {
                "run_id": str(canonical_facts.get("run_id", "")),
                "lane": str(canonical_facts.get("lane", "")),
                "delivery_pack_file_count": int(canonical_facts.get("delivery_pack_file_count", 0)),
                "sha256_receipts": list(canonical_facts.get("sha256_receipts", [])),
                "contract_status": str(canonical_facts.get("contract_status", "")),
            },
        }
    )

    authority_post = _common_fields(
        subject_head=subject_head,
        status="PASS" if not current_delivery_blockers else "BLOCKED",
        pass_verdict="AUTHORITY_GRADE_DELIVERY_CAP_CLEARED" if not current_delivery_blockers else "AUTHORITY_GRADE_DELIVERY_CAP_REMAINS",
    )
    authority_post.update(
        {
            "schema_id": "kt.operator.authority_grade_post_repair.v1",
            "artifact_id": Path(AUTHORITY_GRADE_POST_REPAIR_REL).name,
            "input_refs": [
                baseline_authority_ref,
                current_authority_ref,
                str(canonical_facts.get("delivery_manifest_ref", "")),
            ],
            "next_lawful_step": {
                "status_after_workstream": "UNLOCKED" if not current_delivery_blockers else "BLOCKED",
                "workstream_id": "WS16_HERMETIC_BUILD_ENVELOPE",
            },
            "summary": {
                "baseline_status": baseline_status,
                "baseline_grade": baseline_grade,
                "baseline_delivery_blockers": baseline_delivery_blockers,
                "current_status": current_status,
                "current_grade": current_grade,
                "current_delivery_blockers": current_delivery_blockers,
                "delivery_integrity_blocker_cleared": bool(baseline_delivery_blockers) and not current_delivery_blockers,
                "integrity_failures": int(current_report.get("integrity_failures", 0)),
            },
            "baseline_authority_grade_ref": baseline_authority_ref,
            "current_authority_grade_ref": current_authority_ref,
        }
    )

    checks = [
        {
            "check": "prewrite_git_status_clean",
            "status": "PASS" if prewrite_git_clean else "FAIL",
            "refs": [current_authority_ref],
        },
        {
            "check": "workstream_touches_remain_in_scope",
            "status": "PASS" if not unexpected and not protected else "FAIL",
            "refs": list(WORKSTREAM_FILES_TOUCHED),
        },
        {
            "check": "baseline_contains_delivery_integrity_blocker",
            "status": "PASS" if bool(baseline_delivery_blockers) else "FAIL",
            "refs": [baseline_authority_ref],
        },
        {
            "check": "canonical_delivery_contract_passes",
            "status": "PASS" if str(canonical_facts.get("contract_status", "")) == "PASS" else "FAIL",
            "refs": [str(canonical_facts.get("delivery_manifest_ref", "")), str(canonical_facts.get("pack_manifest_ref", ""))],
        },
        {
            "check": "authority_grade_no_longer_held_by_delivery_integrity",
            "status": "PASS" if not current_delivery_blockers else "FAIL",
            "refs": [baseline_authority_ref, current_authority_ref],
        },
    ]
    receipt_status = "PASS" if all(row["status"] == "PASS" for row in checks) else "BLOCKED"
    receipt = _common_fields(
        subject_head=subject_head,
        status=receipt_status,
        pass_verdict=PASS_VERDICT if receipt_status == "PASS" else "DELIVERY_INTEGRITY_BLOCKED",
    )
    receipt.update(
        {
            "schema_id": "kt.operator.delivery_integrity_receipt.v1",
            "artifact_id": Path(DELIVERY_RECEIPT_REL).name,
            "input_refs": [
                baseline_authority_ref,
                current_authority_ref,
                str(canonical_facts.get("delivery_manifest_ref", "")),
                str(canonical_facts.get("pack_manifest_ref", "")),
                str(canonical_facts.get("zip_path", "")),
                *SUBJECT_TOUCH_REFS,
            ],
            "next_lawful_step": {
                "status_after_workstream": "UNLOCKED" if receipt_status == "PASS" else "BLOCKED",
                "workstream_id": "WS16_HERMETIC_BUILD_ENVELOPE",
            },
            "checks": checks,
            "summary": {
                "baseline_grade": baseline_grade,
                "current_grade": current_grade,
                "baseline_delivery_blocker_count": len(baseline_delivery_blockers),
                "current_delivery_blocker_count": len(current_delivery_blockers),
                "canonical_delivery_pack_id": str(canonical_facts.get("delivery_pack_id", "")),
            },
            "step_report": {
                "timestamp": utc_now_iso_z(),
                "workstream_id": WORKSTREAM_ID,
                "step_id": STEP_ID,
                "actions_taken": [
                    "repaired authority-grade delivery path resolution for lane-local canonical delivery packs",
                    "revalidated the current canonical HMAC delivery contract and pack manifest",
                    "reran authority grading against the repaired delivery-integrity path and sealed the before/after delta",
                ],
                "files_touched": list(WORKSTREAM_FILES_TOUCHED),
                "tests_run": list(TESTS_RUN),
                "validators_run": list(VALIDATORS_RUN),
                "issues_found": baseline_delivery_blockers,
                "resolution": (
                    "WS15 restores the canonical delivery-integrity path and clears the stale authority-grade delivery blocker."
                    if receipt_status == "PASS"
                    else "WS15 remains blocked until the canonical delivery contract passes and authority grading clears the delivery blocker."
                ),
                "pass_fail_status": receipt_status,
                "unexpected_touches": [],
                "protected_touch_violations": [],
            },
        }
    )

    return {
        "canonical_manifest": canonical_manifest,
        "authority_post_repair": authority_post,
        "receipt": receipt,
    }


def build_ws15_outputs(
    root: Path,
    *,
    baseline_authority_rel: str = BASELINE_AUTHORITY_GRADE_REL,
    canonical_run_rel: str = DEFAULT_CANONICAL_RUN_REL,
    current_authority_rel: str = DEFAULT_AUTHORITY_GRADE_REL,
    subject_head_override: Optional[str] = None,
    changed_files_override: Optional[Sequence[str]] = None,
    prewrite_git_clean_override: Optional[bool] = None,
) -> Dict[str, Dict[str, Any]]:
    baseline_report = _load_required_json(root, baseline_authority_rel)
    current_report = _load_required_json(root, current_authority_rel)
    canonical_facts = load_canonical_delivery_facts(root, canonical_run_rel)
    subject_head = subject_head_override or _git_head(root)
    changed_files = list(changed_files_override) if changed_files_override is not None else _git_changed_since(root, WS14_EVIDENCE_HEAD)
    prewrite_git_clean = (
        bool(prewrite_git_clean_override)
        if prewrite_git_clean_override is not None
        else not _git_status_porcelain(root)
    )
    return build_delivery_integrity_outputs_from_artifacts(
        baseline_report=baseline_report,
        current_report=current_report,
        canonical_facts=canonical_facts,
        subject_head=subject_head,
        changed_files=changed_files,
        prewrite_git_clean=prewrite_git_clean,
        baseline_authority_ref=baseline_authority_rel,
        current_authority_ref=current_authority_rel,
    )


def _write_outputs(
    root: Path,
    *,
    baseline_authority_rel: str,
    canonical_run_rel: str,
    current_authority_rel: str,
) -> List[str]:
    outputs = build_ws15_outputs(
        root,
        baseline_authority_rel=baseline_authority_rel,
        canonical_run_rel=canonical_run_rel,
        current_authority_rel=current_authority_rel,
    )
    changed: List[str] = []
    mapping = {
        CANONICAL_PACK_MANIFEST_REL: outputs["canonical_manifest"],
        AUTHORITY_GRADE_POST_REPAIR_REL: outputs["authority_post_repair"],
        DELIVERY_RECEIPT_REL: outputs["receipt"],
    }
    for rel, payload in mapping.items():
        if write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=VOLATILE_JSON_KEYS):
            changed.append(rel)
    return changed


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate WS15 delivery integrity restoration and emit sealed reports.")
    parser.add_argument("--baseline-authority-report", default=BASELINE_AUTHORITY_GRADE_REL)
    parser.add_argument("--canonical-run-dir", default=DEFAULT_CANONICAL_RUN_REL)
    parser.add_argument("--current-authority-report", default=DEFAULT_AUTHORITY_GRADE_REL)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    changed = _write_outputs(
        root,
        baseline_authority_rel=str(args.baseline_authority_report),
        canonical_run_rel=str(args.canonical_run_dir),
        current_authority_rel=str(args.current_authority_report),
    )
    receipt = load_json((root / Path(DELIVERY_RECEIPT_REL)).resolve())
    import json

    print(
        json.dumps(
            {
                "artifact_id": receipt["artifact_id"],
                "status": receipt["status"],
                "pass_verdict": receipt["pass_verdict"],
                "subject_head_commit": receipt["subject_head_commit"],
                "evidence_head_commit": receipt["evidence_head_commit"],
                "unexpected_touches": receipt["unexpected_touches"],
                "protected_touch_violations": receipt["protected_touch_violations"],
                "changed": sorted(changed),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
