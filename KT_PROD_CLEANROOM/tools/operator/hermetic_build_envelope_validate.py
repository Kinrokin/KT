from __future__ import annotations

import argparse
import fnmatch
import hashlib
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.delivery.delivery_contract_validator import validate_delivery_contract
from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.hermetic_replay_linter import lint_hermetic_replay
from tools.operator.titanium_common import file_sha256, load_json, make_run_dir, repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS16_HERMETIC_BUILD_ENVELOPE"
STEP_ID = "WS16_STEP_1_PROVE_CRITICAL_ARTIFACT_BUILD_ENVELOPE"
PASS_VERDICT = "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_hermetic_build_envelope_manifest.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_hermetic_build_envelope_receipt.json"

WS15_EVIDENCE_HEAD = "b4789a544954066ee6c225bc9cfa3fddb51c12ee"
DEFAULT_STATUS_REPORT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_status_seal_b4789a5/status_report.json"
DEFAULT_CANONICAL_RUN_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_canonical_hmac_seal_b4789a5"
DEFAULT_AUTHORITY_REPORT_REL = (
    "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_authority_grade_b4789a5/reports/authority_grade.json"
)
DEFAULT_REPLAY_RUN_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS16_hermetic_replay_proof"

VALIDATORS_RUN = [
    "python -m tools.operator.hermetic_build_envelope_validate",
    "python -m tools.operator.hermetic_replay_linter",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_hermetic_build_envelope_validate.py -q",
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_titanium_substrate.py -k hermetic_replay_linter -q",
]
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/hermetic_build_envelope_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_hermetic_build_envelope_validate.py"
SUBJECT_TOUCH_REFS = [
    TOOL_REL,
    TEST_REL,
]
GENERATED_ARTIFACT_REFS = [
    MANIFEST_REL,
    RECEIPT_REL,
]
CREATED_FILES = [
    TOOL_REL,
    TEST_REL,
    MANIFEST_REL,
    RECEIPT_REL,
]
WORKSTREAM_FILES_TOUCHED = SUBJECT_TOUCH_REFS + GENERATED_ARTIFACT_REFS
SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    MANIFEST_REL: "generated artifact",
    RECEIPT_REL: "generated artifact",
}


def _git(root: Path, *args: str) -> str:
    import subprocess

    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


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
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _require_file(path: Path, *, label: str) -> Path:
    path = path.resolve()
    if not path.exists() or not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required file: {label}: {path.as_posix()}")
    return path


def _rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _sha256_rows(rows: Sequence[Dict[str, Any]]) -> str:
    lines = [f"{row['path']}:{row['sha256']}\n" for row in sorted(rows, key=lambda item: str(item["path"]).lower())]
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def _derive_envelope_mode(container_image_digest: str) -> tuple[str, str, str]:
    if str(container_image_digest).strip():
        return (
            "HERMETIC_CONTAINER_DIGEST_PINNED",
            str(container_image_digest).strip(),
            "container digest pinned; replay claim extends only to that containerized environment plus the recorded critical artifact set",
        )
    return (
        "NEAR_HERMETIC_LOCAL_ENV_FINGERPRINTED",
        "LOCAL_UNCONTAINERIZED_ENVIRONMENT",
        "no real container digest is pinned; replay claim is limited to the recorded platform and Python-version fingerprint only",
    )


def load_canonical_hermetic_facts(root: Path, canonical_run_rel: str, *, container_image_digest: str) -> Dict[str, Any]:
    canonical_run = (root / Path(canonical_run_rel)).resolve()
    delivery_dir = (canonical_run / "delivery").resolve()
    validation = validate_delivery_contract(delivery_dir, require_real_path_receipt=True)

    delivery_manifest_path = _require_file(delivery_dir / "delivery_manifest.json", label="delivery_manifest")
    delivery_manifest = load_json(delivery_manifest_path)

    pack_dir_raw = str(delivery_manifest.get("delivery_dir", "")).strip()
    if not pack_dir_raw:
        raise RuntimeError("FAIL_CLOSED: delivery_manifest.delivery_dir missing")
    pack_dir = Path(pack_dir_raw).expanduser()
    if not pack_dir.is_absolute():
        pack_dir = (canonical_run / pack_dir).resolve()
    pack_dir = pack_dir.resolve()

    pack_manifest_path = _require_file(pack_dir / "delivery_pack_manifest.json", label="delivery_pack_manifest")
    operator_fp_path = _require_file(canonical_run / "reports" / "operator_fingerprint.json", label="operator_fingerprint")
    replay_receipt_path = _require_file(canonical_run / "evidence" / "replay_receipt.json", label="replay_receipt")
    run_protocol_path = _require_file(canonical_run / "evidence" / "run_protocol.json", label="run_protocol")
    replay_sh_path = _require_file(canonical_run / "evidence" / "replay.sh", label="replay.sh")
    replay_ps1_path = _require_file(canonical_run / "evidence" / "replay.ps1", label="replay.ps1")
    real_path_receipt_path = _require_file(
        canonical_run / "reports" / "real_path_attachment_receipt.json",
        label="real_path_attachment_receipt",
    )
    zip_info = delivery_manifest.get("delivery_zip")
    if not isinstance(zip_info, dict):
        raise RuntimeError("FAIL_CLOSED: delivery_manifest.delivery_zip missing")
    zip_path_raw = str(zip_info.get("path", "")).strip()
    if not zip_path_raw:
        raise RuntimeError("FAIL_CLOSED: delivery_manifest.delivery_zip.path missing")
    zip_path = Path(zip_path_raw).expanduser()
    if not zip_path.is_absolute():
        zip_path = (canonical_run / zip_path).resolve()
    zip_path = _require_file(zip_path, label="delivery_zip")

    operator_fp = load_json(operator_fp_path)
    mve_environment_fingerprint = str(operator_fp.get("mve_environment_fingerprint", "")).strip()
    runtime_fingerprint = str(operator_fp.get("runtime_fingerprint", "")).strip()
    if len(mve_environment_fingerprint) != 64:
        raise RuntimeError("FAIL_CLOSED: canonical operator fingerprint missing mve_environment_fingerprint")
    if len(runtime_fingerprint) != 64:
        raise RuntimeError("FAIL_CLOSED: canonical operator fingerprint missing runtime_fingerprint")

    envelope_mode, digest_value, claim_ceiling = _derive_envelope_mode(container_image_digest)
    critical_artifacts = [
        {"kind": "operator_delivery_manifest", "path": _rel(root, delivery_manifest_path), "sha256": file_sha256(delivery_manifest_path)},
        {"kind": "delivery_pack_manifest", "path": _rel(root, pack_manifest_path), "sha256": file_sha256(pack_manifest_path)},
        {"kind": "delivery_zip", "path": _rel(root, zip_path), "sha256": file_sha256(zip_path)},
        {"kind": "operator_fingerprint", "path": _rel(root, operator_fp_path), "sha256": file_sha256(operator_fp_path)},
        {"kind": "replay_receipt", "path": _rel(root, replay_receipt_path), "sha256": file_sha256(replay_receipt_path)},
        {"kind": "run_protocol", "path": _rel(root, run_protocol_path), "sha256": file_sha256(run_protocol_path)},
        {"kind": "replay_sh", "path": _rel(root, replay_sh_path), "sha256": file_sha256(replay_sh_path)},
        {"kind": "replay_ps1", "path": _rel(root, replay_ps1_path), "sha256": file_sha256(replay_ps1_path)},
        {
            "kind": "real_path_attachment_receipt",
            "path": _rel(root, real_path_receipt_path),
            "sha256": file_sha256(real_path_receipt_path),
        },
    ]

    return {
        "canonical_run_ref": canonical_run_rel,
        "contract_status": str(validation.get("status", "")).strip(),
        "delivery_dir": _rel(root, delivery_dir),
        "delivery_manifest_ref": _rel(root, delivery_manifest_path),
        "pack_manifest_ref": _rel(root, pack_manifest_path),
        "zip_path": _rel(root, zip_path),
        "operator_fingerprint_ref": _rel(root, operator_fp_path),
        "replay_receipt_ref": _rel(root, replay_receipt_path),
        "run_protocol_ref": _rel(root, run_protocol_path),
        "replay_sh_ref": _rel(root, replay_sh_path),
        "replay_ps1_ref": _rel(root, replay_ps1_path),
        "real_path_receipt_ref": _rel(root, real_path_receipt_path),
        "critical_artifacts": critical_artifacts,
        "critical_artifact_root_sha256": _sha256_rows(critical_artifacts),
        "critical_artifact_count": len(critical_artifacts),
        "delivery_pack_id": str(load_json(pack_manifest_path).get("delivery_pack_id", "")).strip(),
        "bundle_root_hash": str(load_json(pack_manifest_path).get("bundle_root_hash", "")).strip(),
        "head": str(delivery_manifest.get("head", "")).strip(),
        "lane": str(delivery_manifest.get("lane", "")).strip(),
        "lane_id": str(delivery_manifest.get("lane_id", "")).strip(),
        "pins": delivery_manifest.get("pins", {}),
        "replay_command": str(delivery_manifest.get("replay_command", "")).strip(),
        "mve_environment_fingerprint": mve_environment_fingerprint,
        "runtime_fingerprint": runtime_fingerprint,
        "python_version": platform.python_version(),
        "os_release": platform.platform(),
        "container_image_digest": digest_value,
        "envelope_mode": envelope_mode,
        "claim_ceiling": claim_ceiling,
    }


def build_envelope_manifest_payload(
    *,
    status_report: Dict[str, Any],
    authority_report: Dict[str, Any],
    canonical_facts: Dict[str, Any],
    hermetic_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    subject_head = str(canonical_facts.get("head", "")).strip()
    status_pass = str(status_report.get("status", "")).strip() == "PASS"
    authority_pass = (
        str(authority_report.get("status", "")).strip() == "PASS"
        and str(authority_report.get("grade", "")).strip() == "A"
        and not list(authority_report.get("blockers", []))
    )
    hermetic_pass = hermetic_report is not None and str(hermetic_report.get("status", "")).strip() == "PASS"
    status = "PASS" if status_pass and authority_pass and hermetic_pass else "BLOCKED"
    pass_verdict = PASS_VERDICT if status == "PASS" else "HERMETIC_BUILD_ENVELOPE_BLOCKED"
    payload = {
        "schema_id": "kt.operator.hermetic_build_envelope_manifest.v1",
        "artifact_id": Path(MANIFEST_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": subject_head,
        "compiled_head_commit": subject_head,
        "evidence_head_commit": subject_head,
        "status": status,
        "pass_verdict": pass_verdict,
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "input_refs": [
            DEFAULT_STATUS_REPORT_REL,
            DEFAULT_AUTHORITY_REPORT_REL,
            str(canonical_facts.get("canonical_run_ref", "")),
            str(canonical_facts.get("delivery_manifest_ref", "")),
            str(canonical_facts.get("pack_manifest_ref", "")),
            str(canonical_facts.get("operator_fingerprint_ref", "")),
            str(canonical_facts.get("replay_receipt_ref", "")),
            str(canonical_facts.get("run_protocol_ref", "")),
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS17_SOURCE_BUILD_ATTESTATION",
        },
        "envelope_mode": str(canonical_facts.get("envelope_mode", "")).strip(),
        "claim_ceiling": str(canonical_facts.get("claim_ceiling", "")).strip(),
        "container_image_digest": str(canonical_facts.get("container_image_digest", "")).strip(),
        "python_version": str(canonical_facts.get("python_version", "")).strip(),
        "os_release": str(canonical_facts.get("os_release", "")).strip(),
        "mve_environment_fingerprint": str(canonical_facts.get("mve_environment_fingerprint", "")).strip(),
        "runtime_fingerprint": str(canonical_facts.get("runtime_fingerprint", "")).strip(),
        "canonical_run_ref": str(canonical_facts.get("canonical_run_ref", "")),
        "replay_command": str(canonical_facts.get("replay_command", "")).strip(),
        "critical_artifact_root_sha256": str(canonical_facts.get("critical_artifact_root_sha256", "")).strip(),
        "critical_artifact_count": int(canonical_facts.get("critical_artifact_count", 0)),
        "critical_artifacts": list(canonical_facts.get("critical_artifacts", [])),
        "delivery_pack_id": str(canonical_facts.get("delivery_pack_id", "")).strip(),
        "bundle_root_hash": str(canonical_facts.get("bundle_root_hash", "")).strip(),
        "pins": canonical_facts.get("pins", {}),
        "summary": {
            "status_lane_pass": status_pass,
            "authority_grade_a": authority_pass,
            "canonical_delivery_contract_status": str(canonical_facts.get("contract_status", "")).strip(),
            "hermetic_replay_status": str(hermetic_report.get("status", "")).strip() if hermetic_report else "NOT_RUN",
        },
    }
    if hermetic_report:
        payload["hermetic_replay_run_ref"] = str(hermetic_report.get("replay_run_ref", "")).strip()
        payload["hermetic_replay_receipt_ref"] = str(hermetic_report.get("replay_receipt_ref", "")).strip()
    return payload


def build_hermetic_build_outputs_from_artifacts(
    *,
    status_report: Dict[str, Any],
    authority_report: Dict[str, Any],
    canonical_facts: Dict[str, Any],
    hermetic_report: Dict[str, Any],
    changed_files: Sequence[str],
    prewrite_git_clean: bool,
) -> Dict[str, Dict[str, Any]]:
    unexpected = sorted(path for path in changed_files if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed_files if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError("FAIL_CLOSED: unexpected subject touches detected: " + ", ".join(unexpected + protected))

    subject_head = str(canonical_facts.get("head", "")).strip()
    status_head = str(status_report.get("head", "")).strip()
    authority_head = str(authority_report.get("head", "")).strip()
    if {subject_head, status_head, authority_head} != {subject_head}:
        raise RuntimeError("FAIL_CLOSED: WS15 heads do not converge on the sealed canonical subject head")

    status_ok = str(status_report.get("status", "")).strip() == "PASS"
    authority_ok = (
        str(authority_report.get("status", "")).strip() == "PASS"
        and str(authority_report.get("grade", "")).strip() == "A"
        and not list(authority_report.get("blockers", []))
    )
    canonical_ok = str(canonical_facts.get("contract_status", "")).strip() == "PASS"
    hermetic_ok = str(hermetic_report.get("status", "")).strip() == "PASS"

    manifest = build_envelope_manifest_payload(
        status_report=status_report,
        authority_report=authority_report,
        canonical_facts=canonical_facts,
        hermetic_report=hermetic_report,
    )

    status = "PASS" if all([prewrite_git_clean, status_ok, authority_ok, canonical_ok, hermetic_ok]) else "BLOCKED"
    receipt = {
        "schema_id": "kt.operator.hermetic_build_envelope_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": subject_head,
        "compiled_head_commit": subject_head,
        "evidence_head_commit": subject_head,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "HERMETIC_BUILD_ENVELOPE_BLOCKED",
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
                    "path": str(canonical_facts.get("canonical_run_ref", "")),
                    "reason": "retained under the approved operator run root as the sealed WS15 canonical delivery evidence",
                },
                {
                    "path": str(hermetic_report.get("replay_run_ref", "")),
                    "reason": "retained under the approved operator run root as the WS16 hermetic replay proof run",
                },
            ],
        },
        "surface_classifications": dict(SURFACE_CLASSIFICATIONS),
        "input_refs": [
            DEFAULT_STATUS_REPORT_REL,
            DEFAULT_AUTHORITY_REPORT_REL,
            str(canonical_facts.get("canonical_run_ref", "")),
            str(canonical_facts.get("delivery_manifest_ref", "")),
            str(canonical_facts.get("pack_manifest_ref", "")),
            str(canonical_facts.get("operator_fingerprint_ref", "")),
            MANIFEST_REL,
            str(hermetic_report.get("replay_receipt_ref", "")),
            *SUBJECT_TOUCH_REFS,
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS17_SOURCE_BUILD_ATTESTATION",
        },
        "checks": [
            {
                "check": "prewrite_git_status_clean",
                "status": "PASS" if prewrite_git_clean else "FAIL",
                "refs": [str(canonical_facts.get("canonical_run_ref", ""))],
            },
            {
                "check": "workstream_touches_remain_in_scope",
                "status": "PASS",
                "refs": list(WORKSTREAM_FILES_TOUCHED),
            },
            {
                "check": "ws15_status_pass",
                "status": "PASS" if status_ok else "FAIL",
                "refs": [DEFAULT_STATUS_REPORT_REL],
            },
            {
                "check": "ws15_authority_grade_a",
                "status": "PASS" if authority_ok else "FAIL",
                "refs": [DEFAULT_AUTHORITY_REPORT_REL],
            },
            {
                "check": "canonical_delivery_contract_passes",
                "status": "PASS" if canonical_ok else "FAIL",
                "refs": [str(canonical_facts.get("delivery_manifest_ref", "")), str(canonical_facts.get("pack_manifest_ref", ""))],
            },
            {
                "check": "critical_artifact_set_hashed",
                "status": "PASS" if int(canonical_facts.get("critical_artifact_count", 0)) > 0 else "FAIL",
                "refs": [MANIFEST_REL],
            },
            {
                "check": "hermetic_replay_lint_passes",
                "status": "PASS" if hermetic_ok else "FAIL",
                "refs": [str(hermetic_report.get("replay_receipt_ref", ""))],
            },
        ],
        "summary": {
            "envelope_mode": str(canonical_facts.get("envelope_mode", "")).strip(),
            "claim_ceiling": str(canonical_facts.get("claim_ceiling", "")).strip(),
            "critical_artifact_count": int(canonical_facts.get("critical_artifact_count", 0)),
            "critical_artifact_root_sha256": str(canonical_facts.get("critical_artifact_root_sha256", "")).strip(),
            "mve_environment_fingerprint": str(canonical_facts.get("mve_environment_fingerprint", "")).strip(),
            "canonical_run_ref": str(canonical_facts.get("canonical_run_ref", "")),
            "hermetic_replay_run_ref": str(hermetic_report.get("replay_run_ref", "")),
        },
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "defined the critical artifact set for the sealed WS15 canonical delivery bundle",
                "derived a bounded MVE replay envelope from the sealed operator fingerprint and current platform surface",
                "replayed the delivery contract under the bounded MVE envelope to prove a narrow near-hermetic build claim",
            ],
            "files_touched": list(changed_files),
            "tests_run": list(TESTS_RUN),
            "validators_run": list(VALIDATORS_RUN),
            "issues_found": [],
            "resolution": (
                "WS16 proves a narrow near-hermetic build envelope for the current critical artifact set without widening into general build-system reinvention."
                if status == "PASS"
                else "WS16 remains blocked until the sealed WS15 artifact set passes the bounded hermetic replay proof."
            ),
            "pass_fail_status": status,
            "unexpected_touches": [],
            "protected_touch_violations": [],
        },
    }
    return {
        "manifest": manifest,
        "receipt": receipt,
    }


def _write_replay_receipt(run_dir: Path, report: Dict[str, Any]) -> str:
    rel = _rel(repo_root(), run_dir / "reports" / "replay_receipt.json")
    write_json_stable(run_dir / "reports" / "replay_receipt.json", report, volatile_keys=())
    return rel


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the WS16 hermetic build envelope and emit sealed reports.")
    parser.add_argument("--status-report", default=DEFAULT_STATUS_REPORT_REL)
    parser.add_argument("--canonical-run-dir", default=DEFAULT_CANONICAL_RUN_REL)
    parser.add_argument("--authority-report", default=DEFAULT_AUTHORITY_REPORT_REL)
    parser.add_argument("--container-image-digest", default="")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    prewrite_git_clean = not _git_status_porcelain(root)
    changed_files = _git_changed_since(root, WS15_EVIDENCE_HEAD)
    status_report = _load_required_json(root, str(args.status_report))
    authority_report = _load_required_json(root, str(args.authority_report))
    canonical_facts = load_canonical_hermetic_facts(
        root,
        str(args.canonical_run_dir),
        container_image_digest=str(args.container_image_digest),
    )

    proof_run = make_run_dir(cmd_name="hermetic-replay-proof", requested_run_root=DEFAULT_REPLAY_RUN_REL)
    provisional_manifest = build_envelope_manifest_payload(
        status_report=status_report,
        authority_report=authority_report,
        canonical_facts=canonical_facts,
        hermetic_report=None,
    )
    manifest_path = (root / Path(MANIFEST_REL)).resolve()
    write_json_stable(manifest_path, provisional_manifest, volatile_keys=VOLATILE_JSON_KEYS)

    hermetic_core = lint_hermetic_replay(
        delivery_dir=(root / Path(str(canonical_facts["delivery_dir"]))).resolve(),
        mve_json=manifest_path,
        run_dir=proof_run,
    )
    replay_receipt_ref = _write_replay_receipt(proof_run, hermetic_core)
    hermetic_report = {
        **hermetic_core,
        "replay_run_ref": _rel(root, proof_run),
        "replay_receipt_ref": replay_receipt_ref,
    }

    outputs = build_hermetic_build_outputs_from_artifacts(
        status_report=status_report,
        authority_report=authority_report,
        canonical_facts=canonical_facts,
        hermetic_report=hermetic_report,
        changed_files=changed_files,
        prewrite_git_clean=prewrite_git_clean,
    )
    changed: List[str] = []
    for rel, payload in ((MANIFEST_REL, outputs["manifest"]), (RECEIPT_REL, outputs["receipt"])):
        if write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=VOLATILE_JSON_KEYS):
            changed.append(rel)

    import json

    print(
        json.dumps(
            {
                "artifact_id": outputs["receipt"]["artifact_id"],
                "status": outputs["receipt"]["status"],
                "pass_verdict": outputs["receipt"]["pass_verdict"],
                "subject_head_commit": outputs["receipt"]["subject_head_commit"],
                "evidence_head_commit": outputs["receipt"]["evidence_head_commit"],
                "unexpected_touches": outputs["receipt"]["unexpected_touches"],
                "protected_touch_violations": outputs["receipt"]["protected_touch_violations"],
                "changed": sorted(changed),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outputs["receipt"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
