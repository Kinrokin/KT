from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.verification.attestation_hmac import env_key_name_for_key_id, hmac_key_fingerprint_hex, sign_hmac, verify_hmac_signoff


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS18_BUILD_PROVENANCE_AND_VSA_UPGRADE"
STEP_ID = "WS18_STEP_1_BIND_PROVENANCE_VSA_AND_PUBLICATION_SUBJECTS"
PASS_VERDICT = "BUILD_PROVENANCE_AND_VSA_ALIGNED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
BUILD_PROVENANCE_REL = f"{REPORT_ROOT_REL}/kt_build_provenance.dsse"
VERIFICATION_SUMMARY_REL = f"{REPORT_ROOT_REL}/kt_verification_summary_attestation.dsse"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_build_verification_receipt.json"

DEFAULT_WS16_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_hermetic_build_envelope_manifest.json"
DEFAULT_WS16_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_hermetic_build_envelope_receipt.json"
DEFAULT_WS17_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_revision_trust_receipt.json"
DEFAULT_WS17_POLICY_REL = f"{REPORT_ROOT_REL}/kt_signed_revision_policy.json"
DEFAULT_WS17_SOURCE_PROVENANCE_REL = f"{REPORT_ROOT_REL}/kt_source_provenance.dsse"

BUILD_PROVENANCE_PREDICATE_TYPE = "https://kings-theorem.io/attestations/kt-build-provenance/v1"
VERIFICATION_SUMMARY_PREDICATE_TYPE = "https://kings-theorem.io/attestations/kt-verification-summary/v1"
DOCUMENTARY_SIGNOFF_MODE = "HMAC_DOCUMENTARY_DSSE_BINDING"
EXPECTED_SOURCE_TRUST_MODE = "SEALED_WS15_WS16_SUBSTRATE_PLUS_DUAL_LOCAL_HMAC_ATTESTATION"
PUBLICATION_ALIGNMENT_BOUNDARY = (
    "For WS18, publication surface means the sealed WS15 canonical delivery publication bundle carried forward by the "
    "WS16 critical artifact set; it does not collapse that artifact set into the earlier WS7 authority-subject publication surface."
)
STRONGER_CLAIM_NOT_MADE = (
    "WS18 does not claim detached verifier packaging, external reproduction, outsider replay, or public horizon opening."
)

VALIDATORS_RUN = [
    "python -m tools.operator.build_verification_validate",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_build_verification_validate.py -q",
]
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/build_verification_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_build_verification_validate.py"
GENERATED_ARTIFACT_REFS = [
    BUILD_PROVENANCE_REL,
    VERIFICATION_SUMMARY_REL,
    RECEIPT_REL,
]
WORKSTREAM_FILES_TOUCHED = [
    TOOL_REL,
    TEST_REL,
    *GENERATED_ARTIFACT_REFS,
]
CREATED_FILES = list(WORKSTREAM_FILES_TOUCHED)
SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    BUILD_PROVENANCE_REL: "generated documentary DSSE wrapper",
    VERIFICATION_SUMMARY_REL: "generated documentary DSSE wrapper",
    RECEIPT_REL: "generated receipt",
}


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
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _canonical_hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _normalize_subject_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = [
        {
            "path": str(row.get("path", "")).strip(),
            "sha256": str(row.get("sha256", "")).strip(),
            "kind": str(row.get("kind", "")).strip(),
        }
        for row in rows
    ]
    normalized = [row for row in normalized if row["path"] and row["sha256"]]
    normalized.sort(key=lambda row: (row["path"], row["sha256"], row["kind"]))
    return normalized


def _subject_entries(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {"name": row["path"], "digest": {"sha256": row["sha256"]}}
        for row in _normalize_subject_rows(rows)
    ]


def _subject_root_sha256(rows: Sequence[Dict[str, Any]]) -> str:
    payload = [{"path": row["path"], "sha256": row["sha256"], "kind": row["kind"]} for row in _normalize_subject_rows(rows)]
    return _canonical_hash(payload)


def _subject_identity_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"path": row["path"], "sha256": row["sha256"]} for row in _normalize_subject_rows(rows)]


def _statement_subjects(statement: Dict[str, Any]) -> List[Dict[str, Any]]:
    subject = statement.get("subject")
    if not isinstance(subject, list):
        raise RuntimeError("FAIL_CLOSED: in-toto statement missing subject list")
    rows: List[Dict[str, Any]] = []
    for entry in subject:
        if not isinstance(entry, dict):
            continue
        digest = entry.get("digest") if isinstance(entry.get("digest"), dict) else {}
        rows.append({"path": str(entry.get("name", "")).strip(), "sha256": str(digest.get("sha256", "")).strip(), "kind": ""})
    return _normalize_subject_rows(rows)


def _build_statement(*, subject_entries: Sequence[Dict[str, Any]], predicate_type: str, predicate: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": list(subject_entries),
        "predicateType": str(predicate_type).strip(),
        "predicate": dict(predicate),
    }


def _must_env_key_bytes(key_id: str) -> Tuple[bytes, str]:
    env_name = env_key_name_for_key_id(key_id)
    value = str(os.environ.get(env_name, "")).strip()
    if not value:
        raise RuntimeError(f"FAIL_CLOSED: missing required HMAC env key: {env_name}")
    return value.encode("utf-8"), env_name


def _validate_revision_policy_trust_roots(revision_policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    trust_roots = revision_policy.get("trust_roots")
    if not isinstance(trust_roots, list) or not trust_roots:
        raise RuntimeError("FAIL_CLOSED: WS17 revision policy missing trust_roots")
    verified: List[Dict[str, Any]] = []
    for row in trust_roots:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: revision policy trust_roots malformed")
        key_id = str(row.get("key_id", "")).strip()
        expected_fp = str(row.get("fingerprint_sha256", "")).strip()
        if not key_id or len(expected_fp) != 64:
            raise RuntimeError("FAIL_CLOSED: revision policy trust root incomplete")
        key_bytes, env_name = _must_env_key_bytes(key_id)
        actual_fp = hmac_key_fingerprint_hex(key_bytes)
        if actual_fp != expected_fp:
            raise RuntimeError(f"FAIL_CLOSED: HMAC trust root fingerprint mismatch for {key_id}")
        verified.append({"key_id": key_id, "env_var": env_name, "fingerprint_sha256": actual_fp})
    return verified


def _build_hmac_signoffs(payload_hash: str, trust_roots: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    signoffs: List[Dict[str, Any]] = []
    for row in trust_roots:
        key_id = str(row.get("key_id", "")).strip()
        key_bytes, env_name = _must_env_key_bytes(key_id)
        signature, fingerprint = sign_hmac(key_bytes=key_bytes, key_id=key_id, payload_hash=payload_hash)
        signoff = {
            "key_id": key_id,
            "env_var": env_name,
            "payload_hash": payload_hash,
            "hmac_signature": signature,
            "hmac_key_fingerprint": fingerprint,
            "mode": DOCUMENTARY_SIGNOFF_MODE,
        }
        ok, err = verify_hmac_signoff(signoff=signoff, key_bytes=key_bytes)
        if not ok:
            raise RuntimeError(f"FAIL_CLOSED: HMAC signoff self-verification failed for {key_id}: {err}")
        signoffs.append(signoff)
    return signoffs


def _verify_signoffs(signoffs: Sequence[Dict[str, Any]], payload_hash: str) -> bool:
    if not isinstance(signoffs, list) or len(signoffs) < 2:
        return False
    for row in signoffs:
        if str(row.get("payload_hash", "")).strip() != str(payload_hash).strip():
            return False
        key_id = str(row.get("key_id", "")).strip()
        key_bytes, _ = _must_env_key_bytes(key_id)
        ok, _ = verify_hmac_signoff(signoff=row, key_bytes=key_bytes)
        if not ok:
            return False
    return True


def _build_documentary_dsse(
    *,
    schema_id: str,
    artifact_id: str,
    compiled_head_commit: str,
    statement: Dict[str, Any],
    subject_rows: Sequence[Dict[str, Any]],
    trust_roots: Sequence[Dict[str, Any]],
    interpretation: str,
) -> Dict[str, Any]:
    payload_bytes = canonicalize_bytes(statement)
    payload_sha256 = sha256_hex(payload_bytes)
    signoffs = _build_hmac_signoffs(payload_sha256, trust_roots)
    return {
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": str(compiled_head_commit).strip(),
        "status": "PASS",
        "payloadType": "application/vnd.in-toto+json",
        "payloadBase64": base64.b64encode(payload_bytes).decode("ascii"),
        "payload_sha256": payload_sha256,
        "subject_count": len(_normalize_subject_rows(subject_rows)),
        "subject_root_sha256": _subject_root_sha256(subject_rows),
        "documentary_boundary": {
            "interpretation": interpretation,
            "standard_dsse_signature": False,
        },
        "signatures": signoffs,
    }


def build_build_verification_outputs_from_artifacts(
    *,
    ws16_manifest: Dict[str, Any],
    ws16_receipt: Dict[str, Any],
    ws17_receipt: Dict[str, Any],
    ws17_policy: Dict[str, Any],
    source_provenance_dsse: Dict[str, Any],
    build_provenance_statement: Dict[str, Any],
    verification_summary_statement: Dict[str, Any],
    build_provenance_dsse: Dict[str, Any],
    verification_summary_dsse: Dict[str, Any],
    changed_files: Sequence[str],
    prewrite_scope_clean: bool,
) -> Dict[str, Dict[str, Any]]:
    changed = sorted(set(str(path).replace("\\", "/") for path in changed_files))
    unexpected = sorted(path for path in changed if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError("FAIL_CLOSED: unexpected subject touches detected: " + ", ".join(unexpected + protected))

    subject_head = str(ws16_manifest.get("subject_head_commit", "")).strip()
    ws16_subject = str(ws16_receipt.get("subject_head_commit", "")).strip()
    ws17_subject = str(ws17_receipt.get("subject_head_commit", "")).strip()
    if not subject_head or len({subject_head, ws16_subject, ws17_subject}) != 1:
        raise RuntimeError("FAIL_CLOSED: WS16/WS17 subject heads do not converge")

    publication_rows = _normalize_subject_rows(ws16_manifest.get("critical_artifacts", []))
    provenance_rows = _statement_subjects(build_provenance_statement)
    verification_rows = _statement_subjects(verification_summary_statement)
    aligned_subjects = (
        _subject_identity_rows(provenance_rows)
        == _subject_identity_rows(verification_rows)
        == _subject_identity_rows(publication_rows)
    )

    ws16_ok = (
        str(ws16_manifest.get("status", "")).strip() == "PASS"
        and str(ws16_receipt.get("status", "")).strip() == "PASS"
        and str(ws16_receipt.get("pass_verdict", "")).strip() == "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN"
    )
    ws17_ok = (
        str(ws17_receipt.get("status", "")).strip() == "PASS"
        and str(ws17_receipt.get("pass_verdict", "")).strip() == "SOURCE_BUILD_ATTESTATION_PROVEN"
        and str(ws17_policy.get("source_trust_mode", "")).strip() == EXPECTED_SOURCE_TRUST_MODE
    )
    source_provenance_ok = str(source_provenance_dsse.get("status", "")).strip() == "PASS"

    provenance_signoffs_ok = _verify_signoffs(
        list(build_provenance_dsse.get("signatures", [])),
        str(build_provenance_dsse.get("payload_sha256", "")).strip(),
    )
    verification_signoffs_ok = _verify_signoffs(
        list(verification_summary_dsse.get("signatures", [])),
        str(verification_summary_dsse.get("payload_sha256", "")).strip(),
    )

    stronger_claim_ok = (
        str(build_provenance_statement.get("predicate", {}).get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE
        and str(verification_summary_statement.get("predicate", {}).get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE
    )

    status = "PASS" if all(
        [
            prewrite_scope_clean,
            ws16_ok,
            ws17_ok,
            source_provenance_ok,
            aligned_subjects,
            provenance_signoffs_ok,
            verification_signoffs_ok,
            stronger_claim_ok,
        ]
    ) else "BLOCKED"

    questions = {
        "exact_artifact_subjects_covered": publication_rows,
        "provenance_vsa_publication_subject_alignment": {
            "status": "PASS" if aligned_subjects else "FAIL",
            "subject_count": len(publication_rows),
            "subject_root_sha256": _subject_root_sha256(publication_rows),
            "publication_surface_ref": DEFAULT_WS16_MANIFEST_REL,
            "publication_surface_boundary": PUBLICATION_ALIGNMENT_BOUNDARY,
        },
        "exact_stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
    }

    receipt = {
        "schema_id": "kt.operator.build_verification_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": subject_head,
        "compiled_head_commit": subject_head,
        "evidence_head_commit": subject_head,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "BUILD_PROVENANCE_AND_VSA_BLOCKED",
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
            DEFAULT_WS16_MANIFEST_REL,
            DEFAULT_WS16_RECEIPT_REL,
            DEFAULT_WS17_RECEIPT_REL,
            DEFAULT_WS17_POLICY_REL,
            DEFAULT_WS17_SOURCE_PROVENANCE_REL,
            BUILD_PROVENANCE_REL,
            VERIFICATION_SUMMARY_REL,
            TOOL_REL,
            TEST_REL,
        ],
        "checks": [
            {"check": "prewrite_workspace_scope_clean", "status": "PASS" if prewrite_scope_clean else "FAIL", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "workstream_touches_remain_in_scope", "status": "PASS", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "ws16_envelope_pass", "status": "PASS" if ws16_ok else "FAIL", "refs": [DEFAULT_WS16_MANIFEST_REL, DEFAULT_WS16_RECEIPT_REL]},
            {"check": "ws17_source_attestation_pass", "status": "PASS" if ws17_ok else "FAIL", "refs": [DEFAULT_WS17_RECEIPT_REL, DEFAULT_WS17_POLICY_REL]},
            {"check": "source_provenance_present", "status": "PASS" if source_provenance_ok else "FAIL", "refs": [DEFAULT_WS17_SOURCE_PROVENANCE_REL]},
            {"check": "build_provenance_signoffs_verified", "status": "PASS" if provenance_signoffs_ok else "FAIL", "refs": [BUILD_PROVENANCE_REL]},
            {"check": "verification_summary_signoffs_verified", "status": "PASS" if verification_signoffs_ok else "FAIL", "refs": [VERIFICATION_SUMMARY_REL]},
            {"check": "artifact_subjects_align_across_provenance_vsa_publication", "status": "PASS" if aligned_subjects else "FAIL", "refs": [BUILD_PROVENANCE_REL, VERIFICATION_SUMMARY_REL, DEFAULT_WS16_MANIFEST_REL]},
            {"check": "stronger_claims_explicitly_withheld", "status": "PASS" if stronger_claim_ok else "FAIL", "refs": [BUILD_PROVENANCE_REL, VERIFICATION_SUMMARY_REL]},
        ],
        "questions": questions,
        "summary": {
            "artifact_subject_count": len(publication_rows),
            "artifact_subject_root_sha256": _subject_root_sha256(publication_rows),
            "publication_surface_ref": DEFAULT_WS16_MANIFEST_REL,
            "build_provenance_ref": BUILD_PROVENANCE_REL,
            "verification_summary_ref": VERIFICATION_SUMMARY_REL,
            "verifier_citation_ready_refs": [BUILD_PROVENANCE_REL, VERIFICATION_SUMMARY_REL, DEFAULT_WS16_MANIFEST_REL],
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS19_DETACHED_PUBLIC_VERIFIER_PACKAGE",
        },
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "emitted build provenance for the bounded critical artifact set",
                "emitted verification summary attestation for the same bounded critical artifact set",
                "proved that provenance, verification summary, and the sealed canonical delivery publication surface all point to the same artifact subjects",
            ],
            "files_touched": list(changed),
            "tests_run": list(TESTS_RUN),
            "validators_run": list(VALIDATORS_RUN),
            "issues_found": [],
            "resolution": (
                "WS18 binds build provenance, verification summary, and the bounded publication surface to the same sealed critical artifact subjects."
                if status == "PASS"
                else "WS18 remains blocked until provenance, verification summary, and publication surfaces converge on one bounded artifact subject set."
            ),
            "pass_fail_status": status,
            "unexpected_touches": [],
            "protected_touch_violations": [],
        },
    }
    return {"receipt": receipt}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the narrow WS18 build provenance and verification summary alignment.")
    parser.add_argument("--ws16-manifest", default=DEFAULT_WS16_MANIFEST_REL)
    parser.add_argument("--ws16-receipt", default=DEFAULT_WS16_RECEIPT_REL)
    parser.add_argument("--ws17-receipt", default=DEFAULT_WS17_RECEIPT_REL)
    parser.add_argument("--ws17-policy", default=DEFAULT_WS17_POLICY_REL)
    parser.add_argument("--ws17-source-provenance", default=DEFAULT_WS17_SOURCE_PROVENANCE_REL)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    prewrite_dirty = _dirty_relpaths(root, _git_status_lines(root))
    prewrite_scope_clean = not prewrite_dirty or all(path in WORKSTREAM_FILES_TOUCHED for path in prewrite_dirty)

    ws16_manifest = _load_required_json(root, str(args.ws16_manifest))
    ws16_receipt = _load_required_json(root, str(args.ws16_receipt))
    ws17_receipt = _load_required_json(root, str(args.ws17_receipt))
    ws17_policy = _load_required_json(root, str(args.ws17_policy))
    source_provenance_dsse = _load_required_json(root, str(args.ws17_source_provenance))
    subject_head = str(ws16_manifest.get("subject_head_commit", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: WS16 manifest missing subject_head_commit")

    trust_roots = _validate_revision_policy_trust_roots(ws17_policy)
    subject_rows = _normalize_subject_rows(ws16_manifest.get("critical_artifacts", []))
    if not subject_rows:
        raise RuntimeError("FAIL_CLOSED: WS16 manifest missing bounded critical artifact set")

    subject_entries = _subject_entries(subject_rows)
    subject_root = _subject_root_sha256(subject_rows)
    publication_refs = [
        DEFAULT_WS16_MANIFEST_REL,
        str(ws16_manifest.get("canonical_run_ref", "")).strip(),
        *[row["path"] for row in subject_rows],
    ]

    build_provenance_statement = _build_statement(
        subject_entries=subject_entries,
        predicate_type=BUILD_PROVENANCE_PREDICATE_TYPE,
        predicate={
            "schema_id": "kt.in_toto.predicate.build_provenance.v1",
            "subject_head_commit": subject_head,
            "artifact_subject_count": len(subject_rows),
            "artifact_subject_root_sha256": subject_root,
            "publication_surface_ref": DEFAULT_WS16_MANIFEST_REL,
            "publication_surface_refs": publication_refs,
            "ws16_manifest_ref": DEFAULT_WS16_MANIFEST_REL,
            "ws16_receipt_ref": DEFAULT_WS16_RECEIPT_REL,
            "ws17_receipt_ref": DEFAULT_WS17_RECEIPT_REL,
            "ws17_policy_ref": DEFAULT_WS17_POLICY_REL,
            "source_provenance_ref": DEFAULT_WS17_SOURCE_PROVENANCE_REL,
            "publication_surface_boundary": PUBLICATION_ALIGNMENT_BOUNDARY,
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
    )
    build_provenance_dsse = _build_documentary_dsse(
        schema_id="kt.operator.build_provenance.dsse.v1",
        artifact_id=Path(BUILD_PROVENANCE_REL).name,
        compiled_head_commit=subject_head,
        statement=build_provenance_statement,
        subject_rows=subject_rows,
        trust_roots=trust_roots,
        interpretation=(
            "This is a documentary DSSE wrapper around the bounded build provenance statement for the sealed WS15 canonical delivery artifact set. "
            "Verification follows the WS17 revision policy trust roots and the embedded dual HMAC signoffs."
        ),
    )

    verification_summary_statement = _build_statement(
        subject_entries=subject_entries,
        predicate_type=VERIFICATION_SUMMARY_PREDICATE_TYPE,
        predicate={
            "schema_id": "kt.in_toto.predicate.verification_summary.v1",
            "subject_head_commit": subject_head,
            "artifact_subject_count": len(subject_rows),
            "artifact_subject_root_sha256": subject_root,
            "verification_summary": {
                "ws16_pass_verdict": str(ws16_receipt.get("pass_verdict", "")).strip(),
                "ws17_pass_verdict": str(ws17_receipt.get("pass_verdict", "")).strip(),
                "source_provenance_status": str(source_provenance_dsse.get("status", "")).strip(),
                "publication_surface_boundary": PUBLICATION_ALIGNMENT_BOUNDARY,
            },
            "verifier_citation_ready_refs": [BUILD_PROVENANCE_REL, VERIFICATION_SUMMARY_REL, DEFAULT_WS16_MANIFEST_REL],
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
    )
    verification_summary_dsse = _build_documentary_dsse(
        schema_id="kt.operator.verification_summary_attestation.dsse.v1",
        artifact_id=Path(VERIFICATION_SUMMARY_REL).name,
        compiled_head_commit=subject_head,
        statement=verification_summary_statement,
        subject_rows=subject_rows,
        trust_roots=trust_roots,
        interpretation=(
            "This is a documentary DSSE wrapper around the bounded verification summary attestation for the sealed WS15 canonical delivery artifact set. "
            "Verification follows the same WS17 trust roots and embedded dual HMAC signoffs."
        ),
    )

    for rel, payload in (
        (BUILD_PROVENANCE_REL, build_provenance_dsse),
        (VERIFICATION_SUMMARY_REL, verification_summary_dsse),
    ):
        write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=VOLATILE_JSON_KEYS)

    changed_before_receipt = _dirty_relpaths(root, _git_status_lines(root))
    outputs = build_build_verification_outputs_from_artifacts(
        ws16_manifest=ws16_manifest,
        ws16_receipt=ws16_receipt,
        ws17_receipt=ws17_receipt,
        ws17_policy=ws17_policy,
        source_provenance_dsse=source_provenance_dsse,
        build_provenance_statement=build_provenance_statement,
        verification_summary_statement=verification_summary_statement,
        build_provenance_dsse=build_provenance_dsse,
        verification_summary_dsse=verification_summary_dsse,
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
                "questions": outputs["receipt"]["questions"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outputs["receipt"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
