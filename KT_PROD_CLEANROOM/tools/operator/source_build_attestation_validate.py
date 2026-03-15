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
from tools.operator.crypto_attestation import (
    load_authority_bundle_schema,
    mint_authority_bundle,
    mint_envelope,
    subject_sha256 as authority_subject_sha256,
    validate_authority_bundle,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_publication import build_in_toto_statement_for_authority_subject
from tools.verification.attestation_hmac import env_key_name_for_key_id, hmac_key_fingerprint_hex, sign_hmac, verify_hmac_signoff


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS17_SOURCE_BUILD_ATTESTATION"
STEP_ID = "WS17_STEP_1_BIND_TRUSTED_SOURCE_REVISION_TO_CRITICAL_ARTIFACT_SET"
PASS_VERDICT = "SOURCE_BUILD_ATTESTATION_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
REVISION_POLICY_REL = f"{REPORT_ROOT_REL}/kt_signed_revision_policy.json"
SOURCE_ATTEST_DIR_REL = f"{REPORT_ROOT_REL}/source_build_attestation"
AUTHORITY_SUBJECT_REL = f"{SOURCE_ATTEST_DIR_REL}/authority_subject.json"
IN_TOTO_STATEMENT_REL = f"{SOURCE_ATTEST_DIR_REL}/in_toto_statement.json"
AUTHORITY_BUNDLE_REL = f"{SOURCE_ATTEST_DIR_REL}/authority_bundle.json"
SOURCE_PROVENANCE_DSSE_REL = f"{REPORT_ROOT_REL}/kt_source_provenance.dsse"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_revision_trust_receipt.json"

DEFAULT_STATUS_REPORT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_status_seal_b4789a5/status_report.json"
DEFAULT_AUTHORITY_REPORT_REL = (
    "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_authority_grade_b4789a5/reports/authority_grade.json"
)
DEFAULT_WS16_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_hermetic_build_envelope_manifest.json"
DEFAULT_WS16_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_hermetic_build_envelope_receipt.json"

HMAC_KEY_IDS = ("SIGNER_A", "SIGNER_B")
PREDICATE_TYPE = "https://kings-theorem.io/attestations/kt-source-build-subject/v1"
ATTESTATION_FORMAT = "kt.authority.bundle.v1 with dual local HMAC signoffs plus documentary DSSE-wrapped in-toto Statement v0.1"
STRONGER_CLAIM_NOT_MADE = (
    "WS17 does not claim detached verifier packaging, outsider replay, public horizon opening, "
    "or the WS18 build-provenance/VSA upgrade."
)
VALIDATORS_RUN = [
    "python -m tools.operator.source_build_attestation_validate",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_source_build_attestation_validate.py -q",
]
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/source_build_attestation_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_source_build_attestation_validate.py"
SUBJECT_TOUCH_REFS = [
    TOOL_REL,
    TEST_REL,
]
GENERATED_ARTIFACT_REFS = [
    REVISION_POLICY_REL,
    AUTHORITY_SUBJECT_REL,
    IN_TOTO_STATEMENT_REL,
    AUTHORITY_BUNDLE_REL,
    SOURCE_PROVENANCE_DSSE_REL,
    RECEIPT_REL,
]
CREATED_FILES = SUBJECT_TOUCH_REFS + GENERATED_ARTIFACT_REFS
WORKSTREAM_FILES_TOUCHED = SUBJECT_TOUCH_REFS + GENERATED_ARTIFACT_REFS
SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    REVISION_POLICY_REL: "generated revision trust policy",
    AUTHORITY_SUBJECT_REL: "generated attestation subject",
    IN_TOTO_STATEMENT_REL: "generated in-toto statement",
    AUTHORITY_BUNDLE_REL: "generated authority bundle",
    SOURCE_PROVENANCE_DSSE_REL: "generated documentary DSSE wrapper",
    RECEIPT_REL: "generated receipt",
}
TRUST_PATH_REFS = [
    REVISION_POLICY_REL,
    "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
    "KT_PROD_CLEANROOM/governance/authority_bundle.schema.json",
    "KT_PROD_CLEANROOM/governance/supply_chain_layout.json",
    DEFAULT_WS16_MANIFEST_REL,
    DEFAULT_WS16_RECEIPT_REL,
    AUTHORITY_SUBJECT_REL,
    IN_TOTO_STATEMENT_REL,
    AUTHORITY_BUNDLE_REL,
    SOURCE_PROVENANCE_DSSE_REL,
]


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
        if rel:
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


def _canonical_json_sha256(root: Path, rel: str) -> str:
    return _canonical_hash(_load_required_json(root, rel))


def _must_env_key_bytes(key_id: str) -> Tuple[bytes, str]:
    env_name = env_key_name_for_key_id(key_id)
    value = str(os.environ.get(env_name, "")).strip()
    if not value:
        raise RuntimeError(f"FAIL_CLOSED: missing required HMAC env key: {env_name}")
    return value.encode("utf-8"), env_name


def build_revision_policy_payload(
    *,
    subject_head_commit: str,
    trust_roots: Sequence[Dict[str, Any]],
    ws16_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.signed_revision_policy.v1",
        "artifact_id": Path(REVISION_POLICY_REL).name,
        "generated_utc": utc_now_iso_z(),
        "attested_source_revision": str(subject_head_commit).strip(),
        "evaluated_revision_ref": f"git:{str(subject_head_commit).strip()}",
        "policy_status": "POLICY_EXEMPT_WITH_JUSTIFICATION",
        "git_commit_signature_required": False,
        "git_tag_signature_required": False,
        "source_trust_mode": "SEALED_WS15_WS16_SUBSTRATE_PLUS_DUAL_LOCAL_HMAC_ATTESTATION",
        "policy_exemption": {
            "reason": (
                "WS17 binds the sealed WS15/WS16 subject revision to the bounded critical artifact set with dual local HMAC "
                "authority-bundle signoffs; git commit/tag signing is not being claimed in this workstream."
            ),
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "critical_artifact_count": int(ws16_manifest.get("critical_artifact_count", 0)),
        "critical_artifact_root_sha256": str(ws16_manifest.get("critical_artifact_root_sha256", "")).strip(),
        "critical_artifact_subjects": list(ws16_manifest.get("critical_artifacts", [])),
        "sealed_substrate_refs": [
            DEFAULT_STATUS_REPORT_REL,
            DEFAULT_AUTHORITY_REPORT_REL,
            DEFAULT_WS16_MANIFEST_REL,
            DEFAULT_WS16_RECEIPT_REL,
        ],
        "trust_roots": list(trust_roots),
    }


def build_source_build_authority_subject(
    *,
    root: Path,
    status_report: Dict[str, Any],
    authority_report: Dict[str, Any],
    ws16_manifest: Dict[str, Any],
    ws16_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    subject_head_commit = str(ws16_manifest.get("subject_head_commit", "")).strip()
    law_paths = [
        "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
        "KT_PROD_CLEANROOM/governance/authority_bundle.schema.json",
        "KT_PROD_CLEANROOM/governance/supply_chain_layout.json",
        REVISION_POLICY_REL,
    ]
    law_surface_hashes = {rel: _canonical_json_sha256(root, rel) for rel in law_paths}

    evidence = [
        {
            "name": "ws15_status_report",
            "ref": DEFAULT_STATUS_REPORT_REL,
            "sha256": _canonical_hash(status_report),
        },
        {
            "name": "ws15_authority_grade_report",
            "ref": DEFAULT_AUTHORITY_REPORT_REL,
            "sha256": _canonical_hash(authority_report),
        },
        {
            "name": "ws16_hermetic_build_envelope_manifest",
            "ref": DEFAULT_WS16_MANIFEST_REL,
            "sha256": _canonical_hash(ws16_manifest),
        },
        {
            "name": "ws16_hermetic_build_envelope_receipt",
            "ref": DEFAULT_WS16_RECEIPT_REL,
            "sha256": _canonical_hash(ws16_receipt),
        },
    ]
    for index, artifact in enumerate(list(ws16_manifest.get("critical_artifacts", [])), start=1):
        evidence.append(
            {
                "name": f"critical_artifact_{index}_{str(artifact.get('kind', 'artifact')).strip()}",
                "ref": str(artifact.get("path", "")).strip(),
                "sha256": str(artifact.get("sha256", "")).strip(),
            }
        )

    return {
        "schema_id": "kt.authority.subject.v1",
        "truth_subject_commit": subject_head_commit,
        "truth_produced_at_commit": subject_head_commit,
        "law_surface_hashes": law_surface_hashes,
        "supersedes_subject_sha256": "",
        "evidence": evidence,
    }


def build_source_provenance_dsse_payload(
    *,
    subject_head_commit: str,
    statement: Dict[str, Any],
    subject_sha256_hex: str,
    signoffs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    payload_bytes = canonicalize_bytes(statement)
    payload_sha256 = sha256_hex(payload_bytes)
    return {
        "schema_id": "kt.operator.source_provenance.dsse.v1",
        "artifact_id": Path(SOURCE_PROVENANCE_DSSE_REL).name,
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": str(subject_head_commit).strip(),
        "status": "PASS",
        "payloadType": "application/vnd.in-toto+json",
        "payloadBase64": base64.b64encode(payload_bytes).decode("ascii"),
        "payload_sha256": payload_sha256,
        "subject_sha256": str(subject_sha256_hex).strip(),
        "authority_subject_ref": AUTHORITY_SUBJECT_REL,
        "in_toto_statement_ref": IN_TOTO_STATEMENT_REL,
        "authority_bundle_ref": AUTHORITY_BUNDLE_REL,
        "documentary_boundary": {
            "interpretation": (
                "This is a documentary DSSE wrapper around a dual-local-HMAC authority-bundle attestation for the sealed "
                "WS15/WS16 subject. Verification must follow the authority bundle, the revision trust receipt, and the "
                "bounded trust path recorded there."
            ),
            "standard_dsse_signature": False,
        },
        "signatures": [
            {
                "keyid": str(row.get("key_id", "")).strip(),
                "mode": "HMAC_AUTHORITY_BUNDLE_BINDING",
                "payload_hash": str(row.get("payload_hash", "")).strip(),
                "hmac_key_fingerprint": str(row.get("hmac_key_fingerprint", "")).strip(),
                "verified": True,
            }
            for row in signoffs
        ],
    }


def _build_trust_roots() -> List[Dict[str, Any]]:
    roots: List[Dict[str, Any]] = []
    for key_id in HMAC_KEY_IDS:
        key_bytes, env_name = _must_env_key_bytes(key_id)
        roots.append(
            {
                "key_id": key_id,
                "env_var": env_name,
                "fingerprint_sha256": hmac_key_fingerprint_hex(key_bytes),
            }
        )
    return roots


def _build_dual_hmac_signoffs(subject_sha256_hex: str) -> List[Dict[str, Any]]:
    signoffs: List[Dict[str, Any]] = []
    payload_hash = str(subject_sha256_hex).strip()
    for key_id in HMAC_KEY_IDS:
        key_bytes, env_name = _must_env_key_bytes(key_id)
        signature, fingerprint = sign_hmac(key_bytes=key_bytes, key_id=key_id, payload_hash=payload_hash)
        signoff = {
            "key_id": key_id,
            "env_var": env_name,
            "payload_hash": payload_hash,
            "hmac_signature": signature,
            "hmac_key_fingerprint": fingerprint,
        }
        ok, err = verify_hmac_signoff(signoff=signoff, key_bytes=key_bytes)
        if not ok:
            raise RuntimeError(f"FAIL_CLOSED: HMAC signoff self-verification failed for {key_id}: {err}")
        signoffs.append(signoff)
    return signoffs


def build_source_build_outputs_from_artifacts(
    *,
    status_report: Dict[str, Any],
    authority_report: Dict[str, Any],
    ws16_manifest: Dict[str, Any],
    ws16_receipt: Dict[str, Any],
    revision_policy: Dict[str, Any],
    authority_subject: Dict[str, Any],
    in_toto_statement: Dict[str, Any],
    authority_bundle: Dict[str, Any],
    source_provenance_dsse: Dict[str, Any],
    changed_files: Sequence[str],
    prewrite_scope_clean: bool,
) -> Dict[str, Dict[str, Any]]:
    changed = sorted(set(str(path).replace("\\", "/") for path in changed_files))
    unexpected = sorted(path for path in changed if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError("FAIL_CLOSED: unexpected subject touches detected: " + ", ".join(unexpected + protected))

    subject_head = str(ws16_manifest.get("subject_head_commit", "")).strip()
    status_head = str(status_report.get("head", "")).strip()
    authority_head = str(authority_report.get("head", "")).strip()
    ws16_manifest_evidence = str(ws16_manifest.get("evidence_head_commit", "")).strip()
    ws16_receipt_subject = str(ws16_receipt.get("subject_head_commit", "")).strip()
    ws16_receipt_evidence = str(ws16_receipt.get("evidence_head_commit", "")).strip()
    if not all([subject_head, status_head, authority_head, ws16_manifest_evidence, ws16_receipt_subject, ws16_receipt_evidence]):
        raise RuntimeError("FAIL_CLOSED: missing converged WS15/WS16 head anchors")
    if len({subject_head, status_head, authority_head, ws16_manifest_evidence, ws16_receipt_subject, ws16_receipt_evidence}) != 1:
        raise RuntimeError("FAIL_CLOSED: WS15/WS16 heads do not converge on one sealed subject revision")

    status_ok = str(status_report.get("status", "")).strip() == "PASS"
    authority_ok = (
        str(authority_report.get("status", "")).strip() == "PASS"
        and str(authority_report.get("grade", "")).strip() == "A"
        and not list(authority_report.get("blockers", []))
    )
    ws16_ok = (
        str(ws16_manifest.get("status", "")).strip() == "PASS"
        and str(ws16_receipt.get("status", "")).strip() == "PASS"
        and str(ws16_receipt.get("pass_verdict", "")).strip() == "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN"
    )

    subject_sha = authority_subject_sha256(authority_subject)
    if str(authority_bundle.get("subject_sha256", "")).strip() != subject_sha:
        raise RuntimeError("FAIL_CLOSED: authority bundle does not bind to computed authority subject hash")
    schema = load_authority_bundle_schema(root=repo_root())
    validate_authority_bundle(authority_bundle, schema=schema)

    envelope = authority_bundle.get("envelope") if isinstance(authority_bundle.get("envelope"), dict) else {}
    signoffs = list(envelope.get("signatures", [])) if isinstance(envelope.get("signatures"), list) else []
    signoff_ok = len(signoffs) == len(HMAC_KEY_IDS)
    for signoff in signoffs:
        key_bytes, _ = _must_env_key_bytes(str(signoff.get("key_id", "")).strip())
        ok, err = verify_hmac_signoff(signoff=signoff, key_bytes=key_bytes)
        if not ok:
            raise RuntimeError(f"FAIL_CLOSED: authority bundle HMAC verification failed: {err}")

    artifact_subjects = list(ws16_manifest.get("critical_artifacts", []))
    artifact_ok = len(artifact_subjects) == int(ws16_manifest.get("critical_artifact_count", 0)) and bool(
        str(ws16_manifest.get("critical_artifact_root_sha256", "")).strip()
    )
    stronger_claim_ok = (
        str(revision_policy.get("policy_exemption", {}).get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE
        and bool(source_provenance_dsse.get("documentary_boundary"))
        and source_provenance_dsse["documentary_boundary"].get("standard_dsse_signature") is False
        and str(in_toto_statement.get("predicate", {}).get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE
    )

    status = "PASS" if all([prewrite_scope_clean, status_ok, authority_ok, ws16_ok, signoff_ok, artifact_ok, stronger_claim_ok]) else "BLOCKED"
    questions = {
        "exact_source_revision": subject_head,
        "exact_artifact_subjects_covered": artifact_subjects,
        "exact_attestation_format_and_trust_path": {
            "attestation_format": ATTESTATION_FORMAT,
            "authority_subject_ref": AUTHORITY_SUBJECT_REL,
            "in_toto_statement_ref": IN_TOTO_STATEMENT_REL,
            "authority_bundle_ref": AUTHORITY_BUNDLE_REL,
            "source_provenance_dsse_ref": SOURCE_PROVENANCE_DSSE_REL,
            "trust_path_refs": list(TRUST_PATH_REFS),
        },
        "exact_stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
    }
    receipt = {
        "schema_id": "kt.operator.revision_trust_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": subject_head,
        "compiled_head_commit": subject_head,
        "evidence_head_commit": subject_head,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "SOURCE_BUILD_ATTESTATION_BLOCKED",
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
            DEFAULT_STATUS_REPORT_REL,
            DEFAULT_AUTHORITY_REPORT_REL,
            DEFAULT_WS16_MANIFEST_REL,
            DEFAULT_WS16_RECEIPT_REL,
            *GENERATED_ARTIFACT_REFS[:-1],
            *SUBJECT_TOUCH_REFS,
        ],
        "checks": [
            {"check": "prewrite_workspace_scope_clean", "status": "PASS" if prewrite_scope_clean else "FAIL", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "workstream_touches_remain_in_scope", "status": "PASS", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "ws15_status_pass", "status": "PASS" if status_ok else "FAIL", "refs": [DEFAULT_STATUS_REPORT_REL]},
            {"check": "ws15_authority_grade_a", "status": "PASS" if authority_ok else "FAIL", "refs": [DEFAULT_AUTHORITY_REPORT_REL]},
            {"check": "ws16_envelope_pass", "status": "PASS" if ws16_ok else "FAIL", "refs": [DEFAULT_WS16_MANIFEST_REL, DEFAULT_WS16_RECEIPT_REL]},
            {"check": "source_revision_converges_with_sealed_substrate", "status": "PASS", "refs": [DEFAULT_STATUS_REPORT_REL, DEFAULT_WS16_MANIFEST_REL]},
            {"check": "dual_hmac_authority_bundle_signoffs_valid", "status": "PASS" if signoff_ok else "FAIL", "refs": [AUTHORITY_BUNDLE_REL]},
            {"check": "bounded_critical_artifact_set_covered", "status": "PASS" if artifact_ok else "FAIL", "refs": [DEFAULT_WS16_MANIFEST_REL]},
            {"check": "stronger_claims_explicitly_withheld", "status": "PASS" if stronger_claim_ok else "FAIL", "refs": [REVISION_POLICY_REL, SOURCE_PROVENANCE_DSSE_REL]},
        ],
        "questions": questions,
        "summary": {
            "attested_source_revision": subject_head,
            "critical_artifact_count": int(ws16_manifest.get("critical_artifact_count", 0)),
            "critical_artifact_root_sha256": str(ws16_manifest.get("critical_artifact_root_sha256", "")).strip(),
            "attestation_format": ATTESTATION_FORMAT,
            "trust_path_refs": list(TRUST_PATH_REFS),
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS18_BUILD_PROVENANCE_AND_VSA_UPGRADE",
        },
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "declared the exact sealed source revision trusted for the bounded critical artifact set",
                "minted a deterministic authority subject tied directly to the sealed WS15/WS16 substrate and the exact artifact subjects",
                "bound the subject with dual local HMAC signoffs and emitted a documentary in-toto wrapper without widening into detached verifier or public horizon claims",
            ],
            "files_touched": list(changed),
            "tests_run": list(TESTS_RUN),
            "validators_run": list(VALIDATORS_RUN),
            "issues_found": [],
            "resolution": (
                "WS17 proves only the trusted sealed source revision and bounded source/build attestation path for the critical artifact set."
                if status == "PASS"
                else "WS17 remains blocked until the sealed source revision, bounded artifact set, and dual-HMAC authority bundle converge cleanly."
            ),
            "pass_fail_status": status,
            "unexpected_touches": [],
            "protected_touch_violations": [],
        },
    }
    return {
        "receipt": receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the narrow WS17 source/build attestation and emit sealed reports.")
    parser.add_argument("--status-report", default=DEFAULT_STATUS_REPORT_REL)
    parser.add_argument("--authority-report", default=DEFAULT_AUTHORITY_REPORT_REL)
    parser.add_argument("--ws16-manifest", default=DEFAULT_WS16_MANIFEST_REL)
    parser.add_argument("--ws16-receipt", default=DEFAULT_WS16_RECEIPT_REL)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    prewrite_dirty = _dirty_relpaths(root, _git_status_lines(root))
    prewrite_scope_clean = not prewrite_dirty or all(path in WORKSTREAM_FILES_TOUCHED for path in prewrite_dirty)

    status_report = _load_required_json(root, str(args.status_report))
    authority_report = _load_required_json(root, str(args.authority_report))
    ws16_manifest = _load_required_json(root, str(args.ws16_manifest))
    ws16_receipt = _load_required_json(root, str(args.ws16_receipt))
    subject_head = str(ws16_manifest.get("subject_head_commit", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: WS16 manifest missing subject_head_commit")

    trust_roots = _build_trust_roots()
    revision_policy = build_revision_policy_payload(
        subject_head_commit=subject_head,
        trust_roots=trust_roots,
        ws16_manifest=ws16_manifest,
    )
    write_json_stable((root / Path(REVISION_POLICY_REL)).resolve(), revision_policy, volatile_keys=VOLATILE_JSON_KEYS)

    authority_subject = build_source_build_authority_subject(
        root=root,
        status_report=status_report,
        authority_report=authority_report,
        ws16_manifest=ws16_manifest,
        ws16_receipt=ws16_receipt,
    )
    subject_sha = authority_subject_sha256(authority_subject)
    signoffs = _build_dual_hmac_signoffs(subject_sha)
    envelope = mint_envelope(
        subject_sha256_hex=subject_sha,
        attestation_mode="HMAC_DUAL_LOCAL_SIGNOFF_V1",
        signatures=signoffs,
        transparency={"claimed": False, "mode": "NONE"},
    )
    authority_bundle = mint_authority_bundle(
        subject=authority_subject,
        envelope=envelope,
        bundle_id=f"KT_SOURCE_BUILD_ATTEST_{subject_head[:12]}_{subject_sha[:16]}",
    )
    validate_authority_bundle(authority_bundle, schema=load_authority_bundle_schema(root=root))

    in_toto_statement = build_in_toto_statement_for_authority_subject(
        subject_sha256_hex=subject_sha,
        subject_name=f"kt.source_build.subject.v1:{subject_sha}",
        predicate_type=PREDICATE_TYPE,
        predicate={
            "schema_id": "kt.in_toto.predicate.source_build_subject.v1",
            "attested_source_revision": subject_head,
            "critical_artifact_count": int(ws16_manifest.get("critical_artifact_count", 0)),
            "critical_artifact_root_sha256": str(ws16_manifest.get("critical_artifact_root_sha256", "")).strip(),
            "critical_artifact_subjects": list(ws16_manifest.get("critical_artifacts", [])),
            "revision_policy_ref": REVISION_POLICY_REL,
            "ws16_manifest_ref": DEFAULT_WS16_MANIFEST_REL,
            "ws16_receipt_ref": DEFAULT_WS16_RECEIPT_REL,
            "attestation_fabric_contract_ref": "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
            "authority_bundle_schema_ref": "KT_PROD_CLEANROOM/governance/authority_bundle.schema.json",
            "supply_chain_layout_ref": "KT_PROD_CLEANROOM/governance/supply_chain_layout.json",
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
    )
    source_provenance_dsse = build_source_provenance_dsse_payload(
        subject_head_commit=subject_head,
        statement=in_toto_statement,
        subject_sha256_hex=subject_sha,
        signoffs=signoffs,
    )

    for rel, payload in (
        (AUTHORITY_SUBJECT_REL, authority_subject),
        (IN_TOTO_STATEMENT_REL, in_toto_statement),
        (AUTHORITY_BUNDLE_REL, authority_bundle),
        (SOURCE_PROVENANCE_DSSE_REL, source_provenance_dsse),
    ):
        write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=VOLATILE_JSON_KEYS)

    changed_before_receipt = _dirty_relpaths(root, _git_status_lines(root))
    outputs = build_source_build_outputs_from_artifacts(
        status_report=status_report,
        authority_report=authority_report,
        ws16_manifest=ws16_manifest,
        ws16_receipt=ws16_receipt,
        revision_policy=revision_policy,
        authority_subject=authority_subject,
        in_toto_statement=in_toto_statement,
        authority_bundle=authority_bundle,
        source_provenance_dsse=source_provenance_dsse,
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
