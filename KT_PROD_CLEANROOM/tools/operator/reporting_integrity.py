from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.authority_convergence_validate import (
    AUTHORITY_SUBJECT_REL,
    CRYPTO_PUBLICATION_RECEIPT_REL,
    DEFAULT_CURRENT_STATE_REF,
    DEFAULT_REPORT_ROOT_REL,
    DEFAULT_RUNTIME_AUDIT_REF,
    DOCUMENTARY_VALIDATION_REL,
    LEDGER_BRANCH,
    LEDGER_POINTER_REF,
    PUBLIC_VERIFIER_MANIFEST_REL,
    TRUTH_PUBLICATION_STABILIZATION_REL,
    _documentary_only,
    _head_from,
    _load_json,
    _status_from,
    _supporting_ref,
    build_authority_convergence_report,
)
from tools.operator.public_verifier import HEAD_VERDICT_CONTAINS, HEAD_VERDICT_SUBJECT, SUBJECT_VERDICT_PROVEN, build_public_verifier_report
from tools.operator.titanium_common import file_sha256, load_json, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import CURRENT_POINTER_REL, active_supporting_truth_surfaces, active_truth_source_ref, path_ref, load_json_ref


DEFAULT_REMOTE = "origin"
STATUS_PASS = "PASS"
STATUS_FAIL_CLOSED = "FAIL_CLOSED"
PROOF_CLASS_PUBLISHED_HEAD = "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@dataclass(frozen=True)
class RemoteBranchFact:
    remote: str
    branch: str
    reachable: bool
    published: bool
    head_sha: str
    raw: str
    error: str


def _ls_remote_head(*, root: Path, remote: str, branch: str) -> RemoteBranchFact:
    try:
        raw = _git(root, "ls-remote", "--heads", remote, branch)
    except Exception as exc:  # noqa: BLE001
        return RemoteBranchFact(remote=remote, branch=branch, reachable=False, published=False, head_sha="", raw="", error=str(exc))
    line = raw.strip().splitlines()[0].strip() if raw.strip() else ""
    head_sha = line.split()[0].strip() if line else ""
    return RemoteBranchFact(
        remote=remote,
        branch=branch,
        reachable=True,
        published=bool(head_sha),
        head_sha=head_sha,
        raw=raw,
        error="",
    )


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"FAIL_CLOSED: unable to determine git HEAD: {exc}") from exc


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def build_published_head_self_convergence_receipt(
    *,
    root: Path,
    remote_fact: RemoteBranchFact,
) -> Dict[str, Any]:
    active_source = active_truth_source_ref(root=root)
    supporting_surfaces = active_supporting_truth_surfaces(root=root)
    current_state_ref = _supporting_ref(supporting_surfaces, "current_state_receipt.json", DEFAULT_CURRENT_STATE_REF)
    runtime_audit_ref = _supporting_ref(supporting_surfaces, "runtime_closure_audit.json", DEFAULT_RUNTIME_AUDIT_REF)

    authority_subject = _load_json(root / AUTHORITY_SUBJECT_REL)
    documentary_validation = _load_json(root / DOCUMENTARY_VALIDATION_REL)
    stabilization = _load_json(root / TRUTH_PUBLICATION_STABILIZATION_REL)
    crypto_publication = _load_json(root / CRYPTO_PUBLICATION_RECEIPT_REL)
    verifier_manifest = _load_json(root / PUBLIC_VERIFIER_MANIFEST_REL)

    ledger_pointer = load_json_ref(root=root, ref=active_source)
    ledger_current_state = load_json_ref(root=root, ref=current_state_ref)
    ledger_runtime_audit = load_json_ref(root=root, ref=runtime_audit_ref)

    main_pointer = _load_json(root / CURRENT_POINTER_REL)
    main_current_state = _load_json(root / DEFAULT_REPORT_ROOT_REL / "current_state_receipt.json")
    main_runtime_audit = _load_json(root / DEFAULT_REPORT_ROOT_REL / "runtime_closure_audit.json")

    verifier_report = build_public_verifier_report(root=root, report_root_rel=DEFAULT_REPORT_ROOT_REL)
    current_head_commit = _git_head(root)
    truth_subject_commit = str(authority_subject.get("truth_subject_commit", "")).strip()
    head_equals_subject = bool(current_head_commit) and bool(truth_subject_commit) and current_head_commit == truth_subject_commit
    expected_head_claim_verdict = HEAD_VERDICT_SUBJECT if head_equals_subject else HEAD_VERDICT_CONTAINS

    blockers: List[str] = []
    if not remote_fact.published:
        blockers.append("LEDGER_BRANCH_NOT_PUBLISHED")
    if str(crypto_publication.get("status", "")).strip() != STATUS_PASS:
        blockers.append("CRYPTOGRAPHIC_PUBLICATION_NOT_PASS")
    if str(stabilization.get("status", "")).strip() != STATUS_PASS or not bool(stabilization.get("truth_publication_stabilized")):
        blockers.append("TRUTH_PUBLICATION_NOT_STABILIZED")
    if str(verifier_manifest.get("subject_verdict", "")).strip() != SUBJECT_VERDICT_PROVEN:
        blockers.append("PUBLIC_VERIFIER_SUBJECT_NOT_PROVEN")
    if str(verifier_manifest.get("truth_subject_commit", "")).strip() != truth_subject_commit:
        blockers.append("VERIFIER_SUBJECT_MISMATCH")
    if _head_from(ledger_pointer) != truth_subject_commit:
        blockers.append("LEDGER_POINTER_SUBJECT_MISMATCH")
    if _head_from(ledger_current_state) != truth_subject_commit:
        blockers.append("LEDGER_CURRENT_STATE_SUBJECT_MISMATCH")
    if _head_from(ledger_runtime_audit) != truth_subject_commit:
        blockers.append("LEDGER_RUNTIME_AUDIT_SUBJECT_MISMATCH")
    if str(documentary_validation.get("status", "")).strip() != STATUS_PASS:
        blockers.append("DOCUMENTARY_VALIDATION_NOT_PASS")
    if not _documentary_only(main_pointer):
        blockers.append("MAIN_POINTER_NOT_DOCUMENTARY")
    if not _documentary_only(main_current_state):
        blockers.append("MAIN_CURRENT_STATE_NOT_DOCUMENTARY")
    if not _documentary_only(main_runtime_audit):
        blockers.append("MAIN_RUNTIME_AUDIT_NOT_DOCUMENTARY")
    if str(verifier_report.get("head_claim_verdict", "")).strip() != expected_head_claim_verdict:
        blockers.append("CURRENT_HEAD_OVERREAD")

    status = STATUS_PASS if not blockers else STATUS_FAIL_CLOSED
    return {
        "schema_id": "kt.operator.published_head_self_convergence_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "proof_class": PROOF_CLASS_PUBLISHED_HEAD if not blockers else STATUS_FAIL_CLOSED,
        "validated_head_sha": truth_subject_commit,
        "truth_subject_commit": truth_subject_commit,
        "evidence_commit": str(verifier_manifest.get("evidence_commit", "")).strip(),
        "current_head_commit": current_head_commit,
        "head_equals_subject": head_equals_subject,
        "current_head_claim_verdict": str(verifier_report.get("head_claim_verdict", "")).strip(),
        "claim_boundary": (
            "This receipt proves published-head self-convergence for truth_subject_commit. "
            "If current_head_commit differs, current_head_commit may claim only that it contains evidence for the published subject."
        ),
        "published_head_authority_claimed": not blockers,
        "current_head_authority_claimed": head_equals_subject and not blockers,
        "ledger_branch": remote_fact.branch,
        "ledger_branch_published": bool(remote_fact.published),
        "ledger_branch_head_sha": str(remote_fact.head_sha).strip(),
        "ledger_remote": remote_fact.remote,
        "ledger_remote_reachable": bool(remote_fact.reachable),
        "ledger_remote_error": str(remote_fact.error).strip(),
        "main_live_truth_purged": bool(_documentary_only(main_pointer) and _documentary_only(main_current_state) and _documentary_only(main_runtime_audit)),
        "blockers": blockers,
        "observed": {
            "active_truth_source": active_source,
            "ledger_pointer_head": _head_from(ledger_pointer),
            "ledger_current_state_head": _head_from(ledger_current_state),
            "ledger_runtime_audit_head": _head_from(ledger_runtime_audit),
            "ledger_pointer_posture": _status_from(ledger_pointer, "posture_enum"),
            "ledger_current_state_posture": _status_from(ledger_current_state, "posture_state", "current_p0_state"),
            "ledger_runtime_audit_posture": _status_from(ledger_runtime_audit, "posture_state", "current_state"),
            "publication_receipt_status": str(crypto_publication.get("status", "")).strip(),
            "stabilization_status": str(stabilization.get("status", "")).strip(),
            "verifier_subject_verdict": str(verifier_manifest.get("subject_verdict", "")).strip(),
        },
    }


def _stable_subset_authority(payload: Dict[str, Any]) -> Dict[str, Any]:
    observed = payload.get("observed") if isinstance(payload.get("observed"), dict) else {}
    return {
        "status": str(payload.get("status", "")).strip(),
        "proof_class": str(payload.get("proof_class", "")).strip(),
        "published_head_authority_claimed": bool(payload.get("published_head_authority_claimed")),
        "current_head_authority_claimed": bool(payload.get("current_head_authority_claimed")),
        "h1_admissible": bool(payload.get("h1_admissible")),
        "failures": list(payload.get("failures", [])),
        "truth_subject_commit": str(observed.get("truth_subject_commit", "")).strip(),
        "evidence_commit": str(observed.get("evidence_commit", "")).strip(),
        "ledger_branch_published": bool(observed.get("ledger_branch_published")),
        "ledger_branch_head_sha": str(observed.get("ledger_branch_head_sha", "")).strip(),
        "ledger_pointer_head": str(observed.get("ledger_pointer_head", "")).strip(),
        "ledger_current_state_head": str(observed.get("ledger_current_state_head", "")).strip(),
        "ledger_runtime_audit_head": str(observed.get("ledger_runtime_audit_head", "")).strip(),
    }


def _stable_subset_published(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": str(payload.get("status", "")).strip(),
        "proof_class": str(payload.get("proof_class", "")).strip(),
        "validated_head_sha": str(payload.get("validated_head_sha", "")).strip(),
        "truth_subject_commit": str(payload.get("truth_subject_commit", "")).strip(),
        "evidence_commit": str(payload.get("evidence_commit", "")).strip(),
        "head_equals_subject": bool(payload.get("head_equals_subject")),
        "current_head_claim_verdict": str(payload.get("current_head_claim_verdict", "")).strip(),
        "published_head_authority_claimed": bool(payload.get("published_head_authority_claimed")),
        "current_head_authority_claimed": bool(payload.get("current_head_authority_claimed")),
        "ledger_branch_published": bool(payload.get("ledger_branch_published")),
        "ledger_branch_head_sha": str(payload.get("ledger_branch_head_sha", "")).strip(),
        "main_live_truth_purged": bool(payload.get("main_live_truth_purged")),
        "blockers": list(payload.get("blockers", [])),
    }


def _validate_reporting_state(
    *,
    expected_authority: Dict[str, Any],
    actual_authority: Dict[str, Any],
    expected_published: Dict[str, Any],
    actual_published: Dict[str, Any],
    remote_fact: RemoteBranchFact,
) -> Tuple[List[str], List[str]]:
    contradictions: List[str] = []
    stale: List[str] = []

    if _stable_subset_authority(expected_authority) != _stable_subset_authority(actual_authority):
        stale.append("authority_convergence_receipt_stale_or_mismatched")
    if _stable_subset_published(expected_published) != _stable_subset_published(actual_published):
        stale.append("published_head_self_convergence_receipt_stale_or_mismatched")

    actual_authority_observed = actual_authority.get("observed") if isinstance(actual_authority.get("observed"), dict) else {}
    if bool(actual_authority_observed.get("ledger_branch_published")) != bool(remote_fact.published):
        contradictions.append("authority_convergence_receipt_ledger_branch_published_mismatch")
    if bool(actual_published.get("ledger_branch_published")) != bool(remote_fact.published):
        contradictions.append("published_head_self_convergence_receipt_ledger_branch_published_mismatch")
    if str(actual_published.get("ledger_branch_head_sha", "")).strip() != str(remote_fact.head_sha).strip():
        contradictions.append("published_head_self_convergence_receipt_ledger_branch_head_sha_mismatch")

    return contradictions, stale


def verify_reporting_integrity(
    *,
    root: Path,
    remote: str = DEFAULT_REMOTE,
    ledger_branch: str = LEDGER_BRANCH,
    report_root_rel: str = DEFAULT_REPORT_ROOT_REL,
) -> Dict[str, Any]:
    reports_root = (root / report_root_rel).resolve()
    remote_fact = _ls_remote_head(root=root, remote=remote, branch=ledger_branch)

    authority_path = reports_root / "authority_convergence_receipt.json"
    published_head_path = reports_root / "published_head_self_convergence_receipt.json"
    actual_authority = _load_required(authority_path)
    actual_published = _load_required(published_head_path)

    expected_authority = build_authority_convergence_report(root=root)
    expected_published = build_published_head_self_convergence_receipt(root=root, remote_fact=remote_fact)

    contradictions, stale = _validate_reporting_state(
        expected_authority=expected_authority,
        actual_authority=actual_authority,
        expected_published=expected_published,
        actual_published=actual_published,
        remote_fact=remote_fact,
    )

    status = STATUS_PASS if not contradictions and not stale else STATUS_FAIL_CLOSED
    return {
        "schema_id": "kt.operator.reporting_integrity_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "current_git_head": _git_head(root),
        "ledger_remote": remote_fact.remote,
        "ledger_branch": remote_fact.branch,
        "ledger_remote_reachable": bool(remote_fact.reachable),
        "ledger_branch_published": bool(remote_fact.published),
        "ledger_branch_head_sha": str(remote_fact.head_sha).strip(),
        "contradictions": contradictions,
        "stale_findings": stale,
        "targets": {
            "authority_convergence_receipt": path_ref(root=root, path=authority_path),
            "published_head_self_convergence_receipt": path_ref(root=root, path=published_head_path),
        },
    }


def repair_reporting_integrity(
    *,
    root: Path,
    remote: str = DEFAULT_REMOTE,
    ledger_branch: str = LEDGER_BRANCH,
    report_root_rel: str = DEFAULT_REPORT_ROOT_REL,
    out_receipt_rel: str = f"{DEFAULT_REPORT_ROOT_REL}/reporting_integrity_repair_receipt.json",
) -> Dict[str, Any]:
    reports_root = (root / report_root_rel).resolve()
    remote_fact = _ls_remote_head(root=root, remote=remote, branch=ledger_branch)

    authority_path = reports_root / "authority_convergence_receipt.json"
    published_head_path = reports_root / "published_head_self_convergence_receipt.json"

    before: Dict[str, str] = {}
    for path in (authority_path, published_head_path):
        if path.exists():
            before[path_ref(root=root, path=path)] = file_sha256(path)

    authority_report = build_authority_convergence_report(root=root)
    published_report = build_published_head_self_convergence_receipt(root=root, remote_fact=remote_fact)
    write_json_stable(authority_path, authority_report)
    write_json_stable(published_head_path, published_report)

    after: Dict[str, str] = {}
    for path in (authority_path, published_head_path):
        if path.exists():
            after[path_ref(root=root, path=path)] = file_sha256(path)

    verification_after = verify_reporting_integrity(
        root=root,
        remote=remote,
        ledger_branch=ledger_branch,
        report_root_rel=report_root_rel,
    )
    ok = verification_after["status"] == STATUS_PASS

    repair_receipt = {
        "schema_id": "kt.operator.reporting_integrity_repair_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": STATUS_PASS if ok else "FAIL",
        "current_git_head": _git_head(root),
        "remote_fact": {
            "remote": remote_fact.remote,
            "branch": remote_fact.branch,
            "reachable": bool(remote_fact.reachable),
            "published": bool(remote_fact.published),
            "head_sha": str(remote_fact.head_sha).strip(),
            "error": str(remote_fact.error).strip(),
        },
        "touched": [
            {
                "path": path,
                "before_sha256": before.get(path, ""),
                "after_sha256": after.get(path, ""),
                "changed": bool(before.get(path, "") and after.get(path, "") and before.get(path, "") != after.get(path, "")),
            }
            for path in sorted(set(before) | set(after))
        ],
        "verification_after": verification_after,
        "semantic_ceiling": {
            "published_head_authority_claimed": published_report["published_head_authority_claimed"],
            "current_head_authority_claimed": published_report["current_head_authority_claimed"],
            "h1_allowed": False,
        },
    }
    out_path = (root / out_receipt_rel).resolve()
    write_json_stable(out_path, repair_receipt)
    return repair_receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Repair and verify WS9 subject/evidence-aware authority reporting.")
    ap.add_argument("--mode", choices=("verify", "repair"), default="verify")
    ap.add_argument("--remote", default=DEFAULT_REMOTE)
    ap.add_argument("--ledger-branch", default=LEDGER_BRANCH)
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--out-receipt", default=f"{DEFAULT_REPORT_ROOT_REL}/reporting_integrity_repair_receipt.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(__file__).resolve()
    while root != root.parent and not (root / "KT_PROD_CLEANROOM").exists():
        root = root.parent
    if not (root / "KT_PROD_CLEANROOM").exists():
        raise SystemExit("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM)")

    if str(args.mode).strip() == "repair":
        receipt = repair_reporting_integrity(
            root=root,
            remote=str(args.remote).strip(),
            ledger_branch=str(args.ledger_branch).strip(),
            report_root_rel=str(args.report_root).strip(),
            out_receipt_rel=str(args.out_receipt).strip(),
        )
        print(receipt["status"])
        return 0 if receipt["status"] == STATUS_PASS else 2

    receipt = verify_reporting_integrity(
        root=root,
        remote=str(args.remote).strip(),
        ledger_branch=str(args.ledger_branch).strip(),
        report_root_rel=str(args.report_root).strip(),
    )
    print(receipt["status"])
    return 0 if receipt["status"] == STATUS_PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
