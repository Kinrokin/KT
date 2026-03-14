from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.platform_governance_narrowing import build_platform_governance_claims
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
PUBLIC_VERIFIER_MANIFEST_REL = f"{DEFAULT_REPORT_ROOT_REL}/public_verifier_manifest.json"
CRYPTO_PUBLICATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json"
CRYPTO_PUBLICATION_SUBJECT_REL = "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json"

SUBJECT_VERDICT_PROVEN = "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED"
SUBJECT_VERDICT_UNPROVEN = "TRANSPARENCY_VERIFICATION_NOT_PROVEN"

HEAD_VERDICT_SUBJECT = "HEAD_IS_TRANSPARENCY_VERIFIED_SUBJECT"
HEAD_VERDICT_CONTAINS = "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE"
HEAD_VERDICT_UNPROVEN = "HEAD_TRANSPARENCY_CLAIM_UNPROVEN"

GOVERNANCE_HEAD_VERDICT_PLATFORM_SUBJECT = "HEAD_HAS_PLATFORM_ENFORCEMENT_PROOF"
GOVERNANCE_HEAD_VERDICT_PLATFORM_CONTAINS = "HEAD_CONTAINS_PLATFORM_ENFORCEMENT_EVIDENCE_FOR_SUBJECT"
GOVERNANCE_HEAD_VERDICT_WORKFLOW_SUBJECT = "HEAD_HAS_WORKFLOW_GOVERNANCE_ONLY_EVIDENCE"
GOVERNANCE_HEAD_VERDICT_WORKFLOW_CONTAINS = "HEAD_CONTAINS_WORKFLOW_GOVERNANCE_ONLY_EVIDENCE_FOR_SUBJECT"
GOVERNANCE_HEAD_VERDICT_UNPROVEN = "HEAD_PLATFORM_GOVERNANCE_CLAIM_UNPROVEN"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def build_public_verifier_claims(*, root: Path, live_head: str, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    receipt_ref = CRYPTO_PUBLICATION_RECEIPT_REL
    subject_ref = CRYPTO_PUBLICATION_SUBJECT_REL
    receipt_path = (root / Path(receipt_ref)).resolve()
    subject_path = (root / Path(subject_ref)).resolve()

    publication_receipt_status = "MISSING"
    evidence_commit = ""
    truth_subject_commit = str(live_head).strip()
    subject_verdict = SUBJECT_VERDICT_UNPROVEN
    evidence_contains_subject = False
    evidence_equals_subject = False
    claim_boundary = "No passing cryptographic publication receipt is present; do not claim that HEAD is transparency-verified."

    if receipt_path.exists():
        receipt = load_json(receipt_path)
        publication_receipt_status = str(receipt.get("status", "")).strip() or "UNKNOWN"
        evidence_commit = _git_last_commit_for_paths(root, (receipt_ref, subject_ref))

    if subject_path.exists():
        subject = load_json(subject_path)
        truth_subject_commit = str(subject.get("truth_subject_commit", "")).strip() or truth_subject_commit

    if publication_receipt_status == "PASS" and truth_subject_commit:
        subject_verdict = SUBJECT_VERDICT_PROVEN
        evidence_contains_subject = subject_path.exists()
        evidence_equals_subject = bool(evidence_commit) and evidence_commit == truth_subject_commit
        claim_boundary = (
            "evidence_commit identifies the commit that last changed the cryptographic publication evidence; "
            "truth_subject_commit identifies the transparency-verified subject commit. "
            "Consumers must not equate them unless evidence_equals_subject is true."
        )

    return {
        "evidence_commit": evidence_commit,
        "truth_subject_commit": truth_subject_commit,
        "subject_verdict": subject_verdict,
        "publication_receipt_status": publication_receipt_status,
        "evidence_contains_subject": evidence_contains_subject,
        "evidence_equals_subject": evidence_equals_subject,
        "claim_boundary": claim_boundary,
        "publication_evidence_refs": [receipt_ref, subject_ref],
    }


def build_public_verifier_report(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    report_root = (root / Path(report_root_rel)).resolve()
    manifest_path = report_root / "public_verifier_manifest.json"
    current_head_commit = _git_head(root)
    manifest = load_json(manifest_path) if manifest_path.exists() else {}

    claims = {
        "evidence_commit": str(manifest.get("evidence_commit", "")).strip(),
        "truth_subject_commit": str(manifest.get("truth_subject_commit", "")).strip(),
        "subject_verdict": str(manifest.get("subject_verdict", "")).strip(),
        "publication_receipt_status": str(manifest.get("publication_receipt_status", "")).strip(),
        "evidence_contains_subject": bool(manifest.get("evidence_contains_subject")),
        "evidence_equals_subject": bool(manifest.get("evidence_equals_subject")),
        "claim_boundary": str(manifest.get("claim_boundary", "")).strip(),
        "publication_evidence_refs": manifest.get("publication_evidence_refs", []),
    }
    if not claims["truth_subject_commit"] or not claims["subject_verdict"]:
        claims = build_public_verifier_claims(root=root, live_head=current_head_commit, report_root_rel=report_root_rel)
    governance_claims = build_platform_governance_claims(root=root, report_root_rel=report_root_rel)

    truth_subject_commit = str(claims.get("truth_subject_commit", "")).strip()
    head_equals_subject = bool(current_head_commit) and bool(truth_subject_commit) and current_head_commit == truth_subject_commit
    evidence_contains_subject = bool(claims.get("evidence_contains_subject"))
    subject_verdict = str(claims.get("subject_verdict", "")).strip() or SUBJECT_VERDICT_UNPROVEN
    platform_governance_subject_commit = str(governance_claims.get("platform_governance_subject_commit", "")).strip()
    platform_governance_verdict = str(governance_claims.get("platform_governance_verdict", "")).strip()
    platform_governance_head_equals_subject = (
        bool(current_head_commit) and bool(platform_governance_subject_commit) and current_head_commit == platform_governance_subject_commit
    )

    if subject_verdict == SUBJECT_VERDICT_PROVEN and evidence_contains_subject:
        head_claim_verdict = HEAD_VERDICT_SUBJECT if head_equals_subject else HEAD_VERDICT_CONTAINS
        head_claim_boundary = (
            "Current HEAD equals truth_subject_commit and is the transparency-verified subject."
            if head_equals_subject
            else "Current HEAD contains transparency-verified evidence for truth_subject_commit; HEAD is not itself the verified subject."
        )
        status = "PASS"
    else:
        head_claim_verdict = HEAD_VERDICT_UNPROVEN
        head_claim_boundary = "Current HEAD has no proven transparency claim boundary."
        status = "HOLD"

    if platform_governance_verdict == "PLATFORM_ENFORCEMENT_PROVEN" and platform_governance_subject_commit:
        platform_governance_head_claim_verdict = (
            GOVERNANCE_HEAD_VERDICT_PLATFORM_SUBJECT if platform_governance_head_equals_subject else GOVERNANCE_HEAD_VERDICT_PLATFORM_CONTAINS
        )
        platform_governance_head_claim_boundary = (
            "Current HEAD equals platform_governance_subject_commit and has fresh platform-enforcement proof."
            if platform_governance_head_equals_subject
            else "Current HEAD contains platform-governance evidence for platform_governance_subject_commit; it is not itself freshly governance-proven."
        )
    elif platform_governance_verdict == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED" and platform_governance_subject_commit:
        platform_governance_head_claim_verdict = (
            GOVERNANCE_HEAD_VERDICT_WORKFLOW_SUBJECT if platform_governance_head_equals_subject else GOVERNANCE_HEAD_VERDICT_WORKFLOW_CONTAINS
        )
        platform_governance_head_claim_boundary = (
            "Current HEAD equals platform_governance_subject_commit and has fresh workflow-governance-only evidence, but no platform-enforcement proof."
            if platform_governance_head_equals_subject
            else "Current HEAD contains workflow-governance-only evidence for platform_governance_subject_commit; it is not itself freshly governance-proven."
        )
    else:
        platform_governance_head_claim_verdict = GOVERNANCE_HEAD_VERDICT_UNPROVEN
        platform_governance_head_claim_boundary = "Current HEAD has no proven platform-governance claim boundary."

    return {
        "schema_id": "kt.operator.public_verifier_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "manifest_ref": PUBLIC_VERIFIER_MANIFEST_REL,
        "current_head_commit": current_head_commit,
        "evidence_commit": str(claims.get("evidence_commit", "")).strip(),
        "truth_subject_commit": truth_subject_commit,
        "subject_verdict": subject_verdict,
        "publication_receipt_status": str(claims.get("publication_receipt_status", "")).strip() or "MISSING",
        "evidence_contains_subject": evidence_contains_subject,
        "head_equals_subject": head_equals_subject,
        "head_claim_verdict": head_claim_verdict,
        "claim_boundary": str(claims.get("claim_boundary", "")).strip(),
        "head_claim_boundary": head_claim_boundary,
        "publication_evidence_refs": list(claims.get("publication_evidence_refs", [])),
        "platform_governance_subject_commit": platform_governance_subject_commit,
        "platform_governance_verdict": str(governance_claims.get("platform_governance_verdict", "")).strip(),
        "platform_governance_claim_admissible": bool(governance_claims.get("platform_governance_claim_admissible")),
        "workflow_governance_status": str(governance_claims.get("workflow_governance_status", "")).strip(),
        "branch_protection_status": str(governance_claims.get("branch_protection_status", "")).strip(),
        "platform_governance_claim_boundary": str(governance_claims.get("platform_governance_claim_boundary", "")).strip(),
        "enterprise_legitimacy_ceiling": str(governance_claims.get("enterprise_legitimacy_ceiling", "")).strip(),
        "platform_governance_receipt_refs": list(governance_claims.get("platform_governance_receipt_refs", [])),
        "platform_block": governance_claims.get("platform_block"),
        "platform_governance_head_equals_subject": platform_governance_head_equals_subject,
        "platform_governance_head_claim_verdict": platform_governance_head_claim_verdict,
        "platform_governance_head_claim_boundary": platform_governance_head_claim_boundary,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit the public verifier claim boundary for the current repo HEAD.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    parser.add_argument("--output", default="")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report = build_public_verifier_report(root=root, report_root_rel=str(args.report_root))
    if str(args.output).strip():
        output_path = Path(str(args.output)).expanduser()
        if not output_path.is_absolute():
            output_path = (root / output_path).resolve()
        write_json_stable(output_path, report)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
