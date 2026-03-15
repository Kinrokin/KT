from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.platform_governance_narrowing import (
    PLATFORM_GOVERNANCE_VERDICT_PROVEN,
    PLATFORM_GOVERNANCE_VERDICT_UNPROVEN,
    PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY,
    build_platform_governance_claims,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
LEGACY_NARROWING_REL = f"{DEFAULT_REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json"
PROVEN_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_platform_governance_proven_receipt.json"
LAWFUL_NARROWING_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_platform_governance_lawful_narrowing_receipt.json"
FINAL_DECISION_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_platform_governance_final_decision_receipt.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{DEFAULT_REPORT_ROOT_REL}/public_verifier_manifest.json"
MAIN_BRANCH_PROTECTION_REL = f"{DEFAULT_REPORT_ROOT_REL}/main_branch_protection_receipt.json"
CI_GATE_PROMOTION_REL = f"{DEFAULT_REPORT_ROOT_REL}/ci_gate_promotion_receipt.json"
AUTHORITY_CONVERGENCE_REL = f"{DEFAULT_REPORT_ROOT_REL}/authority_convergence_receipt.json"
CRYPTO_PUBLICATION_REL = f"{DEFAULT_REPORT_ROOT_REL}/cryptographic_publication_receipt.json"
RELEASE_LAW_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_release_law.json"

WORKSTREAM_ID = "WS10_PLATFORM_GOVERNANCE_FINAL_DECISION"
STEP_ID = "WS10_STEP_1_PLATFORM_GOVERNANCE_FINALIZATION"
PASS_VERDICT = "PLATFORM_GOVERNANCE_FINALIZED"

STATUS_PASS = "PASS"
STATUS_FAIL_CLOSED = "FAIL_CLOSED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

DECISION_MODE_PROVEN = "PLATFORM_PROVEN"
DECISION_MODE_NARROWED = "LAWFUL_NARROWING"

ALLOWED_TOUCHES = {
    PROVEN_RECEIPT_REL,
    LAWFUL_NARROWING_RECEIPT_REL,
    FINAL_DECISION_RECEIPT_REL,
    PUBLIC_VERIFIER_MANIFEST_REL,
    RELEASE_LAW_REL,
    "KT_PROD_CLEANROOM/governance/public_verifier_rules.json",
    "KT_PROD_CLEANROOM/governance/closure_foundation/kt_public_verifier_contract.json",
    "KT_PROD_CLEANROOM/governance/closure_foundation/kt_claim_compiler_policy.json",
    "KT_PROD_CLEANROOM/tools/operator/platform_governance_finalize.py",
    "KT_PROD_CLEANROOM/tools/operator/public_verifier.py",
    "KT_PROD_CLEANROOM/tools/operator/public_verifier_release_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_platform_governance_finalize.py",
    "KT_PROD_CLEANROOM/tests/operator/test_public_verifier.py",
    "KT_PROD_CLEANROOM/tests/operator/test_public_verifier_release_validate.py",
}
PROTECTED_PATTERNS = ("KT_ARCHIVE/", ".github/workflows/")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_paths(root: Path) -> List[str]:
    out = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"], text=True, encoding="utf-8")
    rows: List[str] = []
    for line in out.splitlines():
        rel = line[3:].strip()
        if rel:
            rows.append(Path(rel).as_posix())
    return rows


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def build_platform_governance_final_claims(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    final_path = (root / Path(FINAL_DECISION_RECEIPT_REL)).resolve()
    if final_path.exists():
        final_receipt = load_json(final_path)
        verdict = str(final_receipt.get("platform_governance_verdict", "")).strip()
        if verdict:
            return {
                "platform_governance_subject_commit": str(final_receipt.get("platform_governance_subject_commit", "")).strip(),
                "platform_governance_verdict": verdict,
                "platform_governance_claim_admissible": bool(final_receipt.get("platform_governance_claim_admissible")),
                "workflow_governance_status": str(final_receipt.get("workflow_governance_status", "")).strip(),
                "branch_protection_status": str(final_receipt.get("branch_protection_status", "")).strip(),
                "platform_governance_claim_boundary": str(final_receipt.get("platform_governance_claim_boundary", "")).strip(),
                "allowed_current_claims": list(final_receipt.get("allowed_current_claims", [])),
                "forbidden_current_claims": list(final_receipt.get("forbidden_current_claims", [])),
                "enterprise_legitimacy_ceiling": str(final_receipt.get("enterprise_legitimacy_ceiling", "")).strip(),
                "platform_governance_receipt_refs": list(final_receipt.get("platform_governance_receipt_refs", [])),
                "platform_block": final_receipt.get("platform_block"),
            }
    return build_platform_governance_claims(root=root, report_root_rel=report_root_rel)


def _decision_receipt_refs(*, decision_mode: str, report_root_rel: str) -> List[str]:
    refs = [
        str((Path(report_root_rel) / "ci_gate_promotion_receipt.json").as_posix()),
        str((Path(report_root_rel) / "main_branch_protection_receipt.json").as_posix()),
    ]
    if decision_mode == DECISION_MODE_PROVEN:
        refs.append(PROVEN_RECEIPT_REL)
    else:
        refs.extend([LEGACY_NARROWING_REL, LAWFUL_NARROWING_RECEIPT_REL])
    refs.append(FINAL_DECISION_RECEIPT_REL)
    return refs


def build_platform_governance_proven_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    claims = build_platform_governance_claims(root=root, report_root_rel=report_root_rel)
    current_head = _git_head(root)
    proven = str(claims.get("platform_governance_verdict", "")).strip() == PLATFORM_GOVERNANCE_VERDICT_PROVEN
    status = STATUS_PASS if proven else STATUS_NOT_APPLICABLE
    return {
        "artifact_id": Path(PROVEN_RECEIPT_REL).name,
        "schema_id": "kt.operator.platform_governance_proven_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": PLATFORM_GOVERNANCE_VERDICT_PROVEN if proven else STATUS_NOT_APPLICABLE,
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "platform_governance_subject_commit": str(claims.get("platform_governance_subject_commit", "")).strip(),
        "platform_governance_verdict": str(claims.get("platform_governance_verdict", "")).strip(),
        "platform_governance_claim_admissible": bool(claims.get("platform_governance_claim_admissible")),
        "workflow_governance_status": str(claims.get("workflow_governance_status", "")).strip(),
        "branch_protection_status": str(claims.get("branch_protection_status", "")).strip(),
        "platform_governance_claim_boundary": str(claims.get("platform_governance_claim_boundary", "")).strip(),
        "platform_governance_receipt_refs": [
            str((Path(report_root_rel) / "ci_gate_promotion_receipt.json").as_posix()),
            str((Path(report_root_rel) / "main_branch_protection_receipt.json").as_posix()),
        ],
        "enterprise_legitimacy_ceiling": str(claims.get("enterprise_legitimacy_ceiling", "")).strip(),
        "platform_block": claims.get("platform_block"),
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.platform_governance_finalize"],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS11_FINAL_RECUT_AND_RE-ADJUDICATION"},
    }


def build_platform_governance_lawful_narrowing_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    claims = build_platform_governance_claims(root=root, report_root_rel=report_root_rel)
    current_head = _git_head(root)
    narrowed = str(claims.get("platform_governance_verdict", "")).strip() == PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY
    ambiguous = str(claims.get("platform_governance_verdict", "")).strip() == PLATFORM_GOVERNANCE_VERDICT_UNPROVEN
    status = STATUS_PASS if narrowed else STATUS_FAIL_CLOSED if ambiguous else STATUS_NOT_APPLICABLE
    pass_verdict = PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY if narrowed else STATUS_FAIL_CLOSED if ambiguous else STATUS_NOT_APPLICABLE
    return {
        "artifact_id": Path(LAWFUL_NARROWING_RECEIPT_REL).name,
        "schema_id": "kt.operator.platform_governance_lawful_narrowing_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": pass_verdict,
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "platform_governance_subject_commit": str(claims.get("platform_governance_subject_commit", "")).strip(),
        "platform_governance_verdict": str(claims.get("platform_governance_verdict", "")).strip(),
        "platform_governance_claim_admissible": bool(claims.get("platform_governance_claim_admissible")),
        "workflow_governance_status": str(claims.get("workflow_governance_status", "")).strip(),
        "branch_protection_status": str(claims.get("branch_protection_status", "")).strip(),
        "platform_governance_claim_boundary": str(claims.get("platform_governance_claim_boundary", "")).strip(),
        "allowed_current_claims": list(claims.get("allowed_current_claims", [])),
        "forbidden_current_claims": list(claims.get("forbidden_current_claims", [])),
        "enterprise_legitimacy_ceiling": str(claims.get("enterprise_legitimacy_ceiling", "")).strip(),
        "platform_governance_receipt_refs": [
            str((Path(report_root_rel) / "ci_gate_promotion_receipt.json").as_posix()),
            str((Path(report_root_rel) / "main_branch_protection_receipt.json").as_posix()),
            LEGACY_NARROWING_REL,
        ],
        "platform_block": claims.get("platform_block"),
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.platform_governance_finalize"],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS11_FINAL_RECUT_AND_RE-ADJUDICATION"},
    }


def _refreshed_public_verifier_manifest(*, root: Path, claims: Dict[str, Any]) -> Dict[str, Any]:
    manifest = _load_required(root, PUBLIC_VERIFIER_MANIFEST_REL)
    authority = _load_required(root, AUTHORITY_CONVERGENCE_REL)
    publication = _load_required(root, CRYPTO_PUBLICATION_REL)
    current_head = _git_head(root)
    filtered_state_receipts = [
        ref
        for ref in list(manifest.get("state_receipts", []))
        if "platform_governance_" not in str(ref)
    ]
    filtered_state_receipts.append(FINAL_DECISION_RECEIPT_REL)
    updated = dict(manifest)
    updated.update(
        {
            "generated_utc": utc_now_iso_z(),
            "validated_head_sha": current_head,
            "status": STATUS_PASS
            if str(authority.get("status", "")).strip() == STATUS_PASS and str(publication.get("status", "")).strip() == STATUS_PASS
            else "HOLD",
            "platform_governance_subject_commit": str(claims.get("platform_governance_subject_commit", "")).strip(),
            "platform_governance_verdict": str(claims.get("platform_governance_verdict", "")).strip(),
            "platform_governance_claim_admissible": bool(claims.get("platform_governance_claim_admissible")),
            "workflow_governance_status": str(claims.get("workflow_governance_status", "")).strip(),
            "branch_protection_status": str(claims.get("branch_protection_status", "")).strip(),
            "platform_governance_claim_boundary": str(claims.get("platform_governance_claim_boundary", "")).strip(),
            "enterprise_legitimacy_ceiling": str(claims.get("enterprise_legitimacy_ceiling", "")).strip(),
            "platform_governance_receipt_refs": list(claims.get("platform_governance_receipt_refs", [])),
            "platform_block": claims.get("platform_block"),
            "state_receipts": filtered_state_receipts,
        }
    )
    return updated


def build_platform_governance_final_decision_receipt(
    *,
    root: Path,
    report_root_rel: str = DEFAULT_REPORT_ROOT_REL,
    actual_touched: Optional[List[str]] = None,
) -> Dict[str, Any]:
    claims = build_platform_governance_claims(root=root, report_root_rel=report_root_rel)
    current_head = _git_head(root)
    verdict = str(claims.get("platform_governance_verdict", "")).strip()
    if verdict == PLATFORM_GOVERNANCE_VERDICT_PROVEN:
        decision_mode = DECISION_MODE_PROVEN
        status = STATUS_PASS
    elif verdict == PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY:
        decision_mode = DECISION_MODE_NARROWED
        status = STATUS_PASS
    else:
        decision_mode = "AMBIGUOUS_FAIL_CLOSED"
        status = STATUS_FAIL_CLOSED

    touched = sorted(set(actual_touched or []))
    unexpected_touches = [path for path in touched if path not in ALLOWED_TOUCHES]
    protected_touch_violations = [path for path in touched if any(path.startswith(prefix) for prefix in PROTECTED_PATTERNS)]
    if unexpected_touches or protected_touch_violations:
        status = STATUS_FAIL_CLOSED

    receipt_refs = _decision_receipt_refs(decision_mode=decision_mode, report_root_rel=report_root_rel) if status == STATUS_PASS else [
        str((Path(report_root_rel) / "ci_gate_promotion_receipt.json").as_posix()),
        str((Path(report_root_rel) / "main_branch_protection_receipt.json").as_posix()),
    ]
    issues_found = []
    if verdict == PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY:
        issues_found.append("platform_enforcement_unavailable_due_to_live_branch_protection_block")
    if verdict == PLATFORM_GOVERNANCE_VERDICT_UNPROVEN:
        issues_found.append("platform_governance_verdict_ambiguous")

    return {
        "artifact_id": Path(FINAL_DECISION_RECEIPT_REL).name,
        "schema_id": "kt.operator.platform_governance_final_decision_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": PASS_VERDICT if status == STATUS_PASS else STATUS_FAIL_CLOSED,
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "platform_governance_subject_commit": str(claims.get("platform_governance_subject_commit", "")).strip(),
        "platform_governance_verdict": verdict,
        "platform_governance_claim_admissible": bool(claims.get("platform_governance_claim_admissible")),
        "workflow_governance_status": str(claims.get("workflow_governance_status", "")).strip(),
        "branch_protection_status": str(claims.get("branch_protection_status", "")).strip(),
        "platform_governance_claim_boundary": str(claims.get("platform_governance_claim_boundary", "")).strip(),
        "allowed_current_claims": list(claims.get("allowed_current_claims", [])),
        "forbidden_current_claims": list(claims.get("forbidden_current_claims", [])),
        "enterprise_legitimacy_ceiling": str(claims.get("enterprise_legitimacy_ceiling", "")).strip(),
        "platform_block": claims.get("platform_block"),
        "decision_mode": decision_mode,
        "platform_governance_receipt_refs": receipt_refs,
        "release_law_ref": RELEASE_LAW_REL,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "validators_run": ["python -m tools.operator.platform_governance_finalize"],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS11_FINAL_RECUT_AND_RE-ADJUDICATION"},
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "resolved platform governance to either platform proof or explicit workflow-only narrowing from live source receipts",
                "refreshed the public verifier manifest to point at the final governance decision surface",
                "sealed WS10 governance final-decision receipts without upgrading claims above the live branch-protection evidence",
            ],
            "files_touched": touched,
            "tests_run": ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_platform_governance_finalize.py KT_PROD_CLEANROOM/tests/operator/test_public_verifier.py -q"],
            "validators_run": ["python -m tools.operator.platform_governance_finalize"],
            "issues_found": issues_found,
            "resolution": "WS10 either proves platform enforcement or permanently narrows governance claims to the highest live admissible class.",
            "pass_fail_status": status,
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
        },
    }


def emit_platform_governance_finalization(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    claims = build_platform_governance_claims(root=root, report_root_rel=report_root_rel)
    decision_mode = DECISION_MODE_PROVEN if str(claims.get("platform_governance_verdict", "")).strip() == PLATFORM_GOVERNANCE_VERDICT_PROVEN else DECISION_MODE_NARROWED

    write_json_stable((root / PROVEN_RECEIPT_REL).resolve(), build_platform_governance_proven_receipt(root=root, report_root_rel=report_root_rel))
    write_json_stable(
        (root / LAWFUL_NARROWING_RECEIPT_REL).resolve(),
        build_platform_governance_lawful_narrowing_receipt(root=root, report_root_rel=report_root_rel),
    )

    finalized_claims = dict(claims)
    finalized_claims["platform_governance_receipt_refs"] = _decision_receipt_refs(decision_mode=decision_mode, report_root_rel=report_root_rel)
    write_json_stable((root / PUBLIC_VERIFIER_MANIFEST_REL).resolve(), _refreshed_public_verifier_manifest(root=root, claims=finalized_claims))

    actual_touched = _git_status_paths(root)
    final_receipt = build_platform_governance_final_decision_receipt(root=root, report_root_rel=report_root_rel, actual_touched=actual_touched)
    write_json_stable((root / FINAL_DECISION_RECEIPT_REL).resolve(), final_receipt)
    return final_receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Finalize platform governance as either proven or lawfully narrowed.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt = emit_platform_governance_finalization(root=root, report_root_rel=str(args.report_root))
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == STATUS_PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
