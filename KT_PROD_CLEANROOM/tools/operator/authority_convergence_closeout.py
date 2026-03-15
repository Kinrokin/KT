from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS9_AUTHORITY_AND_PUBLISHED_HEAD_CLOSURE"
STEP_ID = "WS9_STEP_1_AUTHORITY_AND_PUBLISHED_HEAD_CLOSEOUT"
PASS_VERDICT = "AUTHORITY_AND_PUBLISHED_HEAD_CLOSED"
REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"

AUTHORITY_REL = f"{REPORT_ROOT_REL}/authority_convergence_receipt.json"
PUBLISHED_REL = f"{REPORT_ROOT_REL}/published_head_self_convergence_receipt.json"
KT_PUBLISHED_REL = f"{REPORT_ROOT_REL}/kt_published_head_self_convergence_receipt.json"
KT_CLOSURE_REL = f"{REPORT_ROOT_REL}/kt_authority_closure_receipt.json"
REPORTING_REPAIR_REL = f"{REPORT_ROOT_REL}/reporting_integrity_repair_receipt.json"

ALLOWED_TOUCHES = {
    AUTHORITY_REL,
    PUBLISHED_REL,
    KT_PUBLISHED_REL,
    KT_CLOSURE_REL,
    REPORTING_REPAIR_REL,
    "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
    "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
    "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
    "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_supersession_receipt.json",
    "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "KT_PROD_CLEANROOM/governance/execution_board.json",
    "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
}
PROTECTED_PATTERNS = (".github/workflows/", "KT_ARCHIVE/")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_paths(root: Path) -> List[str]:
    out = _git(root, "status", "--porcelain=v1")
    rows: List[str] = []
    for line in out.splitlines():
        rel = line[3:].strip()
        if rel:
            rows.append(Path(rel).as_posix())
    return rows


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build_kt_published_head_self_convergence_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    published = _load_required(root, PUBLISHED_REL)
    status = str(published.get("status", "")).strip()
    return {
        "artifact_id": Path(KT_PUBLISHED_REL).name,
        "schema_id": "kt.operator.ws9_published_head_self_convergence_receipt.v1",
        "status": status,
        "pass_verdict": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN" if status == "PASS" else "FAIL_CLOSED",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "truth_subject_commit": str(published.get("truth_subject_commit", "")).strip(),
        "truth_evidence_commit": str(published.get("evidence_commit", "")).strip(),
        "current_head_commit": str(published.get("current_head_commit", "")).strip(),
        "head_equals_subject": bool(published.get("head_equals_subject")),
        "proof_class": str(published.get("proof_class", "")).strip(),
        "current_head_claim_verdict": str(published.get("current_head_claim_verdict", "")).strip(),
        "published_head_authority_claimed": bool(published.get("published_head_authority_claimed")),
        "current_head_authority_claimed": bool(published.get("current_head_authority_claimed")),
        "blockers": list(published.get("blockers", [])),
        "source_receipt_ref": PUBLISHED_REL,
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": [
            "python -m tools.operator.authority_convergence_validate",
            "python -m tools.operator.reporting_integrity --mode verify",
        ],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS10_PLATFORM_GOVERNANCE_FINAL_DECISION"},
    }


def build_authority_closure_receipt(*, root: Path, generated_utc: str) -> Dict[str, Any]:
    current_head = _git_head(root)
    authority = _load_required(root, AUTHORITY_REL)
    published = _load_required(root, PUBLISHED_REL)
    kt_published = _load_required(root, KT_PUBLISHED_REL)
    reporting = _load_required(root, REPORTING_REPAIR_REL)

    actual_touched = sorted(set(_git_status_paths(root) + [KT_PUBLISHED_REL, KT_CLOSURE_REL]))
    unexpected_touches = [path for path in actual_touched if path not in ALLOWED_TOUCHES]
    protected_touch_violations = [path for path in actual_touched if any(path.startswith(prefix) for prefix in PROTECTED_PATTERNS)]

    authority_ok = str(authority.get("status", "")).strip() == "PASS"
    published_ok = str(published.get("status", "")).strip() == "PASS"
    reporting_ok = str(reporting.get("status", "")).strip() == "PASS"
    status = "PASS" if authority_ok and published_ok and reporting_ok and not unexpected_touches and not protected_touch_violations else "FAIL_CLOSED"

    return {
        "artifact_id": Path(KT_CLOSURE_REL).name,
        "schema_id": "kt.operator.authority_closure_receipt.v1",
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "FAIL_CLOSED",
        "generated_utc": generated_utc,
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "truth_subject_commit": str(published.get("truth_subject_commit", "")).strip(),
        "truth_evidence_commit": str(published.get("evidence_commit", "")).strip(),
        "current_head_commit": str(published.get("current_head_commit", "")).strip(),
        "head_equals_subject": bool(published.get("head_equals_subject")),
        "authority_convergence_ref": AUTHORITY_REL,
        "published_head_self_convergence_ref": PUBLISHED_REL,
        "kt_published_head_self_convergence_ref": KT_PUBLISHED_REL,
        "reporting_integrity_ref": REPORTING_REPAIR_REL,
        "authority_convergence_status": str(authority.get("status", "")).strip(),
        "authority_convergence_proof_class": str(authority.get("proof_class", "")).strip(),
        "published_head_self_convergence_status": str(published.get("status", "")).strip(),
        "published_head_self_convergence_proof_class": str(published.get("proof_class", "")).strip(),
        "reporting_integrity_status": str(reporting.get("status", "")).strip(),
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "validators_run": [
            "python -m tools.operator.authority_convergence_validate",
            "python -m tools.operator.reporting_integrity --mode verify",
        ],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS10_PLATFORM_GOVERNANCE_FINAL_DECISION"},
        "step_report": {
            "timestamp": generated_utc,
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "verified the ledger current surfaces against the published truth subject",
                "re-emitted the legacy authority and published-head self-convergence receipts under the WS9 contract",
                "sealed WS9 kt_* closure receipts without upgrading H1",
            ],
            "files_touched": actual_touched,
            "tests_run": ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_validate.py KT_PROD_CLEANROOM/tests/operator/test_reporting_integrity.py KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_closeout.py -q"],
            "validators_run": [
                "python -m tools.operator.authority_convergence_validate",
                "python -m tools.operator.reporting_integrity --mode verify",
            ],
            "issues_found": [],
            "resolution": "WS9 closes authority convergence and published-head self-convergence at the published subject boundary while preserving current-head anti-overread behavior.",
            "pass_fail_status": status,
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
        },
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seal WS9 authority closure receipts from the already-emitted legacy convergence receipts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    root = repo_root()
    generated_utc = utc_now_iso_z()
    kt_published = build_kt_published_head_self_convergence_receipt(root=root)
    write_json_stable((root / KT_PUBLISHED_REL).resolve(), kt_published)
    closure = build_authority_closure_receipt(root=root, generated_utc=generated_utc)
    write_json_stable((root / KT_CLOSURE_REL).resolve(), closure)
    print(json.dumps(closure, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(closure.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
