from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.public_verifier import (
    HEAD_VERDICT_CONTAINS,
    HEAD_VERDICT_SUBJECT,
    SUBJECT_VERDICT_PROVEN,
    build_public_verifier_report,
)
from tools.operator.titanium_common import make_run_dir, repo_root, utc_now_iso_z, write_failure_artifacts, write_json_worm
from tools.operator.truth_authority import CURRENT_POINTER_REL, active_supporting_truth_surfaces, active_truth_source_ref, load_json_ref


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_CURRENT_STATE_REF = "kt_truth_ledger:ledger/current/current_state_receipt.json"
DEFAULT_RUNTIME_AUDIT_REF = "kt_truth_ledger:ledger/current/runtime_closure_audit.json"
LEDGER_POINTER_REF = "kt_truth_ledger:ledger/current/current_pointer.json"
LEDGER_BRANCH = "kt_truth_ledger"

PROOF_CLASS_FAIL_CLOSED = "FAIL_CLOSED"
PROOF_CLASS_PUBLISHED_HEAD = "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"

AUTHORITY_SUBJECT_REL = "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json"
CRYPTO_PUBLICATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json"
DOCUMENTARY_VALIDATION_REL = "KT_PROD_CLEANROOM/reports/documentary_truth_validation_receipt.json"
PUBLIC_VERIFIER_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"
TRUTH_PUBLICATION_STABILIZATION_REL = "KT_PROD_CLEANROOM/reports/kt_truth_publication_stabilization_receipt.json"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _remote_branch_head(*, root: Path, remote: str, branch: str) -> Dict[str, str]:
    try:
        raw = _git(root, "ls-remote", "--heads", remote, branch)
    except Exception as exc:  # noqa: BLE001
        return {
            "remote": remote,
            "branch": branch,
            "reachable": "false",
            "published": "false",
            "head_sha": "",
            "error": str(exc),
        }
    line = raw.strip().splitlines()[0].strip() if raw.strip() else ""
    head_sha = line.split()[0].strip() if line else ""
    return {
        "remote": remote,
        "branch": branch,
        "reachable": "true",
        "published": "true" if bool(head_sha) else "false",
        "head_sha": head_sha,
        "error": "",
    }


def _head_from(payload: Dict[str, Any]) -> str:
    if "validated_head_sha" in payload:
        return str(payload.get("validated_head_sha", "")).strip()
    if "pinned_head_sha" in payload:
        return str(payload.get("pinned_head_sha", "")).strip()
    if "truth_subject_commit" in payload:
        return str(payload.get("truth_subject_commit", "")).strip()
    return ""


def _status_from(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def _supporting_ref(surfaces: Sequence[str], suffix: str, fallback: str) -> str:
    for surface in surfaces:
        if str(surface).strip().endswith(suffix):
            return str(surface).strip()
    return fallback


def _documentary_only(payload: Dict[str, Any]) -> bool:
    if bool(payload.get("documentary_only")):
        return True
    if "live_authority" in payload and payload.get("live_authority") is False:
        return True
    if "LIVE_TRUTH_ALLOWED" in payload and payload.get("LIVE_TRUTH_ALLOWED") is False:
        return True
    status = str(payload.get("status", "")).strip().upper()
    authority_level = str(payload.get("authority_level", "")).strip().upper()
    return "DOCUMENTARY" in status or "SUPERSEDED" in status or authority_level == "DOCUMENTARY_ONLY"


def build_authority_convergence_report(*, root: Path) -> Dict[str, Any]:
    reports_root = (root / DEFAULT_REPORT_ROOT_REL).resolve()
    active_source = active_truth_source_ref(root=root)
    supporting_surfaces = active_supporting_truth_surfaces(root=root)
    current_state_ref = _supporting_ref(supporting_surfaces, "current_state_receipt.json", DEFAULT_CURRENT_STATE_REF)
    runtime_audit_ref = _supporting_ref(supporting_surfaces, "runtime_closure_audit.json", DEFAULT_RUNTIME_AUDIT_REF)

    board = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json")
    readiness = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json")
    documentary_validation = _load_json(root / DOCUMENTARY_VALIDATION_REL)
    stabilization = _load_json(root / TRUTH_PUBLICATION_STABILIZATION_REL)
    crypto_publication = _load_json(root / CRYPTO_PUBLICATION_RECEIPT_REL)
    authority_subject = _load_json(root / AUTHORITY_SUBJECT_REL)
    verifier_manifest = _load_json(root / PUBLIC_VERIFIER_MANIFEST_REL)

    ledger_pointer = load_json_ref(root=root, ref=active_source)
    ledger_current_state = load_json_ref(root=root, ref=current_state_ref)
    ledger_runtime_audit = load_json_ref(root=root, ref=runtime_audit_ref)

    main_pointer = _load_json(root / CURRENT_POINTER_REL)
    main_current_state = _load_json(reports_root / "current_state_receipt.json")
    main_runtime_audit = _load_json(reports_root / "runtime_closure_audit.json")

    verifier_report = build_public_verifier_report(root=root, report_root_rel=DEFAULT_REPORT_ROOT_REL)
    current_head_commit = _git_head(root)
    truth_subject_commit = str(authority_subject.get("truth_subject_commit", "")).strip()
    remote_fact = _remote_branch_head(root=root, remote="origin", branch=LEDGER_BRANCH)

    head_equals_subject = bool(current_head_commit) and bool(truth_subject_commit) and current_head_commit == truth_subject_commit
    expected_head_claim_verdict = HEAD_VERDICT_SUBJECT if head_equals_subject else HEAD_VERDICT_CONTAINS

    observed = {
        "current_head_commit": current_head_commit,
        "truth_subject_commit": truth_subject_commit,
        "evidence_commit": str(verifier_manifest.get("evidence_commit", "")).strip(),
        "current_head_equals_truth_subject": head_equals_subject,
        "active_truth_source": active_source,
        "board_truth_source": str(board.get("authoritative_current_head_truth_source", "")).strip(),
        "readiness_truth_source": str(readiness.get("authoritative_truth_source", "")).strip(),
        "board_authority_mode": str(board.get("authority_mode", "")).strip(),
        "ledger_branch_remote": str(remote_fact.get("remote", "")).strip(),
        "ledger_branch": str(remote_fact.get("branch", "")).strip(),
        "ledger_branch_reachable": str(remote_fact.get("reachable", "")).strip() == "true",
        "ledger_branch_published": str(remote_fact.get("published", "")).strip() == "true",
        "ledger_branch_head_sha": str(remote_fact.get("head_sha", "")).strip(),
        "ledger_pointer_head": _head_from(ledger_pointer),
        "ledger_current_state_head": _head_from(ledger_current_state),
        "ledger_runtime_audit_head": _head_from(ledger_runtime_audit),
        "ledger_pointer_posture": _status_from(ledger_pointer, "posture_enum"),
        "ledger_current_state_posture": _status_from(ledger_current_state, "posture_state", "current_p0_state"),
        "ledger_runtime_audit_posture": _status_from(ledger_runtime_audit, "posture_state", "current_state"),
        "verifier_truth_subject_commit": str(verifier_manifest.get("truth_subject_commit", "")).strip(),
        "verifier_evidence_commit": str(verifier_manifest.get("evidence_commit", "")).strip(),
        "verifier_subject_verdict": str(verifier_manifest.get("subject_verdict", "")).strip(),
        "verifier_publication_receipt_status": str(verifier_manifest.get("publication_receipt_status", "")).strip(),
        "verifier_head_claim_verdict": str(verifier_report.get("head_claim_verdict", "")).strip(),
        "publication_receipt_status": str(crypto_publication.get("status", "")).strip(),
        "stabilization_status": str(stabilization.get("status", "")).strip(),
        "truth_publication_stabilized": bool(stabilization.get("truth_publication_stabilized")),
        "stabilization_truth_subject_commit": str(stabilization.get("truth_subject_commit", "")).strip(),
        "documentary_validation_status": str(documentary_validation.get("status", "")).strip(),
        "main_current_pointer_documentary_only": _documentary_only(main_pointer),
        "main_current_state_documentary_only": _documentary_only(main_current_state),
        "main_runtime_audit_documentary_only": _documentary_only(main_runtime_audit),
    }

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    def expect_true(check_id: str, actual: bool, **extra: Any) -> None:
        checks.append({"check": check_id, "actual": bool(actual), "status": "PASS" if actual else "FAIL", **extra})
        if not actual:
            failures.append(check_id)

    def expect_equal(check_id: str, actual: str, expected: str) -> None:
        ok = bool(actual) and actual == expected
        checks.append({"check": check_id, "actual": actual, "expected": expected, "status": "PASS" if ok else "FAIL"})
        if not ok:
            failures.append(check_id)

    expect_equal("active_truth_source_is_ledger_pointer", observed["active_truth_source"], LEDGER_POINTER_REF)
    expect_equal("execution_board_points_to_active_truth_source", observed["board_truth_source"], observed["active_truth_source"])
    expect_equal("readiness_scope_points_to_active_truth_source", observed["readiness_truth_source"], observed["active_truth_source"])
    expect_true("ledger_branch_published", observed["ledger_branch_published"], remote_error=str(remote_fact.get("error", "")).strip())
    expect_equal("publication_receipt_passes", observed["publication_receipt_status"], "PASS")
    expect_equal("publication_stabilization_passes", observed["stabilization_status"], "PASS")
    expect_true("truth_publication_stabilized", observed["truth_publication_stabilized"])
    expect_equal("authority_subject_matches_stabilization_subject", observed["stabilization_truth_subject_commit"], truth_subject_commit)
    expect_equal("authority_subject_matches_verifier_subject", observed["verifier_truth_subject_commit"], truth_subject_commit)
    expect_equal("verifier_subject_verdict_proven", observed["verifier_subject_verdict"], SUBJECT_VERDICT_PROVEN)
    expect_equal("verifier_publication_receipt_passes", observed["verifier_publication_receipt_status"], "PASS")
    expect_equal("ledger_pointer_matches_truth_subject", observed["ledger_pointer_head"], truth_subject_commit)
    expect_equal("ledger_current_state_matches_truth_subject", observed["ledger_current_state_head"], truth_subject_commit)
    expect_equal("ledger_runtime_audit_matches_truth_subject", observed["ledger_runtime_audit_head"], truth_subject_commit)
    expect_equal("ledger_current_state_posture_matches_pointer", observed["ledger_current_state_posture"], observed["ledger_pointer_posture"])
    expect_equal("ledger_runtime_audit_posture_matches_pointer", observed["ledger_runtime_audit_posture"], observed["ledger_pointer_posture"])
    expect_equal("documentary_truth_validation_passes", observed["documentary_validation_status"], "PASS")
    expect_true("main_current_pointer_documentary_only", observed["main_current_pointer_documentary_only"])
    expect_true("main_current_state_documentary_only", observed["main_current_state_documentary_only"])
    expect_true("main_runtime_audit_documentary_only", observed["main_runtime_audit_documentary_only"])
    expect_equal("current_head_claim_boundary_preserved", observed["verifier_head_claim_verdict"], expected_head_claim_verdict)

    status = "PASS" if not failures else "FAIL"
    proof_class = PROOF_CLASS_PUBLISHED_HEAD if not failures else PROOF_CLASS_FAIL_CLOSED
    return {
        "schema_id": "kt.operator.authority_convergence_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "proof_class": proof_class,
        "published_head_authority_claimed": not failures,
        "current_head_authority_claimed": head_equals_subject and not failures,
        "h1_admissible": False,
        "failures": failures,
        "checks": checks,
        "observed": observed,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate WS9 authority convergence against the published subject/evidence boundary.")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="authority-convergence-validate", requested_run_root=str(args.run_root))
    try:
        report = build_authority_convergence_report(root=repo_root())
        write_json_worm(run_dir / "reports" / "authority_convergence_receipt.json", report, label="authority_convergence_receipt.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.authority.convergence_validate",
                failure_name="AUTHORITY_CONVERGENCE_FAIL",
                message="; ".join(report.get("failures", [])),
                next_actions=[
                    "Align the ledger current surfaces to the published truth subject commit.",
                    "Keep the current-head claim boundary explicit when HEAD differs from truth_subject_commit.",
                    "Do not reopen H1 while authority convergence or published-head self-convergence is unresolved.",
                ],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.authority.convergence_validate",
            failure_name="AUTHORITY_CONVERGENCE_FAIL",
            message=str(exc),
            next_actions=[
                "Inspect the ledger current surfaces, public verifier manifest, and publication attestation artifacts.",
                "Fail closed on any truth-subject mismatch.",
            ],
        )


if __name__ == "__main__":
    raise SystemExit(main())
