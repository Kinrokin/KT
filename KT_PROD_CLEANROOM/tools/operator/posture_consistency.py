from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, write_json_stable
from tools.operator.truth_engine import (
    CANONICAL_READY_FOR_REEARNED_GREEN,
    TRUTHFUL_GREEN,
    derive_live_validation_state,
    normalize_claim_state,
)


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"

ALLOWED_POSTURES = {
    "TRUTH_DEFECTS_PRESENT",
    "CANONICAL_VALIDATED_DIRTY_WORKTREE",
    CANONICAL_READY_FOR_REEARNED_GREEN,
    TRUTHFUL_GREEN,
}


def _status_is_pass(value: str) -> bool:
    return str(value).strip() in {"PASS", "PASS_WITH_WARNINGS", "WARN_ONLY_LIVE"}


def _report_path(root: Path, rel: str) -> Path:
    return (root / rel).resolve()


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = _report_path(root, rel)
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _load_required_report(root: Path, report_root_rel: str, rel: str) -> Dict[str, Any]:
    return _load_required(root, str((Path(report_root_rel) / rel).as_posix()))


def _verify_real_path_matrix(matrix: Dict[str, Any]) -> Dict[str, Any]:
    rows = matrix.get("rows")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("FAIL_CLOSED: real_path_attachment_matrix rows missing")
    program_ids = {str(row.get("program_id", "")).strip() for row in rows if isinstance(row, dict)}
    required = {"program.certify.canonical_hmac", "program.hat_demo", "program.red_assault.serious_v1"}
    missing = sorted(x for x in required if x not in program_ids)
    def _row_passes(row: Dict[str, Any]) -> bool:
        status = str(row.get("attachment_status") or row.get("status") or "PASS").strip().upper()
        return status == "PASS"

    required_passes = {
        program_id: any(
            isinstance(row, dict)
            and str(row.get("program_id", "")).strip() == program_id
            and _row_passes(row)
            for row in rows
        )
        for program_id in required
    }
    failed_required = sorted(program_id for program_id, ok in required_passes.items() if not ok)
    safe_run_ok = any(
        isinstance(row, dict)
        and bool(row.get("safe_run_enforced"))
        and _row_passes(row)
        for row in rows
    )
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: real_path_attachment_matrix missing targets: {', '.join(missing)}")
    if failed_required:
        raise RuntimeError(
            "FAIL_CLOSED: real_path_attachment_matrix missing PASS attachment rows for: "
            + ", ".join(failed_required)
        )
    if not safe_run_ok:
        raise RuntimeError("FAIL_CLOSED: real_path_attachment_matrix missing safe-run enforced row")
    return {
        "status": "PASS",
        "program_ids": sorted(program_ids),
        "required_passes": required_passes,
        "safe_run_enforced_present": safe_run_ok,
    }


def _verify_alias_truth(*, manifest: Dict[str, Any], aliases: Dict[str, Any]) -> Dict[str, Any]:
    authority_sha = str(manifest.get("authority_os_sha256", "")).strip()
    titanium_sha = str(manifest.get("titanium_work_order_sha256", "")).strip()
    equal = authority_sha == titanium_sha
    alias_equal = bool(aliases.get("authority_os_equals_titanium_work_order"))
    if equal != alias_equal:
        raise RuntimeError("FAIL_CLOSED: alias equality flag does not match governance manifest pin equality")
    if equal:
        required = [
            "authority_os_document_id",
            "titanium_work_order_document_id",
            "authority_os_sha256",
            "titanium_work_order_sha256",
            "authority_os_equals_titanium_work_order",
            "alias_type",
            "alias_rationale",
        ]
    else:
        required = [
            "authority_os_document_id",
            "titanium_work_order_document_id",
            "authority_os_sha256",
            "titanium_work_order_sha256",
            "authority_os_equals_titanium_work_order",
            "split_rationale",
        ]
    missing = [field for field in required if not aliases.get(field) and aliases.get(field) is not False]
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: governance_aliases missing fields: {', '.join(missing)}")
    if str(aliases.get("authority_os_sha256", "")).strip() != authority_sha:
        raise RuntimeError("FAIL_CLOSED: governance_aliases authority_os_sha256 mismatch")
    if str(aliases.get("titanium_work_order_sha256", "")).strip() != titanium_sha:
        raise RuntimeError("FAIL_CLOSED: governance_aliases titanium_work_order_sha256 mismatch")
    return {
        "status": "PASS",
        "authority_os_equals_titanium_work_order": equal,
        "alias_type": str(aliases.get("alias_type", "")).strip() if equal else "split",
    }


def _verify_preserved_receipts(root: Path) -> Dict[str, Any]:
    checks = []

    matrix = _load_required(root, "KT_PROD_CLEANROOM/reports/real_path_attachment_matrix.json")
    checks.append({"artifact": "real_path_attachment_matrix.json", **_verify_real_path_matrix(matrix)})

    source = _load_required(root, "KT_PROD_CLEANROOM/reports/source_integrity_receipt.json")
    if str(source.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: source_integrity_receipt not PASS")
    checks.append({"artifact": "source_integrity_receipt.json", "status": "PASS"})

    hashpin = _load_required(root, "KT_PROD_CLEANROOM/reports/hashpin_receipt.json")
    if int(hashpin.get("target_count", 0)) < 7:
        raise RuntimeError("FAIL_CLOSED: hashpin_receipt target_count < 7")
    checks.append({"artifact": "hashpin_receipt.json", "status": "PASS", "target_count": int(hashpin.get("target_count", 0))})

    governance = _load_required(root, "KT_PROD_CLEANROOM/reports/governance_manifest_verification.json")
    if str(governance.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: governance_manifest_verification not PASS")
    checks.append({"artifact": "governance_manifest_verification.json", "status": "PASS"})

    catalog = _load_required(root, "KT_PROD_CLEANROOM/reports/program_catalog_report.json")
    if str(catalog.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: program_catalog_report not PASS")
    checks.append({"artifact": "program_catalog_report.json", "status": "PASS"})

    practice = _load_required(root, "KT_PROD_CLEANROOM/reports/practice_mode_chain_summary.json")
    if str(practice.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: practice_mode_chain_summary not PASS")
    checks.append({"artifact": "practice_mode_chain_summary.json", "status": "PASS"})

    twocc = _load_required(root, "KT_PROD_CLEANROOM/reports/twocleanclone_proof.json")
    if str(twocc.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: twocleanclone_proof not PASS")
    checks.append({"artifact": "twocleanclone_proof.json", "status": "PASS"})

    god = _load_required(root, "KT_PROD_CLEANROOM/reports/godstatus_verdict.json")
    if not _status_is_pass(str(god.get("status", "")).strip()):
        raise RuntimeError("FAIL_CLOSED: godstatus_verdict not PASS/PASS_WITH_WARNINGS")
    checks.append({"artifact": "godstatus_verdict.json", "status": str(god.get("status", "")).strip()})

    ci = _load_required(root, "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json")
    ci_status = str(ci.get("status", "")).strip() or "UNKNOWN"
    allowed_ci_statuses = {"WARN_ONLY_LIVE", "PASS_WITH_PLATFORM_BLOCK", "PASS", "PASS_WITH_WARNINGS"}
    if ci_status not in allowed_ci_statuses:
        raise RuntimeError(
            "FAIL_CLOSED: ci_gate_promotion_receipt status must be one of: "
            + ", ".join(sorted(allowed_ci_statuses))
        )
    checks.append({"artifact": "ci_gate_promotion_receipt.json", "status": ci_status})

    return {"status": "PASS", "checks": checks}


def _head_field(obj: Dict[str, Any]) -> str:
    for key in ("validated_head_sha", "head_sha", "head"):
        value = str(obj.get(key, "")).strip()
        if value:
            return value
    return ""


def _verify_one_button_state(*, root: Path, report_root_rel: str, posture_state: str, live_head: str, branch_ref: str) -> Dict[str, Any]:
    preflight = _load_required_report(root, report_root_rel, "one_button_preflight_receipt.json")
    production = _load_required_report(root, report_root_rel, "one_button_production_receipt.json")
    branch_protection = _load_required(root, f"{DEFAULT_REPORT_ROOT_REL}/main_branch_protection_receipt.json")

    checks: List[Dict[str, Any]] = []
    preflight_status = str(preflight.get("status", "")).strip()
    production_status = str(production.get("status", "")).strip()
    branch_status = str(branch_protection.get("status", "")).strip()

    if posture_state == TRUTHFUL_GREEN:
        if preflight_status != "PASS":
            raise RuntimeError("FAIL_CLOSED: one_button_preflight_receipt must be PASS for truthful green posture")
        if production_status != "PASS":
            raise RuntimeError("FAIL_CLOSED: one_button_production_receipt must be PASS for truthful green posture")
        preflight_head = _head_field(preflight)
        production_head = _head_field(production)
        if preflight_head != live_head:
            raise RuntimeError("FAIL_CLOSED: one_button_preflight_receipt head does not match live head")
        if production_head != live_head:
            raise RuntimeError("FAIL_CLOSED: one_button_production_receipt head does not match live head")
        checks.append({"artifact": "one_button_preflight_receipt.json", "status": "PASS"})
        checks.append({"artifact": "one_button_production_receipt.json", "status": "PASS"})
        if branch_ref == "main":
            if branch_status != "PASS":
                raise RuntimeError("FAIL_CLOSED: truthful green on main requires main_branch_protection_receipt PASS")
            checks.append({"artifact": "main_branch_protection_receipt.json", "status": "PASS"})
    else:
        checks.append({"artifact": "main_branch_protection_receipt.json", "status": branch_status})

    return {"status": "PASS", "checks": checks}


def verify_posture(
    *,
    root: Path,
    expected_posture: str,
    live_validation_index_rel: str = f"{DEFAULT_REPORT_ROOT_REL}/live_validation_index.json",
    report_root_rel: str = DEFAULT_REPORT_ROOT_REL,
) -> Dict[str, Any]:
    current_state = _load_required_report(root, report_root_rel, "current_state_receipt.json")
    runtime_audit = _load_required_report(root, report_root_rel, "runtime_closure_audit.json")
    live_validation_index = _load_required(root, str(live_validation_index_rel))
    manifest = _load_required(root, "KT_PROD_CLEANROOM/governance/governance_manifest.json")
    aliases = _load_required(root, "KT_PROD_CLEANROOM/governance/governance_aliases.json")

    current_posture_raw = str(current_state.get("posture_state") or current_state.get("current_p0_state") or "").strip()
    audit_posture_raw = str(runtime_audit.get("posture_state") or runtime_audit.get("current_state") or "").strip()
    current_posture = normalize_claim_state(current_posture_raw)
    audit_posture = normalize_claim_state(audit_posture_raw)
    current_branch = str(current_state.get("branch_ref") or current_state.get("branch") or "").strip()
    audit_branch = str(runtime_audit.get("branch_ref") or runtime_audit.get("branch") or "").strip()
    current_head = str(current_state.get("validated_head_sha") or current_state.get("head") or "").strip()
    audit_head = str(runtime_audit.get("validated_head_sha") or runtime_audit.get("head") or "").strip()
    live_branch = str(live_validation_index.get("branch_ref", "")).strip()
    live_head = str((live_validation_index.get("worktree") or {}).get("head_sha", "")).strip()
    expected_subject_head = str((live_validation_index.get("worktree") or {}).get("validated_subject_head_sha", "")).strip() or live_head
    carrier_head = str((live_validation_index.get("worktree") or {}).get("publication_carrier_head_sha", "")).strip()
    head_relation = str((live_validation_index.get("worktree") or {}).get("head_relation", "")).strip() or "HEAD_IS_SUBJECT"
    live_state = derive_live_validation_state(live_validation_index)

    if current_posture != audit_posture:
        raise RuntimeError("FAIL_CLOSED: current_state_receipt and runtime_closure_audit posture_state disagree")
    if current_posture not in ALLOWED_POSTURES:
        raise RuntimeError(f"FAIL_CLOSED: posture_state not allowed: {current_posture}")
    if current_branch != audit_branch:
        raise RuntimeError("FAIL_CLOSED: posture receipts disagree on branch_ref")
    if current_head != audit_head:
        raise RuntimeError("FAIL_CLOSED: posture receipts disagree on validated_head_sha")
    if current_branch != live_branch:
        raise RuntimeError("FAIL_CLOSED: posture receipts disagree with live branch_ref")
    if current_head != expected_subject_head:
        raise RuntimeError("FAIL_CLOSED: posture receipts disagree with expected validated subject head")
    if head_relation == "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT" and carrier_head:
        if str(current_state.get("publication_carrier_head_sha", "")).strip() != live_head:
            raise RuntimeError("FAIL_CLOSED: current_state_receipt publication_carrier_head_sha does not match live head")
        if str(runtime_audit.get("publication_carrier_head_sha", "")).strip() != live_head:
            raise RuntimeError("FAIL_CLOSED: runtime_closure_audit publication_carrier_head_sha does not match live head")

    if str(expected_posture).strip() and current_posture != str(expected_posture).strip():
        raise RuntimeError(f"FAIL_CLOSED: current_state_receipt posture_state={current_posture!r} expected={expected_posture!r}")

    allowed_states = {live_state}
    if live_state == CANONICAL_READY_FOR_REEARNED_GREEN:
        allowed_states.add(TRUTHFUL_GREEN)
    if current_posture not in allowed_states:
        raise RuntimeError(
            f"FAIL_CLOSED: posture_state={current_posture!r} not admissible for live_validation_state={live_state!r}"
        )

    preserved = _verify_preserved_receipts(root)
    alias_truth = _verify_alias_truth(manifest=manifest, aliases=aliases)
    one_button = _verify_one_button_state(
        root=root,
        report_root_rel=report_root_rel,
        posture_state=current_posture,
        live_head=current_head,
        branch_ref=current_branch,
    )

    expected_release = {
        "TRUTH_DEFECTS_PRESENT": "NO_GO_TRUTH_DEFECTS_PRESENT",
        "CANONICAL_VALIDATED_DIRTY_WORKTREE": "HOLD_DIRTY_WORKTREE",
        CANONICAL_READY_FOR_REEARNED_GREEN: "HOLD_CANONICAL_READY_FOR_REEARNED_GREEN",
        TRUTHFUL_GREEN: "GO_PRESS_BUTTON_PRODUCTION_ELIGIBLE",
    }[current_posture]
    release_decision = str(current_state.get("current_release_decision", "")).strip()
    audit_release = str(runtime_audit.get("release_decision", "")).strip()
    if release_decision != expected_release:
        raise RuntimeError(
            f"FAIL_CLOSED: current_state_receipt current_release_decision={release_decision!r} expected={expected_release!r}"
        )
    if audit_release != expected_release:
        raise RuntimeError(f"FAIL_CLOSED: runtime_closure_audit release_decision={audit_release!r} expected={expected_release!r}")

    active_stop_gates = current_state.get("active_stop_gates", [])
    blocking_groups = runtime_audit.get("blocking_groups", [])
    current_has_gates = isinstance(active_stop_gates, list) and bool(active_stop_gates)
    audit_has_gates = isinstance(blocking_groups, list) and bool(blocking_groups)
    if current_posture == TRUTHFUL_GREEN:
        if current_has_gates:
            raise RuntimeError("FAIL_CLOSED: truthful green current_state_receipt cannot report active stop gates")
        if audit_has_gates:
            raise RuntimeError("FAIL_CLOSED: truthful green runtime_closure_audit cannot report blocking groups")
    else:
        if not current_has_gates:
            raise RuntimeError("FAIL_CLOSED: non-green current_state_receipt must report active stop gates")
        if not audit_has_gates:
            raise RuntimeError("FAIL_CLOSED: non-green runtime_closure_audit must report blocking groups")

    return {
        "schema_id": "kt.operator.posture_consistency_receipt.v1",
        "status": "PASS",
        "posture_state": current_posture,
        "live_validation_state": live_state,
        "branch_ref": current_branch,
        "validated_head_sha": current_head,
        "preserved_branch_closure": preserved,
        "alias_truth": alias_truth,
        "one_button_state": one_button,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Verify final green posture consistency.")
    ap.add_argument("--expected-posture", default="")
    ap.add_argument("--live-validation-index", default=f"{DEFAULT_REPORT_ROOT_REL}/live_validation_index.json")
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--out", default=f"{DEFAULT_REPORT_ROOT_REL}/posture_consistency_receipt.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    out_path = Path(str(args.out)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = verify_posture(
            root=root,
            expected_posture=str(args.expected_posture),
            live_validation_index_rel=str(args.live_validation_index),
            report_root_rel=str(args.report_root),
        )
        write_json_stable(out_path, report)
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        report = {
            "schema_id": "kt.operator.posture_consistency_receipt.v1",
            "status": "FAIL",
            "message": str(exc),
            "expected_posture": str(args.expected_posture),
        }
        write_json_stable(out_path, report)
        print(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
