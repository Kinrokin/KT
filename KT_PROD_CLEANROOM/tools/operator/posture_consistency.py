from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root


ALLOWED_BRANCH_POSTURES = {
    "P0_GREEN_FULL_CANDIDATE_ON_BRANCH",
    "P0_GREEN_FULL_BRANCH_CONFIRMED_PENDING_MAIN_PROMOTION",
    "P0_GREEN_FULL_ENGINEERING_COMPLETE_PENDING_PLATFORM_ENFORCEMENT",
    "P0_GREEN_FULL_MAINLINE",
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


def _verify_real_path_matrix(matrix: Dict[str, Any]) -> Dict[str, Any]:
    rows = matrix.get("rows")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("FAIL_CLOSED: real_path_attachment_matrix rows missing")
    program_ids = {str(row.get("program_id", "")).strip() for row in rows if isinstance(row, dict)}
    required = {"program.certify.canonical_hmac", "program.hat_demo", "program.red_assault.serious_v1"}
    missing = sorted(x for x in required if x not in program_ids)
    safe_run_ok = any(bool(row.get("safe_run_enforced")) for row in rows if isinstance(row, dict))
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: real_path_attachment_matrix missing targets: {', '.join(missing)}")
    if not safe_run_ok:
        raise RuntimeError("FAIL_CLOSED: real_path_attachment_matrix missing safe-run enforced row")
    return {
        "status": "PASS",
        "program_ids": sorted(program_ids),
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
    if str(ci.get("status", "")).strip() != "WARN_ONLY_LIVE":
        raise RuntimeError("FAIL_CLOSED: ci_gate_promotion_receipt must be WARN_ONLY_LIVE before mainline promotion")
    checks.append({"artifact": "ci_gate_promotion_receipt.json", "status": "WARN_ONLY_LIVE"})

    return {"status": "PASS", "checks": checks}


def _verify_one_button_state(*, root: Path, expected_posture: str) -> Dict[str, Any]:
    preflight = _load_required(root, "KT_PROD_CLEANROOM/reports/one_button_preflight_receipt.json")
    production = _load_required(root, "KT_PROD_CLEANROOM/reports/one_button_production_receipt.json")
    branch_protection = _load_required(root, "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json")

    checks: List[Dict[str, Any]] = []
    preflight_status = str(preflight.get("status", "")).strip()
    production_status = str(production.get("status", "")).strip()
    branch_status = str(branch_protection.get("status", "")).strip()

    if expected_posture in {"P0_GREEN_FULL_ENGINEERING_COMPLETE_PENDING_PLATFORM_ENFORCEMENT", "P0_GREEN_FULL_MAINLINE"}:
        if preflight_status != "PASS":
            raise RuntimeError("FAIL_CLOSED: one_button_preflight_receipt must be PASS for engineering-complete posture")
        if production_status != "PASS":
            raise RuntimeError("FAIL_CLOSED: one_button_production_receipt must be PASS for engineering-complete posture")
        checks.append({"artifact": "one_button_preflight_receipt.json", "status": "PASS"})
        checks.append({"artifact": "one_button_production_receipt.json", "status": "PASS"})

    if expected_posture == "P0_GREEN_FULL_ENGINEERING_COMPLETE_PENDING_PLATFORM_ENFORCEMENT":
        if branch_status == "PASS":
            raise RuntimeError("FAIL_CLOSED: engineering-complete pending platform posture cannot coexist with active branch protection")
        checks.append({"artifact": "main_branch_protection_receipt.json", "status": branch_status})

    if expected_posture == "P0_GREEN_FULL_MAINLINE":
        if branch_status != "PASS":
            raise RuntimeError("FAIL_CLOSED: mainline green posture requires main_branch_protection_receipt PASS")
        checks.append({"artifact": "main_branch_protection_receipt.json", "status": "PASS"})

    return {"status": "PASS", "checks": checks}


def verify_posture(*, root: Path, expected_posture: str) -> Dict[str, Any]:
    current_state = _load_required(root, "KT_PROD_CLEANROOM/reports/current_state_receipt.json")
    runtime_audit = _load_required(root, "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json")
    manifest = _load_required(root, "KT_PROD_CLEANROOM/governance/governance_manifest.json")
    aliases = _load_required(root, "KT_PROD_CLEANROOM/governance/governance_aliases.json")

    current_posture = str(current_state.get("posture_state") or current_state.get("current_p0_state") or "").strip()
    audit_posture = str(runtime_audit.get("posture_state") or runtime_audit.get("current_state") or "").strip()
    current_branch = str(current_state.get("branch_ref") or current_state.get("branch") or "").strip()
    audit_branch = str(runtime_audit.get("branch_ref") or runtime_audit.get("branch") or "").strip()
    current_head = str(current_state.get("validated_head_sha") or current_state.get("head") or "").strip()
    audit_head = str(runtime_audit.get("validated_head_sha") or runtime_audit.get("head") or "").strip()

    if current_posture != expected_posture:
        raise RuntimeError(f"FAIL_CLOSED: current_state_receipt posture_state={current_posture!r} expected={expected_posture!r}")
    if audit_posture != expected_posture:
        raise RuntimeError(f"FAIL_CLOSED: runtime_closure_audit posture_state={audit_posture!r} expected={expected_posture!r}")
    if current_posture not in ALLOWED_BRANCH_POSTURES:
        raise RuntimeError(f"FAIL_CLOSED: posture_state not allowed on branch: {current_posture}")
    if current_branch != audit_branch:
        raise RuntimeError("FAIL_CLOSED: posture receipts disagree on branch_ref")
    if current_head != audit_head:
        raise RuntimeError("FAIL_CLOSED: posture receipts disagree on validated_head_sha")

    preserved = _verify_preserved_receipts(root)
    alias_truth = _verify_alias_truth(manifest=manifest, aliases=aliases)
    one_button = _verify_one_button_state(root=root, expected_posture=expected_posture)

    active_stop_gates = current_state.get("active_stop_gates", [])
    if isinstance(active_stop_gates, list) and active_stop_gates:
        raise RuntimeError("FAIL_CLOSED: current_state_receipt still reports active stop gates")

    blocking_groups = runtime_audit.get("blocking_groups", [])
    if isinstance(blocking_groups, list) and blocking_groups:
        raise RuntimeError("FAIL_CLOSED: runtime_closure_audit still reports blocking groups")

    return {
        "schema_id": "kt.operator.posture_consistency_receipt.v1",
        "status": "PASS",
        "posture_state": expected_posture,
        "branch_ref": current_branch,
        "validated_head_sha": current_head,
        "preserved_branch_closure": preserved,
        "alias_truth": alias_truth,
        "one_button_state": one_button,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Verify final green posture consistency.")
    ap.add_argument("--expected-posture", default="P0_GREEN_FULL_BRANCH_CONFIRMED_PENDING_MAIN_PROMOTION")
    ap.add_argument("--out", default="KT_PROD_CLEANROOM/reports/posture_consistency_receipt.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    out_path = Path(str(args.out)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = verify_posture(root=root, expected_posture=str(args.expected_posture))
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        report = {
            "schema_id": "kt.operator.posture_consistency_receipt.v1",
            "status": "FAIL",
            "message": str(exc),
            "expected_posture": str(args.expected_posture),
        }
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
