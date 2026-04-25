from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    write_json_stable(path, payload)


def _resolve_run_root(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _read_required_text(path: Path) -> str:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required text artifact: {path.as_posix()}")
    return path.read_text(encoding="utf-8", errors="replace").strip()


def _extract_head_from_verdict(verdict: str) -> str:
    match = re.search(r"\bhead=([0-9a-f]{7,64})\b", verdict)
    return str(match.group(1)).strip() if match else ""


def _critical_failures(index: Dict[str, Any]) -> list[Dict[str, Any]]:
    rows = index.get("checks") if isinstance(index.get("checks"), list) else []
    out: list[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if not bool(row.get("critical")):
            continue
        status = str(row.get("status", "")).strip().upper()
        if status in {"PASS", "SKIP"}:
            continue
        out.append(row)
    return out


def _cleanroom_suite_admissible(index: Dict[str, Any]) -> tuple[bool, str]:
    rows = index.get("checks") if isinstance(index.get("checks"), list) else []
    suite_row: Optional[Dict[str, Any]] = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("check_id", "")).strip() == "current_worktree_cleanroom_suite":
            suite_row = row
            break

    if suite_row is None:
        return False, "MISSING"

    suite_status = str(suite_row.get("status", "")).strip().upper() or "UNKNOWN"
    if suite_status == "PASS":
        return True, "PASS"

    failures = _critical_failures(index)
    non_dirty_failures = [row for row in failures if not bool(row.get("dirty_sensitive"))]
    if non_dirty_failures:
        return False, suite_status

    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    subject_dirty = bool(worktree.get("subject_git_dirty")) if "subject_git_dirty" in worktree else bool(worktree.get("git_dirty"))
    publication_carrier_dirty = bool(worktree.get("publication_carrier_dirty"))
    carrier_only_dirty = publication_carrier_dirty and not subject_dirty
    if bool(suite_row.get("dirty_sensitive")) and suite_status == "FAIL" and carrier_only_dirty:
        return True, "PASS_CARRIER_ONLY_DIRTY"

    return False, suite_status


def mint_one_button_receipts(*, safe_run_root: Path, live_validation_index: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    safe_run_verdict = _read_required_text(safe_run_root / "verdict.txt")
    safe_run_preflight = _load_required(safe_run_root / "reports" / "operator_preflight.json")
    safe_run_head = _read_required_text(safe_run_root / "git_head.txt")
    program_run = (safe_run_root / "program_run").resolve()
    nested_manifest = _load_required(program_run / "delivery" / "delivery_manifest.json")
    nested_verdict = _read_required_text(program_run / "verdict.txt")
    nested_run_head = _read_required_text(program_run / "git_head.txt")

    live_head = str((live_validation_index.get("worktree") or {}).get("head_sha", "")).strip()
    validated_subject_head = str((live_validation_index.get("worktree") or {}).get("validated_subject_head_sha", "")).strip() or live_head
    publication_carrier_head = str((live_validation_index.get("worktree") or {}).get("publication_carrier_head_sha", "")).strip()
    head_relation = str((live_validation_index.get("worktree") or {}).get("head_relation", "")).strip() or "HEAD_IS_SUBJECT"
    branch_ref = str(live_validation_index.get("branch_ref", "")).strip()
    generated_utc = str(live_validation_index.get("generated_utc", "")).strip() or utc_now_iso_z()
    suite_admissible, suite_status = _cleanroom_suite_admissible(live_validation_index)

    nested_verdict_head = _extract_head_from_verdict(nested_verdict)
    head_lineage_match = bool(
        live_head
        and safe_run_head == live_head
        and nested_run_head == live_head
        and nested_verdict_head == live_head
    )

    safe_run_ok = (
        safe_run_preflight.get("status") == "PASS"
        and safe_run_verdict.startswith("KT_SAFE_RUN_PASS")
        and safe_run_head == live_head
    )
    nested_ok = nested_verdict.startswith("KT_CERTIFY_PASS") and nested_run_head == live_head and nested_verdict_head == live_head

    preflight = {
        "schema_id": "kt.one_button_preflight_receipt.v2",
        "created_utc": generated_utc,
        "status": "PASS" if safe_run_ok and suite_admissible and head_lineage_match else "FAIL",
        "validated_head_sha": validated_subject_head,
        "publication_carrier_head_sha": publication_carrier_head,
        "head_relation": head_relation,
        "branch_ref": branch_ref,
        "canonical_candidate_run_root": safe_run_root.as_posix(),
        "canonical_candidate_program_run_root": program_run.as_posix(),
        "safe_run_verdict": safe_run_verdict,
        "safe_run_head_sha": safe_run_head,
        "nested_run_head_sha": nested_run_head,
        "nested_verdict_head_sha": nested_verdict_head,
        "head_lineage_match": head_lineage_match,
        "operator_preflight_status": str(safe_run_preflight.get("status", "")).strip(),
        "current_worktree_cleanroom_suite_status": suite_status,
        "current_worktree_cleanroom_suite_admissible": suite_admissible,
        "delivery_manifest": (program_run / "delivery" / "delivery_manifest.json").as_posix(),
        "next_action": (
            "canonical_hmac safe-run is current-head admissible"
            if safe_run_ok and suite_admissible and head_lineage_match
            else "repair safe-run preflight, current-worktree cleanroom suite, or safe-run head lineage"
        ),
    }

    production = {
        "schema_id": "kt.one_button_production_receipt.v2",
        "created_utc": generated_utc,
        "status": "PASS" if safe_run_ok and nested_ok and head_lineage_match else "FAIL",
        "validated_head_sha": validated_subject_head,
        "publication_carrier_head_sha": publication_carrier_head,
        "head_relation": head_relation,
        "branch_ref": branch_ref,
        "frozen_command": "python -m tools.operator.kt_cli --profile v1 safe-run --assurance-mode production --program program.certify.canonical_hmac --config {}",
        "production_run": {
            "safe_run_root": safe_run_root.as_posix(),
            "safe_run_verdict": safe_run_verdict,
            "safe_run_head_sha": safe_run_head,
            "nested_run_root": program_run.as_posix(),
            "nested_run_head_sha": nested_run_head,
            "nested_verdict": nested_verdict,
            "nested_verdict_head_sha": nested_verdict_head,
            "delivery_manifest": (program_run / "delivery" / "delivery_manifest.json").as_posix(),
            "delivery_zip_path": str(nested_manifest.get("zip_path", "")).strip(),
            "delivery_zip_sha256": str(nested_manifest.get("zip_sha256", "")).strip(),
            "program_id": "program.certify.canonical_hmac",
            "safe_run_enforced": True,
            "head_lineage_match": head_lineage_match,
        },
        "next_action": (
            "truth surfaces may claim production eligible on this head"
            if safe_run_ok and nested_ok and head_lineage_match
            else "repair nested canonical_hmac production path or safe-run head lineage"
        ),
    }
    return {"preflight": preflight, "production": production}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Mint current-head one-button receipts from a safe-run canonical_hmac execution.")
    ap.add_argument("--safe-run-root", required=True)
    ap.add_argument("--live-validation-index", default="KT_PROD_CLEANROOM/reports/live_validation_index.json")
    ap.add_argument("--out-dir", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    safe_run_root = _resolve_run_root(root, str(args.safe_run_root))
    index_path = Path(str(args.live_validation_index)).expanduser()
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    out_dir = Path(str(args.out_dir)).expanduser()
    if not out_dir.is_absolute():
        out_dir = (root / out_dir).resolve()

    index = _load_required(index_path)
    receipts = mint_one_button_receipts(safe_run_root=safe_run_root, live_validation_index=index)
    _write_json(out_dir / "one_button_preflight_receipt.json", receipts["preflight"])
    _write_json(out_dir / "one_button_production_receipt.json", receipts["production"])
    status = "PASS" if receipts["preflight"]["status"] == "PASS" and receipts["production"]["status"] == "PASS" else "FAIL"
    print(json.dumps({"safe_run_root": safe_run_root.as_posix(), "status": status}, sort_keys=True, ensure_ascii=True))
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
