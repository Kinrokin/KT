"""Emit current dependency evidence externally without rewriting historical reports.

The checked-in dependency reports are retained as historical evidence.  This
operator creates a new, single-use external evidence root for the current
checkout, validates the three emitted artifacts against the same source head,
and records the historical bytes it deliberately left untouched.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from typing import Any, Dict, Optional, Sequence

from tools.operator.dependency_inventory_emit import emit_dependency_reports, resolve_external_report_root
from tools.operator.dependency_inventory_validate import build_dependency_inventory_validation_report
from tools.operator.titanium_common import file_sha256, repo_root, write_json_worm


HISTORICAL_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
HISTORICAL_FILENAMES = (
    "dependency_inventory.json",
    "python_environment_manifest.json",
    "sbom_cyclonedx.json",
    "dependency_inventory_validation_receipt.json",
)
CURRENT_EVIDENCE_STATUS = "PASS_CURRENT_EXTERNAL_DEPENDENCY_EVIDENCE__HISTORICAL_RECEIPTS_RETAINED"
HOLD_STATUS = "HOLD_CURRENT_EXTERNAL_DEPENDENCY_EVIDENCE"


def _historical_manifest(root: Path) -> Dict[str, Dict[str, str]]:
    raw_root = root / HISTORICAL_REPORT_ROOT_REL
    probe = raw_root
    while True:
        if probe.is_symlink():
            raise RuntimeError(f"HISTORICAL_DEPENDENCY_REPORT_SYMLINK_FORBIDDEN: {probe}")
        parent = probe.parent
        if parent == probe:
            break
        probe = parent
    report_root = raw_root.resolve()
    result: Dict[str, Dict[str, str]] = {}
    for filename in HISTORICAL_FILENAMES:
        path = report_root / filename
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"HISTORICAL_DEPENDENCY_REPORT_MISSING: {path}")
        result[filename] = {
            "path": f"{HISTORICAL_REPORT_ROOT_REL}/{filename}",
            "sha256": file_sha256(path),
        }
    return result


def _external_manifest(report_root: Path) -> Dict[str, Dict[str, str]]:
    result: Dict[str, Dict[str, str]] = {}
    for filename in (*HISTORICAL_FILENAMES[:3], "dependency_inventory_validation_receipt.json"):
        path = report_root / filename
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"CURRENT_DEPENDENCY_EVIDENCE_MISSING: {path}")
        result[filename] = {"path": str(path), "sha256": file_sha256(path)}
    return result


def _require_clean_git_head(root: Path) -> str:
    """Refuse evidence from bytes that cannot be identified by the recorded head."""
    try:
        status = subprocess.run(
            ("git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        head = subprocess.run(
            ("git", "-C", str(root), "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("DEPENDENCY_SOURCE_HEAD_UNAVAILABLE") from exc
    if status.strip():
        raise RuntimeError("DEPENDENCY_SOURCE_WORKTREE_NOT_CLEAN")
    return head


def reconcile_dependency_evidence(*, root: Path, report_root: str | Path) -> Dict[str, Any]:
    """Create and validate a current external dependency-evidence bundle.

    The destination must be a new directory outside ``root``.  No checked-in
    report is changed, and a before/after hash manifest makes that boundary
    independently checkable.
    """
    destination = resolve_external_report_root(root=root, report_root=report_root)
    clean_head = _require_clean_git_head(root)
    historical_before = _historical_manifest(root)
    reports = emit_dependency_reports(root=root, report_root=destination)
    validation = build_dependency_inventory_validation_report(root=root, report_root=destination)
    write_json_worm(
        destination / "dependency_inventory_validation_receipt.json",
        validation,
        label="dependency_inventory_validation_receipt.json",
    )
    historical_after = _historical_manifest(root)
    historical_unchanged = historical_before == historical_after
    current_head = str(reports["inventory"].get("pinned_head_sha", ""))
    head_is_git_bound = reports["inventory"].get("head_source") == "git" and current_head == clean_head
    status = CURRENT_EVIDENCE_STATUS if (
        validation.get("status") == "PASS" and historical_unchanged and head_is_git_bound
    ) else HOLD_STATUS
    receipt: Dict[str, Any] = {
        "schema_id": "kt.operator.dependency_inventory_reconciliation_receipt.v1",
        "status": status,
        "current_head": current_head,
        "current_head_git_bound": head_is_git_bound,
        "source_worktree_clean": True,
        "validation_status": validation.get("status"),
        "historical_reports_retained": historical_unchanged,
        "historical_report_manifest_before": historical_before,
        "historical_report_manifest_after": historical_after,
        "current_external_report_manifest": _external_manifest(destination),
        "claim_scope": (
            "Current-head static Python-import inventory, installed-distribution mapping, "
            "and CycloneDX preview only; no runtime, provider, model, training, or release claim."
        ),
        "execution_boundary": {
            "network_accessed": False,
            "model_inference_invoked": False,
            "training_invoked": False,
            "provider_calls_invoked": False,
        },
    }
    write_json_worm(
        destination / "dependency_inventory_reconciliation_receipt.json",
        receipt,
        label="dependency_inventory_reconciliation_receipt.json",
    )
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit and validate current dependency evidence outside the repository."
    )
    parser.add_argument(
        "--report-root",
        required=True,
        help="new absolute external evidence root; repository paths are rejected",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        receipt = reconcile_dependency_evidence(root=repo_root(), report_root=args.report_root)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": HOLD_STATUS, "failure": str(exc)}, sort_keys=True, ensure_ascii=True))
        return 2
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    return 0 if receipt["status"] == CURRENT_EVIDENCE_STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
