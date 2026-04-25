from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_OUTPUT_DIR_REL = "KT_PROD_CLEANROOM/exports/c006_second_host_kit/current_head_bundle"
MANIFEST_REL = "KT_PROD_CLEANROOM/reports/c006_second_host_bundle_manifest.json"
KIT_INDEX_REL = "KT_PROD_CLEANROOM/reports/c006_second_host_kit.json"
HEARTBEAT_REL = "KT_PROD_CLEANROOM/reports/c006_deferral_heartbeat.json"
DEFERRED_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/deferred_blockers.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/second_host_kit_hardening_receipt.json"
STAGED_REFS = [
    "KT_PROD_CLEANROOM/reports/post_wave5_c006_friendly_host_handoff_pack.json",
    "KT_PROD_CLEANROOM/reports/post_wave5_c006_second_host_submission_template.json",
    "KT_PROD_CLEANROOM/reports/post_wave5_c006_second_host_execution_receipt.json",
    "KT_PROD_CLEANROOM/reports/deferred_blockers.json",
    "KT_PROD_CLEANROOM/reports/c006_deferral_heartbeat.json",
    "KT_PROD_CLEANROOM/reports/kt_independent_replay_recipe.md",
    "KT_PROD_CLEANROOM/docs/operator/C006_SECOND_HOST_RUNBOOK.md",
    "KT_PROD_CLEANROOM/docs/operator/C006_IMPORT_CHECKLIST.md",
    "KT_PROD_CLEANROOM/docs/operator/C006_VALIDATOR_RERUN_CHECKLIST.md",
    "KT_PROD_CLEANROOM/docs/operator/C006_RETURN_FILE_PLACEMENT_CHECKLIST.md",
]


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_bundle_manifest(*, root: Path, output_dir: Path) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for ref in STAGED_REFS:
        src = (root / ref).resolve()
        if not src.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing staged ref for C006 bundle: {ref}")
        rows.append(
            {
                "source_ref": ref,
                "bundle_ref": ref,
                "sha256": _sha256(src),
                "size_bytes": src.stat().st_size,
            }
        )
    return {
        "schema_id": "kt.c006.second_host_bundle_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": _git_head(root),
        "bundle_class": "READY_PENDING_HARDWARE",
        "output_dir": output_dir.as_posix(),
        "bundle_rows": rows,
        "claim_boundary": "This bundle is preparation only. It does not earn E2 or close C006 until a real second-host return is imported and validated.",
    }


def stage_bundle(*, root: Path, output_dir: Path) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for ref in STAGED_REFS:
        src = (root / ref).resolve()
        dest = (output_dir / ref).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    manifest = build_bundle_manifest(root=root, output_dir=output_dir)
    write_json_stable((output_dir / MANIFEST_REL).resolve(), manifest)
    return manifest


def build_kit_hardening_receipt(*, root: Path, output_dir: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    heartbeat = load_json((root / HEARTBEAT_REL).resolve())
    deferred = load_json((root / DEFERRED_BLOCKERS_REL).resolve())
    kit_index = load_json((root / KIT_INDEX_REL).resolve()) if (root / KIT_INDEX_REL).exists() else {}
    deferred_rows = deferred.get("deferred", [])
    c006_row = next(
        (
            row
            for row in deferred_rows
            if isinstance(row, dict) and str(row.get("blocker_id", "")).strip() == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
        ),
        {},
    )
    return {
        "schema_id": "kt.c006.second_host_kit_hardening_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS"
        if str(manifest.get("status", "")).strip() == "PASS" and str(heartbeat.get("status", "")).strip() == "PASS" and bool(c006_row)
        else "FAIL",
        "kit_status": "READY_STAGED_PENDING_HARDWARE",
        "bundle_manifest_ref": MANIFEST_REL,
        "bundle_output_dir": output_dir.as_posix(),
        "bundle_file_count": len(manifest.get("bundle_rows", [])),
        "blocker_id": str(c006_row.get("blocker_id", "")).strip(),
        "deferral_status": str(c006_row.get("status", "")).strip(),
        "return_import_path": str(c006_row.get("reentry_condition", {}).get("return_import_path", "")).strip(),
        "validator_commands": list(kit_index.get("validator_commands", []))
        if isinstance(kit_index.get("validator_commands"), list)
        else [
            "python -m tools.operator.post_wave5_c006_second_host_execute_validate",
            "python -m tools.operator.w3_externality_and_comparative_proof_validate",
            "python -m tools.operator.c006_deferral_law_validate",
            "python -m tools.operator.omega_gate",
        ],
        "source_refs": [
            HEARTBEAT_REL,
            DEFERRED_BLOCKERS_REL,
            KIT_INDEX_REL,
            MANIFEST_REL,
        ],
        "claim_boundary": "This receipt proves the second-host kit is staged and current-head bound, but it does not earn E2 until a real second-host return is imported and validated.",
        "next_lawful_move": "Keep the staged bundle current and execute it immediately when friendly second-host hardware appears.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stage the C006 second-host kit into a portable bundle directory.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    output_dir = _resolve(root, str(args.output_dir))
    manifest = stage_bundle(root=root, output_dir=output_dir)
    receipt_path = _resolve(root, str(args.receipt_output))
    receipt = build_kit_hardening_receipt(root=root, output_dir=output_dir, manifest=manifest)
    write_json_stable(receipt_path, receipt)
    summary = {
        "status": manifest["status"],
        "current_git_head": manifest["current_git_head"],
        "bundle_file_count": len(manifest["bundle_rows"]),
        "output_dir": manifest["output_dir"],
        "receipt_status": receipt["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
