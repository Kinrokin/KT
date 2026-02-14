from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.verification.fl3_canonical import sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.replay_script_generator import render_replay_ps1, render_replay_sh
from tools.verification.run_protocol_generator import verify_run_protocol_pair
from tools.verification.worm_write import enforce_all_or_none_exist, write_text_worm


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read JSON (fail-closed): {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {name}: {path.as_posix()}")
    return obj


def _read_law_bundle_hash(path: Path) -> str:
    h = path.read_text(encoding="utf-8").strip()
    if len(h) != 64:
        raise FL3ValidationError("law_bundle_hash.txt missing/invalid (fail-closed)")
    return h


def _mismatch(field: str, expected: Any, actual: Any) -> Dict[str, str]:
    return {"field": str(field), "expected": str(expected), "actual": str(actual)}


def build_governance_twin_manifest(
    *, run_protocol: Dict[str, Any], law_bundle_hash: str, time_contract: Dict[str, Any]
) -> Dict[str, Any]:
    created_at = str(run_protocol.get("created_at", "")).strip() or str(run_protocol.get("timestamp_utc", "")).strip()
    if not created_at:
        created_at = "1970-01-01T00:00:00Z"

    obj: Dict[str, Any] = {
        "schema_id": "kt.governance_twin_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.governance_twin_manifest.v1.json"),
        "twin_manifest_id": "",
        "run_id": str(run_protocol.get("run_id", "")),
        "lane_id": str(run_protocol.get("lane_id", "")),
        "law_bundle_hash": str(law_bundle_hash),
        "time_contract_id": str(time_contract.get("time_contract_id", "")),
        "run_protocol_id": str(run_protocol.get("run_protocol_id", "")),
        "run_protocol_json_hash": str(run_protocol.get("run_protocol_json_hash", "")),
        "bundle_root_hash": str(run_protocol.get("bundle_root_hash", "")),
        "created_at": created_at,
        "notes": None,
    }
    obj["twin_manifest_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "twin_manifest_id"})
    validate_schema_bound_object(obj)
    return obj


def build_governance_twin_report(
    *, manifest: Dict[str, Any], mismatches: List[Dict[str, str]], created_at: str
) -> Dict[str, Any]:
    status = "PASS" if not mismatches else "FAIL_CLOSED"
    reason_codes: List[str] = []
    if status != "PASS":
        reason_codes = ["GOVERNANCE_TWIN_MISMATCH"]

    obj: Dict[str, Any] = {
        "schema_id": "kt.governance_twin_report.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.governance_twin_report.v1.json"),
        "twin_report_id": "",
        "twin_manifest_id": str(manifest.get("twin_manifest_id", "")),
        "run_id": str(manifest.get("run_id", "")),
        "lane_id": str(manifest.get("lane_id", "")),
        "status": status,
        "reason_codes": sorted(reason_codes),
        "mismatches": sorted(mismatches, key=lambda m: str(m.get("field", ""))),
        "created_at": created_at,
        "notes": None,
    }
    obj["twin_report_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "twin_report_id"})
    validate_schema_bound_object(obj)
    return obj


def run_governance_twin(
    *, evidence_dir: Path
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    evidence_dir = evidence_dir.resolve()

    run_protocol = verify_run_protocol_pair(
        json_path=evidence_dir / "run_protocol.json",
        md_path=evidence_dir / "RUN_PROTOCOL.md",
    )

    created_at = str(run_protocol.get("created_at", "")).strip() or "1970-01-01T00:00:00Z"
    law_bundle_hash = _read_law_bundle_hash(evidence_dir / "law_bundle_hash.txt")
    time_contract = _read_json_dict(evidence_dir / "time_contract.json", name="time_contract.json")
    validate_schema_bound_object(time_contract)

    # Cross-artifact consistency checks.
    mismatches: List[Dict[str, str]] = []

    secret_report = _read_json_dict(evidence_dir / "secret_scan_report.json", name="secret_scan_report.json")
    secret_summary = _read_json_dict(evidence_dir / "secret_scan_summary.json", name="secret_scan_summary.json")
    validate_schema_bound_object(secret_report)
    validate_schema_bound_object(secret_summary)
    if str(secret_summary.get("report_hash")) != str(secret_report.get("report_hash")):
        mismatches.append(_mismatch("secret_scan_summary.report_hash", secret_report.get("report_hash"), secret_summary.get("report_hash")))
    if str(secret_summary.get("status")) != str(secret_report.get("status")):
        mismatches.append(_mismatch("secret_scan_summary.status", secret_report.get("status"), secret_summary.get("status")))
    if str(run_protocol.get("secret_scan_result")) != str(secret_report.get("status")):
        mismatches.append(_mismatch("run_protocol.secret_scan_result", secret_report.get("status"), run_protocol.get("secret_scan_result")))

    replay_receipt = _read_json_dict(evidence_dir / "replay_receipt.json", name="replay_receipt.json")
    validate_schema_bound_object(replay_receipt)
    if str(replay_receipt.get("replay_command")) != str(run_protocol.get("replay_command")):
        mismatches.append(_mismatch("replay_receipt.replay_command", run_protocol.get("replay_command"), replay_receipt.get("replay_command")))
    if str(replay_receipt.get("replay_script_hash")) != str(run_protocol.get("replay_script_hash")):
        mismatches.append(_mismatch("replay_script_hash", run_protocol.get("replay_script_hash"), replay_receipt.get("replay_script_hash")))

    sh_text = (evidence_dir / "replay.sh").read_text(encoding="utf-8")
    ps1_text = (evidence_dir / "replay.ps1").read_text(encoding="utf-8")
    if sh_text != render_replay_sh(replay_command=str(run_protocol.get("replay_command"))):
        mismatches.append(_mismatch("replay.sh", "<canonical>", "<mismatch>"))
    if ps1_text != render_replay_ps1(replay_command=str(run_protocol.get("replay_command"))):
        mismatches.append(_mismatch("replay.ps1", "<canonical>", "<mismatch>"))
    combined = sha256_hex_of_obj(
        {"replay_ps1_sha256": sha256_text(ps1_text), "replay_sh_sha256": sha256_text(sh_text)}, drop_keys=set()
    )
    if str(run_protocol.get("replay_script_hash")) != combined:
        mismatches.append(_mismatch("run_protocol.replay_script_hash", combined, run_protocol.get("replay_script_hash")))

    # Bind job_dir root hash.
    hash_manifest = _read_json_dict(evidence_dir / "job_dir" / "hash_manifest.json", name="job_dir/hash_manifest.json")
    validate_schema_bound_object(hash_manifest)
    if str(run_protocol.get("bundle_root_hash")) != str(hash_manifest.get("root_hash")):
        mismatches.append(_mismatch("run_protocol.bundle_root_hash", hash_manifest.get("root_hash"), run_protocol.get("bundle_root_hash")))

    manifest = build_governance_twin_manifest(run_protocol=run_protocol, law_bundle_hash=law_bundle_hash, time_contract=time_contract)
    report = build_governance_twin_report(manifest=manifest, mismatches=mismatches, created_at=created_at)
    return manifest, report


def write_governance_twin_artifacts(*, out_dir: Path, manifest: Dict[str, Any], report: Dict[str, Any]) -> Tuple[Path, Path]:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    man_path = out_dir / "governance_twin_manifest.json"
    rep_path = out_dir / "governance_twin_report.json"
    enforce_all_or_none_exist([man_path, rep_path], label="governance twin artifacts")
    write_text_worm(path=man_path, text=json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label="governance_twin_manifest.json")
    write_text_worm(path=rep_path, text=json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label="governance_twin_report.json")
    return man_path, rep_path


def run_governance_twin_and_write(*, evidence_dir: Path, out_dir: Optional[Path] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    manifest, report = run_governance_twin(evidence_dir=evidence_dir)
    write_governance_twin_artifacts(out_dir=out_dir or evidence_dir, manifest=manifest, report=report)
    return manifest, report


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run governance twin checks (mirror) and emit schema-bound artifacts.")
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out-dir", default=None)
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    evidence_dir = Path(args.evidence_dir)
    out_dir = Path(args.out_dir) if args.out_dir else None
    _manifest, report = run_governance_twin_and_write(evidence_dir=evidence_dir, out_dir=out_dir)
    status = str(report.get("status", "FAIL_CLOSED"))
    print(json.dumps({"status": status, "twin_report_id": report.get("twin_report_id")}, sort_keys=True, ensure_ascii=True))
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
