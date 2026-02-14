from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_run_protocol_schema import FL3_RUN_PROTOCOL_SCHEMA_ID
from schemas.schema_files import schema_version_hash
from tools.verification.fl3_canonical import sha256_json, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import enforce_all_or_none_exist, write_text_worm


RUN_PROTOCOL_SCHEMA_FILE = "fl3/kt.run_protocol.v1.json"


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sorted_adapters(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise FL3ValidationError("active_adapters must be a non-empty list (fail-closed)")
    out: List[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise FL3ValidationError("active_adapters must contain objects (fail-closed)")
        adapter_id = str(item.get("adapter_id", "")).strip()
        adapter_hash = str(item.get("adapter_hash", "")).strip()
        if not adapter_id or not adapter_hash:
            raise FL3ValidationError("active_adapters requires adapter_id and adapter_hash (fail-closed)")
        row: Dict[str, Any] = {
            "adapter_id": adapter_id,
            "adapter_hash": adapter_hash,
        }
        profile_hash = item.get("adapter_profile_hash")
        if profile_hash is not None:
            row["adapter_profile_hash"] = str(profile_hash)
        out.append(row)
    return sorted(out, key=lambda x: (x["adapter_id"], x["adapter_hash"]))


def _sorted_dataset_entries(value: Any) -> List[Dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise FL3ValidationError("datasets must be a list when present (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            raise FL3ValidationError("datasets entries must be objects (fail-closed)")
        relpath = str(item.get("relpath", "")).strip()
        digest = str(item.get("sha256", "")).strip()
        if not relpath or not digest:
            raise FL3ValidationError("datasets entries require relpath and sha256 (fail-closed)")
        out.append({"relpath": relpath, "sha256": digest})
    return sorted(out, key=lambda x: x["relpath"])


def _sorted_laws(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise FL3ValidationError("active_laws must be a list when present (fail-closed)")
    rows = [str(x).strip() for x in value if isinstance(x, str) and str(x).strip()]
    return sorted(rows)


def render_run_protocol_markdown(protocol: Dict[str, Any]) -> str:
    adapters = _sorted_adapters(protocol.get("active_adapters", []))
    datasets = _sorted_dataset_entries(protocol.get("datasets"))
    laws = _sorted_laws(protocol.get("active_laws"))

    lines: List[str] = []
    lines.append("# KT RUN PROTOCOL")
    lines.append("")
    lines.append(f"run_protocol_id: {protocol.get('run_protocol_id', '')}")
    lines.append(f"run_id: {protocol['run_id']}")
    lines.append(f"lane_id: {protocol['lane_id']}")
    lines.append(f"timestamp_utc: {protocol['timestamp_utc']}")
    lines.append(f"determinism_mode: {protocol['determinism_mode']}")
    lines.append(f"io_guard_status: {protocol['io_guard_status']}")
    lines.append(f"secret_scan_result: {protocol['secret_scan_result']}")
    lines.append(f"base_model_id: {protocol['base_model_id']}")
    lines.append(f"execution_environment_hash: {protocol['execution_environment_hash']}")
    lines.append(f"governed_phase_start_hash: {protocol['governed_phase_start_hash']}")
    lines.append(f"bundle_root_hash: {protocol['bundle_root_hash']}")
    lines.append("")
    lines.append("## Replay")
    lines.append(protocol["replay_command"])
    lines.append("")
    lines.append("## Active Adapters")
    for adapter in adapters:
        profile = adapter.get("adapter_profile_hash")
        suffix = f" profile={profile}" if isinstance(profile, str) and profile else ""
        lines.append(f"- {adapter['adapter_id']} hash={adapter['adapter_hash']}{suffix}")
    lines.append("")
    lines.append("## Active Laws")
    if laws:
        for law in laws:
            lines.append(f"- {law}")
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("## Datasets")
    if datasets:
        for dataset in datasets:
            lines.append(f"- {dataset['relpath']} sha256={dataset['sha256']}")
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("## Notes")
    notes = protocol.get("notes")
    lines.append(str(notes) if isinstance(notes, str) and notes.strip() else "<none>")
    lines.append("")
    return "\n".join(lines)


def build_run_protocol(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise FL3ValidationError("Run protocol payload must be an object (fail-closed)")

    obj: Dict[str, Any] = dict(payload)
    obj["schema_id"] = FL3_RUN_PROTOCOL_SCHEMA_ID
    obj["schema_version_hash"] = schema_version_hash(RUN_PROTOCOL_SCHEMA_FILE)
    obj["created_at"] = str(obj.get("created_at") or _utc_now_z())
    obj["timestamp_utc"] = str(obj.get("timestamp_utc") or obj["created_at"])
    obj["lane_id"] = str(obj.get("lane_id") or "FL4_SEAL")
    obj["active_adapters"] = _sorted_adapters(obj.get("active_adapters"))
    obj["active_laws"] = _sorted_laws(obj.get("active_laws"))
    obj["datasets"] = _sorted_dataset_entries(obj.get("datasets"))
    obj["bootstrap_receipt_hash"] = obj.get("bootstrap_receipt_hash", None)
    obj["base_model_commit"] = obj.get("base_model_commit", None)
    obj["notes"] = obj.get("notes", None)
    obj["secret_scan_result"] = str(obj.get("secret_scan_result") or "PASS")

    replay_command = str(obj.get("replay_command", "")).strip()
    if not replay_command:
        raise FL3ValidationError("replay_command is required (fail-closed)")
    obj["replay_command"] = replay_command

    replay_script_hash = str(obj.get("replay_script_hash", "")).strip()
    if not replay_script_hash:
        replay_script_hash = sha256_text(replay_command)
    obj["replay_script_hash"] = replay_script_hash

    obj["run_protocol_id"] = sha256_json(
        {k: v for k, v in obj.items() if k not in {"created_at", "run_protocol_id", "run_protocol_json_hash", "run_protocol_md_hash"}}
    )
    markdown = render_run_protocol_markdown(obj)
    obj["run_protocol_md_hash"] = sha256_text(markdown)
    obj["run_protocol_json_hash"] = sha256_json({k: v for k, v in obj.items() if k != "run_protocol_json_hash"})

    validate_schema_bound_object(obj)
    return obj


def write_run_protocol_pair(*, out_dir: Path, protocol: Dict[str, Any]) -> Tuple[Path, Path]:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown = render_run_protocol_markdown(protocol)
    expected_md_hash = sha256_text(markdown)
    if protocol.get("run_protocol_md_hash") != expected_md_hash:
        raise FL3ValidationError("run_protocol_md_hash does not match canonical markdown (fail-closed)")

    json_path = out_dir / "run_protocol.json"
    md_path = out_dir / "RUN_PROTOCOL.md"
    json_text = json.dumps(protocol, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    md_text = markdown if markdown.endswith("\n") else markdown + "\n"

    enforce_all_or_none_exist([json_path, md_path], label="run_protocol artifacts")
    write_text_worm(path=json_path, text=json_text, label="run_protocol.json")
    write_text_worm(path=md_path, text=md_text, label="RUN_PROTOCOL.md")
    return json_path, md_path


def verify_run_protocol_pair(*, json_path: Path, md_path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to parse run protocol JSON (fail-closed): {json_path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError("run_protocol.json must be an object (fail-closed)")
    validate_schema_bound_object(obj)

    markdown = md_path.read_text(encoding="utf-8")
    expected = render_run_protocol_markdown(obj)
    if markdown.rstrip("\n") != expected.rstrip("\n"):
        raise FL3ValidationError("RUN_PROTOCOL.md is not the canonical render of run_protocol.json (fail-closed)")
    if sha256_text(expected) != obj.get("run_protocol_md_hash"):
        raise FL3ValidationError("run_protocol_md_hash mismatch (fail-closed)")
    return obj


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate hash-bound run protocol artifacts (JSON + markdown).")
    ap.add_argument("--input-json", required=True, help="Input JSON payload path (missing fields are derived).")
    ap.add_argument("--out-dir", required=True, help="Output directory for run_protocol.json and RUN_PROTOCOL.md.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    in_path = Path(args.input_json).resolve()
    out_dir = Path(args.out_dir).resolve()
    payload = json.loads(in_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise FL3ValidationError("Input JSON payload must be an object (fail-closed)")
    protocol = build_run_protocol(payload)
    write_run_protocol_pair(out_dir=out_dir, protocol=protocol)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
