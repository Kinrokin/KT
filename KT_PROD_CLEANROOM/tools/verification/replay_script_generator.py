from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from schemas.schema_files import schema_version_hash
from tools.verification.fl3_canonical import sha256_json, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import enforce_all_or_none_exist, write_text_worm

REPLAY_RECEIPT_SCHEMA_FILE = "fl3/kt.replay_receipt.v1.json"


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_replay_sh(*, replay_command: str) -> str:
    cmd = str(replay_command).strip()
    if not cmd:
        raise FL3ValidationError("replay_command must be non-empty (fail-closed)")
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -Eeuo pipefail",
            "",
            cmd,
            "",
        ]
    )


def render_replay_ps1(*, replay_command: str) -> str:
    cmd = str(replay_command).strip()
    if not cmd:
        raise FL3ValidationError("replay_command must be non-empty (fail-closed)")
    return "\n".join(
        [
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "",
            cmd,
            "",
        ]
    )


def write_replay_scripts(*, out_dir: Path, replay_command: str) -> Tuple[Path, Path, Dict[str, str]]:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sh_text = render_replay_sh(replay_command=replay_command)
    ps1_text = render_replay_ps1(replay_command=replay_command)
    sh_hash = sha256_text(sh_text)
    ps1_hash = sha256_text(ps1_text)
    bundle_hash = sha256_json({"replay_ps1_sha256": ps1_hash, "replay_sh_sha256": sh_hash})

    sh_path = out_dir / "replay.sh"
    ps1_path = out_dir / "replay.ps1"

    enforce_all_or_none_exist([sh_path, ps1_path], label="replay scripts")
    write_text_worm(path=sh_path, text=sh_text, label="replay.sh")
    write_text_worm(path=ps1_path, text=ps1_text, label="replay.ps1")

    return sh_path, ps1_path, {"replay_sh_sha256": sh_hash, "replay_ps1_sha256": ps1_hash, "replay_script_hash": bundle_hash}


def build_replay_receipt(
    *,
    run_id: str,
    lane_id: str,
    replay_command: str,
    replay_hashes: Dict[str, str],
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = str(replay_command).strip()
    if not cmd:
        raise FL3ValidationError("replay_command must be non-empty (fail-closed)")

    created_at = _utc_now_z()
    obj: Dict[str, Any] = {
        "schema_id": "kt.replay_receipt.v1",
        "schema_version_hash": schema_version_hash(REPLAY_RECEIPT_SCHEMA_FILE),
        "replay_receipt_id": "",
        "run_id": str(run_id),
        "lane_id": str(lane_id),
        "replay_command": cmd,
        "replay_sh_sha256": str(replay_hashes.get("replay_sh_sha256", "")).strip(),
        "replay_ps1_sha256": str(replay_hashes.get("replay_ps1_sha256", "")).strip(),
        "replay_script_hash": str(replay_hashes.get("replay_script_hash", "")).strip(),
        "created_at": created_at,
        "notes": notes,
    }
    obj["replay_receipt_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "replay_receipt_id"}})
    validate_schema_bound_object(obj)
    return obj


def write_replay_receipt(*, out_dir: Path, receipt: Dict[str, Any]) -> Path:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / "replay_receipt.json"
    text = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    write_text_worm(path=out_path, text=text, label="replay_receipt.json")
    return out_path


def write_replay_artifacts(
    *,
    out_dir: Path,
    replay_command: str,
    run_id: str,
    lane_id: str,
    notes: Optional[str] = None,
) -> Tuple[Path, Path, Path, Dict[str, str]]:
    sh_path, ps1_path, replay_hashes = write_replay_scripts(out_dir=out_dir, replay_command=replay_command)
    receipt = build_replay_receipt(
        run_id=run_id,
        lane_id=lane_id,
        replay_command=replay_command,
        replay_hashes=replay_hashes,
        notes=notes,
    )
    receipt_path = write_replay_receipt(out_dir=out_dir, receipt=receipt)
    return sh_path, ps1_path, receipt_path, replay_hashes
