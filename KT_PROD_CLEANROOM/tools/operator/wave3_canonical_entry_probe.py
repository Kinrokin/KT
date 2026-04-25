from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from core.invariants_gate import CONSTITUTION_VERSION_HASH
from kt.entrypoint import invoke as entry_invoke
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH
from tools.operator.titanium_common import repo_root, write_json_stable


def _load_json(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return payload


def _build_context(*, payload: Dict[str, Any], artifact_root: Path) -> Dict[str, Any]:
    return {
        "artifact_root": str(artifact_root.resolve()),
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {
            "input": json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        },
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def run_probe(*, payload: Dict[str, Any], artifact_root: Path) -> Dict[str, Any]:
    artifact_root = artifact_root.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    context = _build_context(payload=payload, artifact_root=artifact_root)
    result = entry_invoke(context)
    return {
        "artifact_root": artifact_root.as_posix(),
        "entry_result": result,
        "status": "PASS",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one canonical entrypoint probe for Wave 3 minimum viable civilization validation.")
    parser.add_argument("--payload-file", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--telemetry-output", default="")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    payload_path = Path(str(args.payload_file)).expanduser()
    if not payload_path.is_absolute():
        payload_path = (root / payload_path).resolve()
    artifact_root = Path(str(args.artifact_root)).expanduser()
    if not artifact_root.is_absolute():
        artifact_root = (root / artifact_root).resolve()
    out_path = Path(str(args.output)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()

    telemetry_output = str(args.telemetry_output).strip()
    if telemetry_output:
        telemetry_path = Path(telemetry_output).expanduser()
        if not telemetry_path.is_absolute():
            telemetry_path = (root / telemetry_path).resolve()
        os.environ["KT_RUNTIME_TELEMETRY_PATH"] = str(telemetry_path)

    payload = _load_json(payload_path)
    result = run_probe(payload=payload, artifact_root=artifact_root)
    write_json_stable(out_path, result)
    print(json.dumps({"artifact_root": result["artifact_root"], "status": result["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
