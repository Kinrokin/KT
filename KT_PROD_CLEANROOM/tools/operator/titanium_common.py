from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.strict_json import load_no_dupes
from tools.verification.worm_write import write_text_worm


EXIT_CODES: Dict[str, int] = {
    "STOP_GATE_BLOCKED": 10,
    "PIN_MISSING": 11,
    "SOURCE_INTEGRITY_FAIL": 12,
    "CATALOG_INCOMPLETE": 13,
    "GOV_MANIFEST_INVALID": 14,
    "DELIVERY_CONTRACT_FAIL": 20,
    "BINDING_LOOP_FAIL": 21,
    "WORM_VIOLATION": 22,
    "SECRET_OR_PROBE_LEAK_DETECTED": 23,
    "REPLAY_NONDETERMINISTIC": 30,
    "MAI_CONFORMANCE_FAIL": 40,
    "CONSTITUTION_EPOCH_MISMATCH": 50,
    "LEDGER_CHAIN_INVALID": 60,
    "GOD_STATUS_HOLD": 70,
}


def utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now_compact_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def repo_root() -> Path:
    return repo_root_from(Path(__file__))


def runs_root(root: Optional[Path] = None) -> Path:
    base = root or repo_root()
    return (base / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_OPERATOR").resolve()


def make_run_dir(*, cmd_name: str, requested_run_root: str = "") -> Path:
    root = repo_root()
    if str(requested_run_root).strip():
        run_dir = Path(str(requested_run_root)).expanduser()
        if not run_dir.is_absolute():
            run_dir = (root / run_dir).resolve()
    else:
        run_dir = (runs_root(root) / f"{utc_now_compact_z()}_{cmd_name}").resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "reports").mkdir(parents=True, exist_ok=True)
    (run_dir / "transcripts").mkdir(parents=True, exist_ok=True)
    return run_dir


def load_json(path: Path) -> Dict[str, Any]:
    obj = load_no_dupes(path)
    if not isinstance(obj, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def write_json_worm(path: Path, obj: Dict[str, Any], *, label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)


def canonical_file_sha256(path: Path) -> str:
    return sha256_hex(canonicalize_bytes(load_json(path)))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def operator_fingerprint() -> Dict[str, Any]:
    machine_surface = {
        "machine": platform.machine(),
        "node": platform.node(),
        "platform": platform.platform(),
        "python": sys.version,
        "user": getpass.getuser(),
    }
    runtime_surface = {
        "cwd": os.getcwd(),
        "executable": sys.executable,
        "pid": os.getpid(),
    }
    return {
        "created_utc": utc_now_iso_z(),
        "machine_fingerprint": sha256_hex(canonicalize_bytes(machine_surface)),
        "mve_environment_fingerprint": sha256_hex(canonicalize_bytes({"platform": platform.platform(), "python": platform.python_version()})),
        "operator_id": os.environ.get("KT_OPERATOR_ID", getpass.getuser()),
        "runtime_fingerprint": sha256_hex(canonicalize_bytes(runtime_surface)),
    }


def write_failure_artifacts(
    *,
    run_dir: Path,
    program_id: str,
    failure_name: str,
    message: str,
    next_actions: list[str],
    operator_intent_hash: str = "",
) -> int:
    error_obj = {
        "created_utc": utc_now_iso_z(),
        "exit_code": EXIT_CODES.get(failure_name, 2),
        "failure_class": failure_name,
        "message": str(message),
        "program_id": program_id,
    }
    fp_obj = {
        "errortaxonomy": error_obj,
        "operator_intent_hash": operator_intent_hash,
        "program_id": program_id,
        "runtime_fingerprint": operator_fingerprint()["runtime_fingerprint"],
    }
    failure_fp = sha256_hex(canonicalize_bytes(fp_obj))
    write_json_worm(run_dir / "reports" / "errortaxonomy.json", error_obj, label="errortaxonomy.json")
    write_json_worm(
        run_dir / "reports" / "failure_fingerprint.json",
        {"failure_fingerprint": failure_fp, "schema_id": "kt.operator.failure_fingerprint.v1"},
        label="failure_fingerprint.json",
    )
    write_text_worm(
        path=run_dir / "reports" / "nextaction.sh",
        text="\n".join(str(x) for x in next_actions) + "\n",
        label="nextaction.sh",
    )
    write_text_worm(
        path=run_dir / "reports" / "next_action.sh",
        text="\n".join(str(x) for x in next_actions) + "\n",
        label="next_action.sh",
    )
    return EXIT_CODES.get(failure_name, 2)
