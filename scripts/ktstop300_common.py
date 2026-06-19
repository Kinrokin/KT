from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPORTS = ROOT / "reports"
PACKETS = ROOT / "packets"
DOCS = ROOT / "docs"
ADMISSION = ROOT / "admission"
SCHEMAS = ROOT / "schemas"
REGISTRY = ROOT / "registry"
EVIDENCE = ROOT / "evidence"
FIXTURES = ROOT / "fixtures"

STOP50_PACKET = PACKETS / "ktstop50_v1.zip"
STOP50_PACKET_SHA256 = "88897536607e923a0723ad60bb9219712a447a00abd18cd8c0b2db21aa71bc18"
STOP50_ASSESSMENT = EVIDENCE / "KT_STOP50_V1_ASSESSMENT_ONLY.zip"
STOP50_ASSESSMENT_SHA256 = "50d94b6b3688c5917547fb7ff12747defc9ba0ab7944c1231d4b218f74383ec9"
STOP50_WRAPPER = EVIDENCE / "KT_STOP50_V1_WRAPPER_COLLECTION.zip"
STOP50_WRAPPER_SHA256 = "59f530d378e80720c925fbd2d916622a345f588e292d17bfaf4bc761bf25917d"
STOP50_SYNTHESIS = EVIDENCE / "KT_STOP50_HOSTILE_SYNTHESIS_V2.json"

ACTIVE_TRANCHE = "AUTHOR_KTSTOP50_IMPORT_AND_STOP300_HOSTILE_FALSIFICATION_PACKET_V2"
OUTCOME = "KT_STOP50_BOUND__STOP300_HOSTILE_FALSIFICATION_PACKET_READY__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V1"

STOP300_PACKET = PACKETS / "ktstop300_v1.zip"
STOP300_DATASET = "ktstop300-v1"
STOP300_RUN_MODE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V1"
STOP300_RUNBOOK = DOCS / "KT_STOP300_ONE_CELL.md"
STOP300_V2_PACKET = PACKETS / "ktstop300_v2.zip"
STOP300_V2_DATASET = "ktstop300-v2"
STOP300_V2_RUN_MODE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V2"
STOP300_V2_RUNBOOK = DOCS / "KT_STOP300_V2_ONE_CELL.md"
STOP300_V2_OUTCOME = "KT_STOP300_PRE_GPU_INTEGRITY_REPAIRED__HOSTILE_FALSIFICATION_V2_PACKET_READY__CLAIM_CEILING_PRESERVED"
STOP300_V2_NEXT_LAWFUL_MOVE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V2"
STOP300_V3_PACKET = PACKETS / "ktstop300_v3.zip"
STOP300_V3_DATASET = "ktstop300-v3"
STOP300_V3_RUN_MODE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V3"
STOP300_V3_RUNBOOK = DOCS / "KT_STOP300_V3_ONE_CELL.md"
STOP300_V3_OUTCOME = "KT_STOP300_V2_POSTMERGE_AUDITED__STARTUP_IDENTITY_COURT_TIMING_AND_DURABILITY_REPAIRED__STOP300_V3_PACKET_READY__CLAIM_CEILING_PRESERVED"
STOP300_V3_NEXT_LAWFUL_MOVE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V3"

AUTHORITY_FALSE = {
    "shadow_runtime_authority": False,
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "selector_deployment_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
    "production_math_mode_claim": False,
}

SCOPED_AUTHORITY = {
    "sandbox_inference_authority": True,
    "commercial_claim": False,
    "external_validation_claim": False,
    "router_superiority_claim": False,
    "production_runtime_authority": False,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def assert_hash(path: Path, expected: str, label: str) -> str:
    actual = sha256_file(path)
    if actual != expected:
        raise SystemExit(f"{label} sha256 mismatch: expected {expected} got {actual}")
    return actual


def load_zip_json(zip_path: Path, member: str) -> Any:
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read(member).decode("utf-8-sig"))


def load_zip_jsonl(zip_path: Path, member: str) -> list[dict[str, Any]]:
    with zipfile.ZipFile(zip_path) as zf:
        return [json.loads(line) for line in zf.read(member).decode("utf-8-sig").splitlines() if line.strip()]


def authority_payload() -> dict[str, Any]:
    return {"claim_ceiling_status": "PRESERVED", **AUTHORITY_FALSE}


def repo_artifact_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() in {".json", ".jsonl", ".md", ".py", ".txt"}:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def repo_artifact_stats(path: Path) -> tuple[str, int]:
    data = repo_artifact_bytes(path)
    return hashlib.sha256(data).hexdigest(), len(data)


def artifact_id(path: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_").upper()


def registry_entry(path: Path, primary_class: str, claim_authority: str, controls_execution: bool, notes: str) -> dict[str, Any]:
    relative = rel(path)
    sha, size = repo_artifact_stats(path)
    return {
        "artifact_id": artifact_id(relative),
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "claim_authority": claim_authority,
        "controls_execution": controls_execution,
        "current_authority": True,
        "notes": notes,
        "path": relative,
        "primary_class": primary_class,
        "role": "ktstop300_hostile_falsification_packet",
        "sha256": sha,
        "size_bytes": size,
        "source_lane": ACTIVE_TRANCHE,
        "superseded_by": None,
        "supersedes": [],
        "updated_utc": utc_now(),
        "validation_status": "PASS",
    }


def update_registry(paths: list[tuple[Path, str, str, bool, str]]) -> None:
    registry_path = REGISTRY / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    entries = [registry_entry(*spec) for spec in paths if spec[0].exists()]
    delta_path = REGISTRY / "artifact_authority_registry_ktstop300_delta_receipt.json"
    delta = {
        "schema_id": "kt.artifact_authority_registry.ktstop300_delta_receipt.v1",
        "created_utc": utc_now(),
        "source_lane": ACTIVE_TRANCHE,
        "status": "PASS",
        "claim_ceiling_status": "PRESERVED",
        "entries_added_or_updated": entries,
        "notes": "STOP300 hostile falsification packet forge. Sandbox inference packet only; no Kaggle execution, shadow execution, production runtime, training, promotion, selector deployment, adapter mutation, production prompt mutation, or production math-mode authority.",
    }
    write_json(delta_path, delta)
    entries.append(
        registry_entry(delta_path, "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 artifact authority delta receipt.")
    )
    delta["entries_added_or_updated"] = entries
    write_json(delta_path, delta)
    by_path = {artifact["path"]: artifact for artifact in registry["artifacts"]}
    for entry in entries:
        by_path[entry["path"]] = entry
    registry["artifacts"] = list(by_path.values())
    registry["artifact_count"] = len(registry["artifacts"])
    registry["current_head"] = git_output("rev-parse", "HEAD")
    registry["updated_utc"] = utc_now()
    write_json(registry_path, registry)
