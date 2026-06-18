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
SCHEMAS = ROOT / "schemas"
REGISTRY = ROOT / "registry"
EVIDENCE = ROOT / "evidence"

ASSESSMENT = EVIDENCE / "KT_STOP10_V1_ASSESSMENT_ONLY.zip"
ASSESSMENT_SHA256 = "c1580bec70abea0da8ef86441b6a2158a9f8325ba151bf5a3e6bd197cab15076"
SOURCE_PACKET = PACKETS / "ktstop10_v1.zip"
SOURCE_PACKET_SHA256 = "640ae33f1c7a5694bf640aaa5b1857dd0b801b252b55cd3e0fa31e8a574af464"
RUN_MODE = "RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1"
PACKET_PATH = PACKETS / "ktstoprt_v1.zip"
KAGGLE_DATASET_NAME = "ktstoprt-v1"
ONE_CELL_RUNBOOK = DOCS / "KT_STOPRT_ONE_CELL.md"
ACTIVE_TRANCHE = "AUTHOR_KTSTOP10_RUNTIME_TERMINATION_HARDENING_AND_PACKET_FORGE_V2"
OUTCOME = "KT_STOP10_IMPORTED__PROMPT_ONLY_STOP_REJECTED__FIRST_FINAL_SAFETY_AUDITED__RUNTIME_STOP_PACKET_READY__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1"

AUTHORITY_FALSE = {
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
    "sandbox_training": False,
    "shadow_runtime": False,
    "canary_runtime": False,
    "production_runtime": False,
    "artifact_publication": "assessment_zip_and_hf_evidence_only",
    "external_claim": False,
    "commercial_claim": False,
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


def repo_artifact_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() in {".json", ".jsonl", ".md", ".py", ".txt"}:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def repo_artifact_stats(path: Path) -> tuple[str, int]:
    data = repo_artifact_bytes(path)
    return hashlib.sha256(data).hexdigest(), len(data)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def load_assessment_member(name: str) -> bytes:
    with zipfile.ZipFile(ASSESSMENT) as zf:
        return zf.read(name)


def load_assessment_json(name: str) -> Any:
    return json.loads(load_assessment_member(name).decode("utf-8-sig"))


def load_assessment_jsonl(name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in load_assessment_member(name).decode("utf-8-sig").splitlines() if line.strip()]


def load_ktstop10_config() -> dict[str, Any]:
    with zipfile.ZipFile(SOURCE_PACKET) as zf:
        return json.loads(zf.read("runtime/ktstop10_config.json").decode("utf-8-sig"))


def assert_hash(path: Path, expected: str, label: str) -> str:
    actual = sha256_file(path)
    if actual != expected:
        raise SystemExit(f"{label} sha256 mismatch: expected {expected} got {actual}")
    return actual


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
        "role": "ktstoprt_runtime_termination_hardening",
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
    delta_path = REGISTRY / "artifact_authority_registry_ktstoprt_delta_receipt.json"
    delta = {
        "schema_id": "kt.artifact_authority_registry.ktstoprt_delta_receipt.v1",
        "created_utc": utc_now(),
        "source_lane": ACTIVE_TRANCHE,
        "status": "PASS",
        "claim_ceiling_status": "PRESERVED",
        "entries_added_or_updated": entries,
        "notes": "KTSTOPRT artifact authority delta receipt. Sandbox inference packet only; no training, promotion, selector deployment, adapter mutation, production prompt mutation, production math mode, commercial, external, S-tier, or frontier authority.",
    }
    write_json(delta_path, delta)
    entries.append(
        registry_entry(
            delta_path,
            "CANONICAL_RECEIPT_CURRENT",
            "CURRENT_HEAD",
            False,
            "KTSTOPRT artifact authority delta receipt.",
        )
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


def authority_payload() -> dict[str, Any]:
    return {"claim_ceiling_status": "PRESERVED", **AUTHORITY_FALSE}
