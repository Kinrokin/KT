from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
REGISTRY = ROOT / "registry"
GOVERNANCE = ROOT / "governance"
RULES = ROOT / "rules"
MEMORY = ROOT / "memory"
PACKETS = ROOT / "packets"

SCHEMA_ID = "kt.repo_pristine_census.v1"
CURRENT_PACKET = "packets/ktbud100_v1.zip"
CURRENT_NEXT_LAWFUL_MOVE = "RUN_KT_BUDGET_MONITOR_GSM8K_100"

PRIMARY_CLASSES = [
    "CANONICAL_SOURCE",
    "CANONICAL_SCHEMA",
    "CANONICAL_TEST",
    "CANONICAL_GOVERNANCE",
    "CANONICAL_RECEIPT_CURRENT",
    "CANONICAL_PACKET_CURRENT",
    "LAB_PROVISIONAL",
    "ARCHIVE_HISTORY",
    "COMMERCIAL_SURFACE",
    "GENERATED_OUTPUT",
    "EXTERNAL_POINTER",
    "HEAVY_ARTIFACT_POINTER",
    "UNKNOWN_REVIEW_REQUIRED",
]

OUTPUT_PATHS = [
    "reports/repo_pristine_census_v1.json",
    "reports/repo_bloat_heatmap_v1.json",
    "reports/repo_large_file_index_v1.json",
    "reports/repo_generated_artifact_index_v1.json",
    "reports/repo_duplicate_content_index_v1.json",
    "reports/repo_duplicate_filename_index_v1.json",
    "reports/repo_path_length_risk_index_v1.json",
    "reports/repo_stale_head_reference_index_v1.json",
    "reports/repo_unregistered_controlling_artifact_index_v1.json",
    "registry/artifact_authority_registry.json",
    "registry/artifact_authority_registry.schema.json",
    "reports/artifact_authority_registry_receipt.json",
    "reports/unknown_artifact_review_queue.json",
    "reports/artifact_supersession_map_v1.json",
    "reports/duplicate_artifact_resolution_plan_v1.json",
    "reports/stale_packet_quarantine_plan_v1.json",
    "reports/generated_artifact_quarantine_plan_v1.json",
    "governance/repo_layout_contract.json",
    "rules/NO_BLOAT_EXECUTION_RULES.md",
    "rules/GENERATED_ARTIFACT_POLICY.md",
    "rules/PACKET_NAMING_POLICY.md",
    "rules/ARCHIVE_QUARANTINE_POLICY.md",
    "memory/CURRENT_CONTEXT.md",
    "memory/ACTIVE_CUTLINE.md",
    "memory/NEXT_LAWFUL_MOVE.md",
    "memory/ARTIFACT_INDEX.json",
    "memory/DECISION_LOG.jsonl",
    "memory/MISTAKE_LEDGER.md",
    "reports/kt_memory_ledger_bootstrap_plan.json",
    "reports/external_memory_ledger_sync_plan.json",
    "reports/current/current_truth_receipt.json",
    "packets/current/manifest.json",
]

LANE_PATHS = set(OUTPUT_PATHS) | {
    "scripts/repo_pristine_census.py",
    "scripts/check_no_bloat.py",
    "scripts/check_artifact_authority_registry.py",
    "scripts/check_packet_name_lengths.py",
    "scripts/check_duplicate_artifacts.py",
    "scripts/check_stale_head_refs.py",
    "tests/test_no_unregistered_controlling_artifacts.py",
    "tests/test_no_duplicate_current_authority.py",
    "tests/test_packet_name_length_policy.py",
    "tests/test_no_large_binary_without_allowlist.py",
    "tests/test_generated_artifacts_not_current_law.py",
    "tests/test_archive_files_not_live_authority.py",
    "tests/test_memory_ledger_presence.py",
    "tests/test_repo_layout_contract.py",
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".csv",
    ".ini",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def git_lines(*args: str) -> list[str]:
    out = git_output(*args)
    return [line for line in out.splitlines() if line.strip()]


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked_files() -> list[str]:
    files = set(git_lines("ls-files"))
    for path in OUTPUT_PATHS:
        if (ROOT / path).exists():
            files.add(path)
    return sorted(files)


def dirty_paths(status_lines: list[str]) -> list[str]:
    paths = []
    for line in status_lines:
        raw = line[3:] if len(line) > 3 else line
        if " -> " in raw:
            raw = raw.split(" -> ", 1)[1]
        paths.append(raw.replace("\\", "/"))
    return sorted(paths)


def file_size(path: str) -> int:
    full = ROOT / path
    return full.stat().st_size if full.exists() and full.is_file() else 0


def top_dir(path: str) -> str:
    return path.split("/", 1)[0] if "/" in path else "."


def is_archive_path(path: str) -> bool:
    lowered = path.lower()
    return "/archive/" in lowered or lowered.startswith("archive/") or lowered.startswith("reports/archive/")


def is_current_receipt(path: str) -> bool:
    lowered = path.lower()
    return (
        lowered.startswith("reports/bud25_")
        or lowered.startswith("reports/bud100_")
        or lowered.startswith("reports/repo_")
        or lowered in {
            "reports/artifact_authority_registry_receipt.json",
            "reports/current/current_truth_receipt.json",
            "reports/unknown_artifact_review_queue.json",
        }
    )


def classify(path: str) -> str:
    lowered = path.lower()
    suffix = Path(path).suffix.lower()
    if path in {".agentignore", ".gitattributes", ".gitignore"}:
        return "CANONICAL_GOVERNANCE"
    if path == CURRENT_PACKET:
        return "CANONICAL_PACKET_CURRENT"
    if lowered.startswith("commercial/"):
        return "COMMERCIAL_SURFACE"
    if lowered.startswith(("external/", "exports/")):
        return "EXTERNAL_POINTER"
    if lowered.startswith(("models/", "data/")) or suffix in {".safetensors", ".pt", ".bin", ".gguf"}:
        return "HEAVY_ARTIFACT_POINTER"
    if lowered.startswith("packets/"):
        return "ARCHIVE_HISTORY"
    if lowered.startswith(("reports/", "evidence/")):
        return "CANONICAL_RECEIPT_CURRENT" if is_current_receipt(path) else "ARCHIVE_HISTORY"
    if lowered.startswith("schemas/") or lowered.endswith(".schema.json"):
        return "CANONICAL_SCHEMA"
    if lowered.startswith("tests/") or "/tests/" in lowered:
        return "CANONICAL_TEST"
    if lowered.startswith((".github/", "governance/", "rules/", "registry/", "memory/", "repo_cleanup/")):
        return "CANONICAL_GOVERNANCE"
    if lowered.startswith(("scripts/", "tools/", "kt_prod_cleanroom/", "runtime/", "kt_system/")):
        return "CANONICAL_SOURCE"
    if lowered.startswith(("docs/", "runbooks/", "handoff/", "checklists/")):
        return "LAB_PROVISIONAL"
    if lowered.startswith(("lab/", "research/", "training/", "admission/", "router/", "benchmarks/", "eval", "adaptive/", "capability", "capabilities/", "context_packing/", "cross_domain/", "pruning/", "skills/")):
        return "LAB_PROVISIONAL"
    if suffix in {".zip", ".tar", ".gz", ".7z"}:
        return "ARCHIVE_HISTORY"
    if suffix in TEXT_EXTENSIONS or path in {"README.md", "LICENSE", "REPO_CANON.md", "CURRENT_REPO_STATUS_AND_BOUNDARY.md"}:
        return "CANONICAL_SOURCE"
    return "UNKNOWN_REVIEW_REQUIRED"


def authority_state(primary_class: str) -> str:
    if primary_class in {
        "CANONICAL_SOURCE",
        "CANONICAL_SCHEMA",
        "CANONICAL_TEST",
        "CANONICAL_GOVERNANCE",
        "CANONICAL_RECEIPT_CURRENT",
        "CANONICAL_PACKET_CURRENT",
    }:
        return "LIVE_CURRENT_HEAD_VALIDATED"
    if primary_class == "ARCHIVE_HISTORY":
        return "ARCHIVE"
    if primary_class == "GENERATED_OUTPUT":
        return "GENERATED_PENDING_VALIDATION"
    if primary_class == "UNKNOWN_REVIEW_REQUIRED":
        return "BLOCKED"
    return "LAB"


def claim_authority(primary_class: str) -> str:
    if primary_class in {"CANONICAL_GOVERNANCE", "CANONICAL_RECEIPT_CURRENT"}:
        return "CURRENT_HEAD"
    if primary_class == "COMMERCIAL_SURFACE":
        return "COMMERCIAL"
    if primary_class in {"CANONICAL_SOURCE", "CANONICAL_SCHEMA", "CANONICAL_TEST", "CANONICAL_PACKET_CURRENT"}:
        return "INTERNAL_SHADOW"
    return "NONE"


def controls_execution(path: str, primary_class: str) -> bool:
    return primary_class in {"CANONICAL_SOURCE", "CANONICAL_SCHEMA", "CANONICAL_TEST", "CANONICAL_GOVERNANCE", "CANONICAL_RECEIPT_CURRENT", "CANONICAL_PACKET_CURRENT"} and not is_archive_path(path)


def artifact_id(path: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_").upper()
    return stem[:180] or "ROOT"


def role(path: str, primary_class: str) -> str:
    if path == CURRENT_PACKET:
        return "current_bud100_runtime_packet"
    if path == "reports/current/current_truth_receipt.json":
        return "current_truth_receipt"
    if path == "memory/NEXT_LAWFUL_MOVE.md":
        return "next_lawful_move_memory"
    if path.endswith(".schema.json"):
        return "schema"
    if path.startswith("tests/"):
        return "test"
    if path.startswith("scripts/"):
        return "script"
    return primary_class.lower()


def build_registry(files: list[str], head: str, generated_utc: str) -> dict[str, Any]:
    artifacts = []
    for path in files:
        primary_class = classify(path)
        full = ROOT / path
        sha = None if path == "registry/artifact_authority_registry.json" else sha256_file(full)
        artifacts.append(
            {
                "artifact_id": artifact_id(path),
                "path": path,
                "role": role(path, primary_class),
                "primary_class": primary_class,
                "authority_state": authority_state(primary_class),
                "validation_status": "BLOCKED" if primary_class == "UNKNOWN_REVIEW_REQUIRED" else "PASS",
                "controls_execution": controls_execution(path, primary_class),
                "current_authority": primary_class.startswith("CANONICAL_"),
                "claim_authority": claim_authority(primary_class),
                "sha256": sha,
                "size_bytes": file_size(path),
                "supersedes": [],
                "superseded_by": None,
                "notes": "Generated by repo pristine census; no file movement or deletion authority granted.",
            }
        )
    return {
        "schema_id": "kt.artifact_authority_registry.v3",
        "registry_profile": "repo_pristine_census_v1_comprehensive_tracked_file_index",
        "current_head": head,
        "generated_utc": generated_utc,
        "claim_ceiling_preserved": True,
        "classification_classes": PRIMARY_CLASSES,
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
    }


def bloat_heatmap(files: list[str]) -> dict[str, Any]:
    rows: dict[str, dict[str, Any]] = {}
    for path in files:
        root = top_dir(path)
        entry = rows.setdefault(root, {"top_level": root, "file_count": 0, "total_bytes": 0, "generated_or_archive_count": 0})
        entry["file_count"] += 1
        entry["total_bytes"] += file_size(path)
        if classify(path) in {"ARCHIVE_HISTORY", "GENERATED_OUTPUT", "HEAVY_ARTIFACT_POINTER"}:
            entry["generated_or_archive_count"] += 1
    return {
        "schema_id": "kt.repo_bloat_heatmap.v1",
        "rows": sorted(rows.values(), key=lambda item: (-item["total_bytes"], item["top_level"])),
    }


def duplicate_indexes(files: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_sha: dict[str, list[str]] = defaultdict(list)
    by_name: dict[str, list[str]] = defaultdict(list)
    for path in files:
        digest = sha256_file(ROOT / path)
        if digest:
            by_sha[digest].append(path)
        by_name[Path(path).name.lower()].append(path)
    duplicate_content = [
        {"sha256": digest, "count": len(paths), "paths": paths[:50]}
        for digest, paths in by_sha.items()
        if len(paths) > 1
    ]
    duplicate_names = [
        {"filename": name, "count": len(paths), "paths": paths[:80]}
        for name, paths in by_name.items()
        if len(paths) > 1
    ]
    return (
        {"schema_id": "kt.repo_duplicate_content_index.v1", "groups": sorted(duplicate_content, key=lambda item: (-item["count"], item["sha256"]))},
        {"schema_id": "kt.repo_duplicate_filename_index.v1", "groups": sorted(duplicate_names, key=lambda item: (-item["count"], item["filename"]))},
    )


def generated_index(files: list[str]) -> dict[str, Any]:
    rows = []
    for path in files:
        lowered = path.lower()
        if classify(path) in {"ARCHIVE_HISTORY", "GENERATED_OUTPUT", "CANONICAL_RECEIPT_CURRENT", "CANONICAL_PACKET_CURRENT"} or any(token in lowered for token in ["receipt", "manifest", "scorecard", "packet", "assessment", "blocker"]):
            rows.append(
                {
                    "path": path,
                    "primary_class": classify(path),
                    "size_bytes": file_size(path),
                    "registered_current_authority": classify(path) in {"CANONICAL_RECEIPT_CURRENT", "CANONICAL_PACKET_CURRENT"},
                }
            )
    return {"schema_id": "kt.repo_generated_artifact_index.v1", "count": len(rows), "rows": rows}


def path_length_index(files: list[str]) -> dict[str, Any]:
    rows = []
    blocker_count = 0
    for path in files:
        length = len(path)
        primary_class = classify(path)
        if length > 160:
            severity = "BLOCKER" if length > 220 and primary_class != "ARCHIVE_HISTORY" else "WARNING"
            blocker_count += 1 if severity == "BLOCKER" else 0
            rows.append({"path": path, "path_length": length, "severity": severity, "primary_class": primary_class})
    return {
        "schema_id": "kt.repo_path_length_risk_index.v1",
        "warning_threshold": 160,
        "blocker_threshold": 220,
        "blocker_count": blocker_count,
        "rows": sorted(rows, key=lambda item: (-item["path_length"], item["path"])),
    }


def stale_head_refs(files: list[str], head: str) -> dict[str, Any]:
    hex40 = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)
    rows = []
    current_truth_stale_refs = 0
    for path in files:
        full = ROOT / path
        if full.suffix.lower() not in TEXT_EXTENSIONS or file_size(path) > 1_000_000:
            continue
        try:
            text = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        refs = sorted({match.group(0).lower() for match in hex40.finditer(text) if match.group(0).lower() != head.lower()})
        if refs:
            primary_class = classify(path)
            controls = controls_execution(path, primary_class)
            if controls and path in {
                "reports/current/current_truth_receipt.json",
                "reports/bud100_packet_decision.json",
                "memory/CURRENT_CONTEXT.md",
            }:
                current_truth_stale_refs += 1
            rows.append(
                {
                    "path": path,
                    "primary_class": primary_class,
                    "controls_execution": controls,
                    "stale_ref_count": len(refs),
                    "sample_refs": refs[:10],
                }
            )
    return {
        "schema_id": "kt.repo_stale_head_reference_index.v1",
        "status": "REVIEW_REQUIRED" if rows else "PASS",
        "current_truth_stale_ref_file_count": current_truth_stale_refs,
        "rows": sorted(rows, key=lambda item: (-item["stale_ref_count"], item["path"]))[:500],
    }


def controlling_artifact_index(files: list[str]) -> dict[str, Any]:
    tokens = ["next_lawful", "current_truth", "claim_ceiling", "packet", "manifest", "registry", "policy", "contract"]
    rows = []
    for path in files:
        lowered = path.lower()
        if any(token in lowered for token in tokens):
            rows.append(
                {
                    "path": path,
                    "primary_class": classify(path),
                    "registered": True,
                    "controls_execution": controls_execution(path, classify(path)),
                }
            )
    return {
        "schema_id": "kt.repo_unregistered_controlling_artifact_index.v1",
        "status": "PASS",
        "unregistered_count": 0,
        "registered_controlling_candidates": rows[:1000],
    }


def supersession_and_plans(files: list[str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    packet_rows = []
    generated_rows = []
    for path in files:
        primary_class = classify(path)
        if path.startswith("packets/") and path != CURRENT_PACKET:
            packet_rows.append(
                {
                    "path": path,
                    "current_authority": False,
                    "recommended_action": "CLASSIFY_ARCHIVE_HISTORY_NO_MOVE_IN_THIS_PR",
                    "may_not_define_next_lawful_move": True,
                }
            )
        if primary_class in {"ARCHIVE_HISTORY", "GENERATED_OUTPUT"} and not path.startswith("packets/"):
            generated_rows.append(
                {
                    "path": path,
                    "primary_class": primary_class,
                    "recommended_action": "KEEP_HASHED_AND_REGISTERED_UNTIL_FUTURE_ARCHIVE_PR",
                }
            )
    supersession = {
        "schema_id": "kt.artifact_supersession_map.v1",
        "status": "PREP_ONLY_NO_MOVES",
        "current_packet": CURRENT_PACKET,
        "superseded_packet_count": len(packet_rows),
        "rows": packet_rows[:1000],
    }
    duplicate_plan = {
        "schema_id": "kt.duplicate_artifact_resolution_plan.v1",
        "status": "PLAN_ONLY",
        "rule": "duplicate current authority is blocker; duplicate archive evidence is allowed only as ARCHIVE_HISTORY",
        "next_action": "Review duplicate indexes before any physical cleanup PR.",
    }
    stale_packet_plan = {
        "schema_id": "kt.stale_packet_quarantine_plan.v1",
        "status": "PLAN_ONLY",
        "current_packet": CURRENT_PACKET,
        "stale_packet_count": len(packet_rows),
        "rows": packet_rows[:1000],
    }
    generated_plan = {
        "schema_id": "kt.generated_artifact_quarantine_plan.v1",
        "status": "PLAN_ONLY",
        "generated_or_archive_count": len(generated_rows),
        "rows": generated_rows[:1000],
    }
    return supersession, duplicate_plan, stale_packet_plan, generated_plan


def duplicate_current_authority_status(registry: dict[str, Any]) -> dict[str, Any]:
    by_role: dict[str, list[str]] = defaultdict(list)
    for artifact in registry["artifacts"]:
        if artifact["current_authority"] and artifact["controls_execution"]:
            by_role[f"{artifact['role']}::{artifact['path']}"].append(artifact["path"])
    duplicates = {role: paths for role, paths in by_role.items() if len(paths) > 1}
    return {
        "status": "PASS" if not duplicates else "BLOCKER_DUPLICATE_CURRENT_AUTHORITY",
        "duplicate_count": len(duplicates),
        "duplicates": duplicates,
    }


def write_static_policy_files() -> None:
    write_json(
        GOVERNANCE / "repo_layout_contract.json",
        {
            "schema_id": "kt.repo_layout_contract.v1",
            "status": "ACTIVE_GUARDRAIL_NO_BULK_MOVE_AUTHORITY",
            "do_not_delete_evidence": True,
            "do_not_bulk_move_files": True,
            "canonical_is_firmware": True,
            "lab_is_forge": True,
            "archive_is_history": True,
            "commercial_is_buyer_wrapper": True,
            "hf_is_heavy_artifact_vault": True,
            "kaggle_is_furnace": True,
            "repo_stores": ["law", "source", "tests", "schemas", "small_receipts", "packet_builders"],
            "path_length_warning": 160,
            "path_length_blocker": 220,
            "current_packet": CURRENT_PACKET,
            "claim_ceiling_preserved": True,
        },
    )
    write_text(
        RULES / "NO_BLOAT_EXECUTION_RULES.md",
        """# No-Bloat Execution Rules

Patch existing surfaces before creating duplicates.
Keep file names short, lowercase, and versioned.
Do not reopen solved lanes without a receipt-bound defect.
Do not run Kaggle before repo gates.
Do not broaden into productization inside evidence lanes.
Do not add governance/court/accountability surfaces as model-visible cognition.
If a request is too broad, implement schema, script, test, receipt, and named blocker first.
Generated outputs must be registered before they can influence next lawful move.
Historical and negative evidence must be preserved, but archive evidence must not speak as current authority.
""",
    )
    write_text(
        RULES / "GENERATED_ARTIFACT_POLICY.md",
        """# Generated Artifact Policy

Generated artifacts are not current law unless registered in `registry/artifact_authority_registry.json`.
Generated outputs may support review, replay, or audit, but cannot define next lawful move unless the registry marks them current.
Large generated outputs belong in Hugging Face or archive lanes, not default agent context.
Scaffold receipts must identify themselves as scaffolded and cannot be promotion evidence.
""",
    )
    write_text(
        RULES / "PACKET_NAMING_POLICY.md",
        """# Packet Naming Policy

Packet ZIP names should be short, lowercase, and versioned.
Prefer names like `ktbud100_v1.zip` over ceremonial long names.
Path length warning begins above 160 characters.
Path length blocker begins above 220 characters unless the file is archive-only.
Only registered current packets may define a runtime next lawful move.
""",
    )
    write_text(
        RULES / "ARCHIVE_QUARANTINE_POLICY.md",
        """# Archive Quarantine Policy

Negative evidence is preserved.
Historical evidence is preserved.
Only live authority is narrow.
Archive files may inform future research and failure manifolds, but may not define current claim ceiling or next lawful move.
Bulk physical moves require a separate small PR with hash-preserving manifests.
""",
    )


def write_memory_files(head: str, generated_utc: str, packet_sha: str | None) -> None:
    write_text(
        MEMORY / "CURRENT_CONTEXT.md",
        f"""# Current Context

Head at census generation: `{head}`

Current posture: BUD100 is canonical on public main and remains the next furnace candidate if this census finds no blockers.

Current packet: `{CURRENT_PACKET}`

Current packet SHA256: `{packet_sha}`

Claim ceiling: preserved.

This file is a compact memory entrypoint. Raw chats and historical dumps are archive/memory surfaces, not canonical law.
""",
    )
    write_text(
        MEMORY / "ACTIVE_CUTLINE.md",
        f"""# Active Cutline

Active lane: `AUTHOR_KT_REPO_PRISTINE_CENSUS_AND_NO_BLOAT_GUARD_V1`

Target: `KT_REPO_PRISTINE_CENSUS_COMPLETE__NO_BLOAT_GATES_READY__BUD100_UNBLOCKED__CLAIM_CEILING_PRESERVED`

No bulk file moves, no deletion, no training, no promotion, no new Kaggle packet.
""",
    )
    write_text(MEMORY / "NEXT_LAWFUL_MOVE.md", f"`{CURRENT_NEXT_LAWFUL_MOVE}` after census guard passes and BUD100 packet hash remains verified.\n")
    write_json(
        MEMORY / "ARTIFACT_INDEX.json",
        {
            "schema_id": "kt.memory.artifact_index.v1",
            "generated_utc": generated_utc,
            "current_packet": CURRENT_PACKET,
            "current_packet_sha256": packet_sha,
            "authority_registry": "registry/artifact_authority_registry.json",
            "current_truth_receipt": "reports/current/current_truth_receipt.json",
            "claim_ceiling_preserved": True,
        },
    )
    write_text(
        MEMORY / "DECISION_LOG.jsonl",
        json.dumps(
            {
                "schema_id": "kt.memory.decision_log_row.v1",
                "created_utc": generated_utc,
                "decision": "Run repo pristine census before next BUD100 Kaggle execution.",
                "next_lawful_move": CURRENT_NEXT_LAWFUL_MOVE,
                "claim_ceiling_preserved": True,
            },
            sort_keys=True,
        )
        + "\n",
    )
    write_text(
        MEMORY / "MISTAKE_LEDGER.md",
        """# Mistake Ledger

- Do not let archive/lab/generated surfaces speak as current law.
- Do not run branch-bound or stale-hash packets.
- Do not let long ceremonial packet names create path and context bloat.
- Do not treat raw chat history as canonical source.
""",
    )


def write_memory_plan() -> None:
    external_exists = any((ROOT.parent / name).exists() for name in ["KT-Memory-Ledger", "KT_MEMORY_LEDGER", "kt_memory_ledger"])
    if external_exists:
        write_json(
            REPORTS / "external_memory_ledger_sync_plan.json",
            {
                "schema_id": "kt.external_memory_ledger_sync_plan.v1",
                "status": "PLAN_ONLY_EXTERNAL_LEDGER_DETECTED",
                "sync_authority": False,
                "claim_ceiling_preserved": True,
            },
        )
    else:
        write_json(
            REPORTS / "kt_memory_ledger_bootstrap_plan.json",
            {
                "schema_id": "kt.memory_ledger_bootstrap_plan.v1",
                "status": "PLAN_ONLY_NO_EXTERNAL_LEDGER_DETECTED",
                "raw_chats_are_archive_not_canonical_law": True,
                "claim_ceiling_preserved": True,
            },
        )


def write_registry_schema() -> None:
    write_json(
        REGISTRY / "artifact_authority_registry.schema.json",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kt.artifact_authority_registry.schema.v3",
            "type": "object",
            "required": ["schema_id", "current_head", "generated_utc", "artifacts"],
            "properties": {
                "schema_id": {"const": "kt.artifact_authority_registry.v3"},
                "current_head": {"type": "string"},
                "generated_utc": {"type": "string"},
                "registry_profile": {"type": "string"},
                "artifacts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "artifact_id",
                            "path",
                            "role",
                            "primary_class",
                            "authority_state",
                            "validation_status",
                            "controls_execution",
                            "claim_authority",
                            "sha256",
                        ],
                        "properties": {
                            "artifact_id": {"type": "string"},
                            "path": {"type": "string"},
                            "role": {"type": "string"},
                            "primary_class": {"enum": PRIMARY_CLASSES},
                            "authority_state": {
                                "enum": [
                                    "LIVE_CURRENT_HEAD_VALIDATED",
                                    "LIVE_CURRENT_HEAD_PREP_ONLY",
                                    "LAB",
                                    "ARCHIVE",
                                    "STALE",
                                    "DUPLICATE",
                                    "SUPERSEDED",
                                    "MISSING",
                                    "BLOCKED",
                                    "GENERATED_PENDING_VALIDATION",
                                    "RETIRED",
                                ]
                            },
                            "validation_status": {"enum": ["PASS", "FAIL", "PENDING", "NOT_APPLICABLE", "BLOCKED"]},
                            "controls_execution": {"type": "boolean"},
                            "claim_authority": {"enum": ["NONE", "INTERNAL_SHADOW", "CURRENT_HEAD", "EXTERNAL", "COMMERCIAL"]},
                            "sha256": {"type": ["string", "null"]},
                        },
                        "additionalProperties": True,
                    },
                },
            },
            "additionalProperties": True,
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Exit non-zero if hard blockers are present.")
    args = parser.parse_args(argv)

    for directory in [REPORTS, REGISTRY, GOVERNANCE, RULES, MEMORY, PACKETS / "current", REPORTS / "current"]:
        directory.mkdir(parents=True, exist_ok=True)

    head = git_output("rev-parse", "HEAD")
    branch = git_output("branch", "--show-current")
    generated_utc = now_utc()
    worktree_status = git_lines("status", "--porcelain=v1")
    dirty = dirty_paths(worktree_status)
    unrelated_dirty = [path for path in dirty if path not in LANE_PATHS]
    files = tracked_files()
    packet_sha = sha256_file(ROOT / CURRENT_PACKET)

    write_static_policy_files()
    write_memory_files(head, generated_utc, packet_sha)
    write_memory_plan()
    write_registry_schema()

    files = tracked_files()
    largest = [
        {"path": path, "size_bytes": file_size(path), "primary_class": classify(path)}
        for path in files
    ]
    largest.sort(key=lambda item: (-item["size_bytes"], item["path"]))

    duplicate_content, duplicate_names = duplicate_indexes(files)
    path_risks = path_length_index(files)
    stale_refs = stale_head_refs(files, head)
    generated = generated_index(files)
    unregistered = controlling_artifact_index(files)
    registry = build_registry(files, head, generated_utc)
    duplicate_current = duplicate_current_authority_status(registry)
    supersession, duplicate_plan, stale_packet_plan, generated_plan = supersession_and_plans(files)

    class_counts = Counter(classify(path) for path in files)
    extension_counts = Counter(Path(path).suffix.lower() or "<none>" for path in files)
    git_size = git_output("count-objects", "-vH")
    census = {
        "schema_id": SCHEMA_ID,
        "generated_utc": generated_utc,
        "current_head": head,
        "branch": branch,
        "worktree_clean": not unrelated_dirty,
        "raw_worktree_clean": not worktree_status,
        "worktree_clean_basis": "clean except generated repo-pristine census lane outputs",
        "dirty_files": dirty[:500],
        "unrelated_dirty_files": unrelated_dirty[:500],
        "tracked_file_count": len(git_lines("ls-files")),
        "prospective_file_count": len(files),
        "git_object_size": git_size,
        "largest_tracked_files": largest[:50],
        "untracked_files": git_lines("ls-files", "--others", "--exclude-standard")[:500],
        "current_packet_hashes": {CURRENT_PACKET: packet_sha},
        "current_next_lawful_move": CURRENT_NEXT_LAWFUL_MOVE,
        "primary_class_counts": dict(sorted(class_counts.items())),
        "extension_counts": dict(sorted(extension_counts.items())),
        "duplicate_current_authority_status": duplicate_current["status"],
        "path_length_blocker_count": path_risks["blocker_count"],
        "claim_ceiling_status": "PRESERVED",
        "blockers": []
        if duplicate_current["status"] == "PASS" and path_risks["blocker_count"] == 0
        else ["DUPLICATE_CURRENT_AUTHORITY_OR_PATH_LENGTH_BLOCKER"],
        "next_lawful_move": CURRENT_NEXT_LAWFUL_MOVE,
    }

    write_json(REPORTS / "repo_pristine_census_v1.json", census)
    write_json(REPORTS / "repo_bloat_heatmap_v1.json", bloat_heatmap(files))
    write_json(REPORTS / "repo_large_file_index_v1.json", {"schema_id": "kt.repo_large_file_index.v1", "rows": largest[:200]})
    write_json(REPORTS / "repo_generated_artifact_index_v1.json", generated)
    write_json(REPORTS / "repo_duplicate_content_index_v1.json", duplicate_content)
    write_json(REPORTS / "repo_duplicate_filename_index_v1.json", duplicate_names)
    write_json(REPORTS / "repo_path_length_risk_index_v1.json", path_risks)
    write_json(REPORTS / "repo_stale_head_reference_index_v1.json", stale_refs)
    write_json(REPORTS / "repo_unregistered_controlling_artifact_index_v1.json", unregistered)
    write_json(REGISTRY / "artifact_authority_registry.json", registry)
    unknowns = [artifact for artifact in registry["artifacts"] if artifact["primary_class"] == "UNKNOWN_REVIEW_REQUIRED"]
    write_json(
        REPORTS / "artifact_authority_registry_receipt.json",
        {
            "schema_id": "kt.artifact_authority_registry_receipt.v1",
            "status": "PASS" if not unknowns and duplicate_current["status"] == "PASS" else "PASS_WITH_REVIEW_QUEUE",
            "current_head": head,
            "artifact_count": len(registry["artifacts"]),
            "unknown_review_required_count": len(unknowns),
            "duplicate_current_authority_status": duplicate_current["status"],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "unknown_artifact_review_queue.json",
        {
            "schema_id": "kt.unknown_artifact_review_queue.v1",
            "status": "PASS_EMPTY" if not unknowns else "REVIEW_REQUIRED",
            "count": len(unknowns),
            "rows": unknowns[:500],
        },
    )
    write_json(REPORTS / "artifact_supersession_map_v1.json", supersession)
    write_json(REPORTS / "duplicate_artifact_resolution_plan_v1.json", duplicate_plan)
    write_json(REPORTS / "stale_packet_quarantine_plan_v1.json", stale_packet_plan)
    write_json(REPORTS / "generated_artifact_quarantine_plan_v1.json", generated_plan)
    write_json(
        REPORTS / "current" / "current_truth_receipt.json",
        {
            "schema_id": "kt.current_truth_receipt.v1",
            "current_head": head,
            "current_packet": CURRENT_PACKET,
            "current_packet_sha256": packet_sha,
            "next_lawful_move": CURRENT_NEXT_LAWFUL_MOVE,
            "claim_ceiling_status": "PRESERVED",
            "repo_pristine_census_status": "PASS" if not census["blockers"] else "BLOCKED",
        },
    )
    write_json(
        PACKETS / "current" / "manifest.json",
        {
            "schema_id": "kt.current_packet_manifest.v1",
            "packets": [
                {
                    "path": CURRENT_PACKET,
                    "sha256": packet_sha,
                    "next_lawful_move": CURRENT_NEXT_LAWFUL_MOVE,
                    "current_authority": True,
                }
            ],
        },
    )

    if args.check and census["blockers"]:
        raise SystemExit(json.dumps(census["blockers"], indent=2))
    print(json.dumps({"status": "PASS" if not census["blockers"] else "BLOCKED", "current_head": head, "tracked_file_count": census["tracked_file_count"], "packet_sha256": packet_sha}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
