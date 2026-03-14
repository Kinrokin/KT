from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from tools.operator.titanium_common import (
    load_json,
    repo_root,
    semantically_equal_json,
    utc_now_iso_z,
    write_json_stable,
)


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP4_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_historical_memory_ingestion_receipt.json"
TRUST_ZONE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"

SNAPSHOT_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_snapshot_manifest.json"
PHYSICAL_INVENTORY_REL = f"{REPORT_ROOT_REL}/kt_physical_inventory.json"
PARSE_RESULTS_REL = f"{REPORT_ROOT_REL}/kt_parse_results.json"
PARSE_FAILURES_REL = f"{REPORT_ROOT_REL}/kt_parse_failures.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_snapshot_inventory_compilation_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/snapshot_inventory_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_snapshot_inventory_compile.py"

DELIVERABLE_REFS = [SNAPSHOT_MANIFEST_REL, PHYSICAL_INVENTORY_REL, PARSE_RESULTS_REL, PARSE_FAILURES_REL]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)

RESIDUE_PREFIXES = (
    ".pytest_cache/",
    ".venv/",
    "exports/",
    "tmp/",
    "KT_PROD_CLEANROOM/exports/",
)

CRITICAL_PREFIXES = (
    "KT_PROD_CLEANROOM/governance/",
    "KT_PROD_CLEANROOM/tools/operator/",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "KT_PROD_CLEANROOM/reports/",
    "KT_PROD_CLEANROOM/exports/_truth/",
)

BINARY_SUFFIXES = {
    ".bin",
    ".ckpt",
    ".cpython-310-pytest-9.0.2.pyc",
    ".cpython-310.pyc",
    ".db",
    ".dll",
    ".exe",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".onnx",
    ".pdf",
    ".png",
    ".pt",
    ".pyc",
    ".safetensors",
    ".so",
    ".zip",
}

TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".css",
    ".csv",
    ".gitattributes",
    ".gitignore",
    ".hash",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsonl",
    ".md",
    ".op1",
    ".op2",
    ".ps1",
    ".pub",
    ".py",
    ".schema.json",
    ".sh",
    ".svg",
    ".tla",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _git_history_for_paths(root: Path, paths: Sequence[str]) -> List[str]:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "log", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    try:
        output = _git(root, "show", "--pretty=", "--name-only", commit)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not str(older).strip() or not str(newer).strip():
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_path_set(root: Path, *args: str) -> Set[str]:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-z", *args],
            text=False,
            stderr=subprocess.DEVNULL,
        )
    except Exception:  # noqa: BLE001
        return set()
    return {item.decode("utf-8").replace("\\", "/") for item in output.split(b"\x00") if item}


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _matches_any(relpath: str, patterns: Sequence[str]) -> bool:
    rel = str(relpath).replace("\\", "/")
    rel_path = Path(rel)
    for pattern in patterns:
        pattern_norm = str(pattern).replace("\\", "/")
        if rel_path.match(pattern_norm):
            return True
        wildcard_positions = [idx for idx in (pattern_norm.find("*"), pattern_norm.find("?"), pattern_norm.find("[")) if idx >= 0]
        base = pattern_norm[: min(wildcard_positions)] if wildcard_positions else pattern_norm
        if base and rel.startswith(base):
            return True
    return False


def _zone_rows(root: Path) -> List[Dict[str, Any]]:
    registry = _load_required(root, TRUST_ZONE_REGISTRY_REL)
    rows = registry.get("zones")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: trust_zone_registry zones missing")
    return [row for row in rows if isinstance(row, dict)]


def _step_context(root: Path) -> Dict[str, Any]:
    step4 = _load_required(root, STEP4_RECEIPT_REL)
    if str(step4.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 5 is blocked until Step 4 historical memory ingestion is PASS.")
    return {
        "step4_receipt": step4,
        "step4_evidence_commit": _git_last_commit_for_paths(root, [STEP4_RECEIPT_REL]),
        "work_order": _load_required(root, WORK_ORDER_REL),
        "zone_rows": _zone_rows(root),
    }


def _iter_repo_files(root: Path) -> Iterable[Tuple[str, Path]]:
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        filenames.sort()
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            rel = path.relative_to(root).as_posix()
            yield rel, path


def _snapshot_scope_paths(root: Path, tracking_sets: Dict[str, Set[str]]) -> List[Tuple[str, Path]]:
    scope = sorted(tracking_sets["tracked"] | tracking_sets["untracked"])
    rows: List[Tuple[str, Path]] = []
    for rel in scope:
        path = (root / Path(rel)).resolve()
        if path.exists() and path.is_file():
            rows.append((rel.replace("\\", "/"), path))
    return rows


def _ignored_residue_summary(ignored_paths: Set[str]) -> Dict[str, Any]:
    buckets: Dict[str, int] = {
        ".pytest_cache": 0,
        ".venv": 0,
        "__pycache__": 0,
        "KT_PROD_CLEANROOM/exports": 0,
        "exports": 0,
        "other_ignored": 0,
    }
    for rel in ignored_paths:
        normalized = str(rel).replace("\\", "/")
        if normalized.startswith(".pytest_cache/"):
            buckets[".pytest_cache"] += 1
        elif normalized.startswith(".venv/"):
            buckets[".venv"] += 1
        elif "/__pycache__/" in f"/{normalized}" or normalized.startswith("__pycache__/"):
            buckets["__pycache__"] += 1
        elif normalized.startswith("KT_PROD_CLEANROOM/exports/"):
            buckets["KT_PROD_CLEANROOM/exports"] += 1
        elif normalized.startswith("exports/"):
            buckets["exports"] += 1
        else:
            buckets["other_ignored"] += 1
    return {
        "ignored_residue_file_count": len(ignored_paths),
        "buckets": buckets,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _looks_binary(prefix: bytes) -> bool:
    if b"\x00" in prefix:
        return True
    if not prefix:
        return False
    text_bytes = set(range(32, 127)) | {9, 10, 13}
    nontext = sum(1 for byte in prefix if byte not in text_bytes)
    return nontext / len(prefix) > 0.3


def _tracking_sets(root: Path) -> Dict[str, Set[str]]:
    return {
        "tracked": _git_path_set(root),
        "untracked": _git_path_set(root, "--others", "--exclude-standard"),
        "ignored": _git_path_set(root, "--others", "-i", "--exclude-standard"),
    }


def _tracking_status(rel: str, tracking_sets: Dict[str, Set[str]]) -> str:
    if rel in tracking_sets["tracked"]:
        return "tracked"
    if rel in tracking_sets["untracked"]:
        return "untracked"
    if rel in tracking_sets["ignored"]:
        return "ignored"
    return "untracked"


def _is_residue_path(rel: str) -> bool:
    normalized = str(rel).replace("\\", "/")
    if any(normalized.startswith(prefix) for prefix in RESIDUE_PREFIXES):
        return True
    return "/__pycache__/" in f"/{normalized}"


def _trust_zone(rel: str, tracking_status: str, zone_rows: Sequence[Dict[str, Any]]) -> str:
    normalized = str(rel).replace("\\", "/")

    if _is_residue_path(normalized):
        if normalized.startswith("KT_PROD_CLEANROOM/exports/_truth/"):
            return "GENERATED_RUNTIME_TRUTH"
        if normalized.startswith("exports/") or normalized.startswith("KT_PROD_CLEANROOM/exports/"):
            return "GENERATED_RUNTIME_TRUTH"
        return "QUARANTINED"
    if normalized == ".env.secret":
        return "QUARANTINED"
    if normalized.startswith("KT_PROD_CLEANROOM/tests/"):
        if normalized.startswith("KT_PROD_CLEANROOM/tests/growth/") or normalized.startswith("KT_PROD_CLEANROOM/tests/policy_c/") or normalized.startswith("KT_PROD_CLEANROOM/tests/fl4/"):
            return "LAB"
        return "CANONICAL"
    if normalized == "AGENTS.md":
        return "CANONICAL"

    for row in zone_rows:
        zone_id = str(row.get("zone_id", "")).strip().upper()
        includes = [str(item).strip() for item in row.get("include", []) if str(item).strip()]
        excludes = [str(item).strip() for item in row.get("exclude", []) if str(item).strip()]
        if includes and _matches_any(normalized, includes) and not _matches_any(normalized, excludes):
            return zone_id

    if tracking_status == "ignored":
        return "QUARANTINED"
    if normalized.startswith("KT_PROD_CLEANROOM/reports/") or normalized.startswith("KT_PROD_CLEANROOM/exports/"):
        return "GENERATED_RUNTIME_TRUTH"
    return "QUARANTINED"


def _generation_status(rel: str, tracking_status: str) -> str:
    normalized = str(rel).replace("\\", "/")
    if normalized.startswith(".venv/"):
        return "vendored"
    if _is_residue_path(normalized) or normalized.startswith("KT_PROD_CLEANROOM/reports/") or normalized.startswith("KT_PROD_CLEANROOM/exports/") or normalized.startswith("exports/"):
        return "generated"
    if normalized.startswith("KT-Codex/") or tracking_status == "tracked":
        return "authored"
    return "unknown"


def _file_type(rel: str) -> str:
    normalized = str(rel).replace("\\", "/")
    chain = "".join(Path(normalized).suffixes).lower()
    last = Path(normalized).suffix.lower()
    name = Path(normalized).name

    if chain.endswith(".schema.json"):
        return "json_schema"
    if chain.endswith(".jsonl"):
        return "jsonl"
    if chain.endswith(".json"):
        return "json"
    if last == ".py":
        return "python"
    if last == ".md":
        return "markdown"
    if last == ".csv":
        return "csv"
    if last in {".yaml", ".yml"}:
        return "yaml"
    if last == ".toml":
        return "toml"
    if last in {".ini", ".cfg", ".conf"}:
        return "ini"
    if last == ".ps1":
        return "powershell"
    if last == ".sh":
        return "shell"
    if last in {".html", ".svg", ".xml"}:
        return "markup"
    if last == ".css":
        return "css"
    if last == ".js":
        return "javascript"
    if last in {".hash", ".pub", ".op1", ".op2"}:
        return "text_signature"
    if chain in BINARY_SUFFIXES or last in BINARY_SUFFIXES:
        return "binary"
    if name in {".gitignore", ".gitattributes", "LICENSE", "README", "README.md", "runbook.txt"} or not last:
        return "text"
    return "unknown"


def _decode_text_bytes(raw: bytes, *, allow_legacy_text: bool) -> str:
    encodings = ("utf-8-sig",)
    if allow_legacy_text:
        encodings = encodings + ("cp1252",)
    last_error: Optional[UnicodeDecodeError] = None
    for encoding in encodings:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError as exc:
            last_error = exc
    if last_error is None:
        raise UnicodeDecodeError("utf-8", b"", 0, 1, "unknown_decode_error")
    raise last_error


def _text_parser_result(path: Path) -> Tuple[str, str]:
    try:
        _decode_text_bytes(path.read_bytes(), allow_legacy_text=True)
    except UnicodeDecodeError as exc:
        return "parse_failed", f"utf8_decode_error:{exc.reason}"
    return "parseable", ""


def _structured_parser_result(path: Path, file_type: str) -> Tuple[str, str]:
    try:
        text = _decode_text_bytes(path.read_bytes(), allow_legacy_text=False)
        if file_type in {"json", "json_schema"}:
            json.loads(text)
        elif file_type == "jsonl":
            for line in text.splitlines():
                    raw = str(line).strip()
                    if raw:
                        json.loads(raw)
        elif file_type == "csv":
            list(csv.reader(text.splitlines()))
        elif file_type == "python":
            ast.parse(text, filename=path.as_posix())
        else:
            return _text_parser_result(path)
    except UnicodeDecodeError as exc:
        return "parse_failed", f"utf8_decode_error:{exc.reason}"
    except json.JSONDecodeError as exc:
        return "parse_failed", f"json_decode_error:{exc.msg}"
    except SyntaxError as exc:
        return "parse_failed", f"syntax_error:{exc.msg}"
    except csv.Error as exc:
        return "parse_failed", f"csv_error:{str(exc)}"
    return "parseable", ""


def _parse_state(path: Path, rel: str, file_type: str, tracking_status: str) -> Tuple[str, str, str]:
    normalized = str(rel).replace("\\", "/")
    parser_family = "opaque"

    if _is_residue_path(normalized) and tracking_status == "ignored":
        return "opaque", "residue_opaque", "ignored_runtime_residue"

    prefix = b""
    with path.open("rb") as handle:
        prefix = handle.read(8192)

    chain = "".join(path.suffixes).lower()
    if chain in BINARY_SUFFIXES or path.suffix.lower() in BINARY_SUFFIXES:
        return "opaque", "binary_suffix", "binary_suffix"
    if file_type in {"json", "json_schema", "jsonl", "csv", "python"}:
        state, reason = _structured_parser_result(path, file_type)
        return state, file_type, reason
    if file_type in {"markdown", "yaml", "toml", "ini", "powershell", "shell", "markup", "css", "javascript", "text_signature", "text"}:
        if _looks_binary(prefix):
            return "opaque", "opaque", "binary_detected"
        state, reason = _text_parser_result(path)
        return state, "utf8_text", reason
    if _looks_binary(prefix):
        return "opaque", parser_family, "binary_detected"
    state, reason = _text_parser_result(path)
    return state, "utf8_text", reason


def _taints_state(rel: str, parse_state: str) -> Tuple[bool, str]:
    normalized = str(rel).replace("\\", "/")
    if parse_state == "parseable":
        return False, ""
    if _is_residue_path(normalized):
        return False, ""
    if any(normalized.startswith(prefix) for prefix in CRITICAL_PREFIXES):
        if parse_state == "opaque":
            return True, "opaque_artifact_in_critical_path"
        return True, "parse_failed_in_critical_path"
    return False, ""


def _snapshot_id(head: str, files: Sequence[Dict[str, Any]]) -> str:
    digest = hashlib.sha256(json.dumps(list(files), sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
    return f"kt_snapshot::{head}::{len(files)}::{digest}"


def _collect_inventory(root: Path, *, generated_utc: str) -> Dict[str, Any]:
    ctx = _step_context(root)
    head = _git_head(root)
    tracking_sets = _tracking_sets(root)
    zone_rows = ctx["zone_rows"]

    manifest_files: List[Dict[str, Any]] = []
    inventory_rows: List[Dict[str, Any]] = []
    parse_failed_files: List[Dict[str, Any]] = []
    tainting_files: List[Dict[str, Any]] = []

    parse_state_counts: Dict[str, int] = {"opaque": 0, "parse_failed": 0, "parseable": 0}
    generation_counts: Dict[str, int] = {"authored": 0, "generated": 0, "vendored": 0, "unknown": 0}
    tracking_counts: Dict[str, int] = {"tracked": 0, "untracked": 0, "ignored": 0}
    trust_zone_counts: Dict[str, int] = {zone: 0 for zone in ("CANONICAL", "LAB", "ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "QUARANTINED")}
    parser_family_counts: Dict[str, int] = {}
    opaque_counts_by_zone: Dict[str, int] = {zone: 0 for zone in trust_zone_counts}

    scope_rows = _snapshot_scope_paths(root, tracking_sets)
    ignored_summary = _ignored_residue_summary(tracking_sets["ignored"])

    for rel, path in scope_rows:
        stat = path.stat()
        tracking_status = _tracking_status(rel, tracking_sets)
        trust_zone = _trust_zone(rel, tracking_status, zone_rows)
        generation_status = _generation_status(rel, tracking_status)
        file_type = _file_type(rel)
        parse_state, parser_family, parse_reason = _parse_state(path, rel, file_type, tracking_status)
        taints_state, taint_reason = _taints_state(rel, parse_state)
        sha256 = _sha256_file(path)

        manifest_entry = {
            "path": rel,
            "size_bytes": int(stat.st_size),
            "file_type": file_type,
            "sha256": sha256,
            "generation_status": generation_status,
            "parse_state": parse_state,
            "trust_zone": trust_zone,
        }
        manifest_files.append(manifest_entry)

        inventory_rows.append(
            {
                "path": rel,
                "tracking_status": tracking_status,
                "parser_family": parser_family,
                "parse_reason": parse_reason,
                "taints_state": taints_state,
                "taint_reason": taint_reason,
            }
        )

        parse_state_counts[parse_state] = parse_state_counts.get(parse_state, 0) + 1
        generation_counts[generation_status] = generation_counts.get(generation_status, 0) + 1
        tracking_counts[tracking_status] = tracking_counts.get(tracking_status, 0) + 1
        trust_zone_counts[trust_zone] = trust_zone_counts.get(trust_zone, 0) + 1
        parser_family_counts[parser_family] = parser_family_counts.get(parser_family, 0) + 1
        if parse_state == "opaque":
            opaque_counts_by_zone[trust_zone] = opaque_counts_by_zone.get(trust_zone, 0) + 1
        if parse_state == "parse_failed":
            parse_failed_files.append(
                {
                    "path": rel,
                    "file_type": file_type,
                    "parse_reason": parse_reason,
                    "parser_family": parser_family,
                    "tracking_status": tracking_status,
                    "trust_zone": trust_zone,
                    "taints_state": taints_state,
                    "taint_reason": taint_reason,
                }
            )
        if taints_state:
            tainting_files.append(
                {
                    "path": rel,
                    "parse_state": parse_state,
                    "parser_family": parser_family,
                    "taint_reason": taint_reason,
                    "trust_zone": trust_zone,
                }
            )

    manifest_files.sort(key=lambda row: row["path"])
    inventory_rows.sort(key=lambda row: row["path"])
    parse_failed_files.sort(key=lambda row: row["path"])
    tainting_files.sort(key=lambda row: row["path"])

    state_taint_status = "STATE_TAINTED" if tainting_files else "CLEAR"
    snapshot_id = _snapshot_id(head, manifest_files)

    manifest = {
        "schema_id": "kt.operator.snapshot_manifest.v1",
        "snapshot_id": snapshot_id,
        "generated_utc": generated_utc,
        "repo_root": root.as_posix(),
        "source_head_commit": head,
        "state_taint_status": state_taint_status,
        "files": manifest_files,
    }

    physical_inventory = {
        "schema_id": "kt.operator.physical_inventory.v1",
        "generated_utc": generated_utc,
        "snapshot_manifest_ref": SNAPSHOT_MANIFEST_REL,
        "source_head_commit": head,
        "coverage": {
            "inventory_file_count": len(manifest_files),
            "snapshot_scope_file_count": len(scope_rows),
            "tracking_counts": tracking_counts,
            "trust_zone_counts": trust_zone_counts,
            "generation_status_counts": generation_counts,
            "parse_state_counts": parse_state_counts,
            "ignored_residue_summary": ignored_summary,
        },
        "files": inventory_rows,
    }

    parse_results = {
        "schema_id": "kt.operator.parse_results.v1",
        "generated_utc": generated_utc,
        "snapshot_manifest_ref": SNAPSHOT_MANIFEST_REL,
        "source_head_commit": head,
        "state_taint_status": state_taint_status,
        "summary": {
            "parseable_file_count": parse_state_counts.get("parseable", 0),
            "opaque_file_count": parse_state_counts.get("opaque", 0),
            "parse_failed_file_count": parse_state_counts.get("parse_failed", 0),
            "parser_family_counts": dict(sorted(parser_family_counts.items())),
            "trust_zone_parse_state_counts": {
                zone: {
                    "opaque": opaque_counts_by_zone.get(zone, 0),
                }
                for zone in sorted(trust_zone_counts.keys())
            },
        },
    }

    parse_failures = {
        "schema_id": "kt.operator.parse_failures.v1",
        "generated_utc": generated_utc,
        "snapshot_manifest_ref": SNAPSHOT_MANIFEST_REL,
        "source_head_commit": head,
        "state_taint_status": state_taint_status,
        "taint_rule": "If an opaque or parse_failed artifact contaminates a sovereign or critical runtime path, mark STATE_TAINTED and block downstream proof promotion until isolated or resolved.",
        "parse_failed_files": parse_failed_files,
        "tainting_files": tainting_files,
        "opaque_counts_by_zone": {zone: opaque_counts_by_zone.get(zone, 0) for zone in sorted(opaque_counts_by_zone.keys())},
    }

    return {
        "manifest": manifest,
        "physical_inventory": physical_inventory,
        "parse_results": parse_results,
        "parse_failures": parse_failures,
    }


def build_snapshot_reports(*, root: Path, generated_utc: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    return _collect_inventory(root, generated_utc=generated_utc or utc_now_iso_z())


def build_snapshot_inventory_report(*, root: Path) -> Dict[str, Any]:
    ctx = _step_context(root)
    generated_utc = utc_now_iso_z()
    first = build_snapshot_reports(root=root, generated_utc=generated_utc)
    second = build_snapshot_reports(root=root, generated_utc=generated_utc)

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    def _status_row(*, check: str, passed: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
        return {"check": check, "detail": detail, "refs": list(refs), "status": "PASS" if passed else "FAIL"}

    prior_gate_ok = str(ctx["step4_receipt"].get("status", "")).strip() == "PASS"
    checks.append(
        _status_row(
            check="prior_gate_passed",
            passed=prior_gate_ok,
            detail="Step 5 requires the Step 4 historical memory ingestion receipt to be PASS.",
            refs=[STEP4_RECEIPT_REL],
        )
    )
    if not prior_gate_ok:
        failures.append("prior_gate_passed")

    manifest = first["manifest"]
    physical_inventory = first["physical_inventory"]
    parse_results = first["parse_results"]
    parse_failures = first["parse_failures"]

    coverage_ok = int(physical_inventory["coverage"]["inventory_file_count"]) == int(physical_inventory["coverage"]["snapshot_scope_file_count"]) == len(manifest["files"])
    checks.append(
        _status_row(
            check="full_file_inventory_coverage",
            passed=coverage_ok,
            detail="The deterministic snapshot scope must cover every tracked file plus explicit nonignored untracked files; ignored residue is summarized separately.",
            refs=[SNAPSHOT_MANIFEST_REL, PHYSICAL_INVENTORY_REL],
        )
    )
    if not coverage_ok:
        failures.append("full_file_inventory_coverage")

    required_fields = {"path", "size_bytes", "file_type", "sha256", "generation_status", "parse_state", "trust_zone"}
    fields_ok = all(required_fields.issubset(set(row.keys())) for row in manifest["files"])
    checks.append(
        _status_row(
            check="every_file_has_required_fields",
            passed=fields_ok,
            detail="Every file entry must carry path, size, type, hash, generation status, parse state, and trust zone.",
            refs=[SNAPSHOT_MANIFEST_REL],
        )
    )
    if not fields_ok:
        failures.append("every_file_has_required_fields")

    parse_failures_ok = len(parse_failures["parse_failed_files"]) == int(parse_results["summary"]["parse_failed_file_count"])
    checks.append(
        _status_row(
            check="parse_failures_explicit",
            passed=parse_failures_ok,
            detail="Parse failures must be explicit and count-consistent with the parse results summary.",
            refs=[PARSE_RESULTS_REL, PARSE_FAILURES_REL],
        )
    )
    if not parse_failures_ok:
        failures.append("parse_failures_explicit")

    deterministic_ok = all(semantically_equal_json(first[key], second[key]) for key in ("manifest", "physical_inventory", "parse_results", "parse_failures"))
    checks.append(
        _status_row(
            check="deterministic_rerun_semantics",
            passed=deterministic_ok,
            detail="A second compiler run over the same head must reproduce semantically identical outputs.",
            refs=[SNAPSHOT_MANIFEST_REL, PHYSICAL_INVENTORY_REL, PARSE_RESULTS_REL, PARSE_FAILURES_REL],
        )
    )
    if not deterministic_ok:
        failures.append("deterministic_rerun_semantics")

    taint_consistent = manifest["state_taint_status"] == parse_results["state_taint_status"] == parse_failures["state_taint_status"]
    checks.append(
        _status_row(
            check="state_taint_status_consistent",
            passed=taint_consistent,
            detail="Manifest, parse results, and parse failures must agree on state taint status.",
            refs=[SNAPSHOT_MANIFEST_REL, PARSE_RESULTS_REL, PARSE_FAILURES_REL],
        )
    )
    if not taint_consistent:
        failures.append("state_taint_status_consistent")

    subject_commit = _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS)
    current_head_commit = _git_head(root)
    subject_history = _git_history_for_paths(root, SUBJECT_ARTIFACT_REFS)
    earliest_subject_commit = subject_history[-1] if subject_history else ""
    step_baseline_commit = _git_parent(root, earliest_subject_commit)
    actual_subject_touched = _git_diff_files(root, step_baseline_commit, subject_commit, SUBJECT_ARTIFACT_REFS)
    if not actual_subject_touched:
        actual_subject_touched = _git_changed_files(root, subject_commit)
    actual_touched = sorted(set(actual_subject_touched + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = sorted(path for path in actual_touched if _is_protected(path))
    post_touch_ok = set(actual_touched) == set(PLANNED_MUTATES) and not unexpected_touches and not protected_touch_violations

    checks.append(
        _status_row(
            check="post_touch_accounting_clean",
            passed=post_touch_ok,
            detail="Actual touched set must match the lawful Step 5 subject files plus the compilation receipt.",
            refs=PLANNED_MUTATES,
        )
    )
    if not post_touch_ok:
        failures.append("post_touch_accounting_clean")

    status = "PASS" if not failures else "FAIL_CLOSED"
    taint_status = manifest["state_taint_status"]
    next_step_status = "UNLOCKED" if status == "PASS" and taint_status == "CLEAR" else "BLOCKED"
    verdict = "SNAPSHOT_AND_INVENTORY_COMPILED" if status == "PASS" else "SNAPSHOT_OR_INVENTORY_NONDETERMINISTIC_FAIL_CLOSED"

    return {
        "schema_id": "kt.operator.snapshot_inventory_compilation_receipt.v1",
        "generated_utc": generated_utc,
        "status": status,
        "pass_verdict": verdict,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 5,
            "step_name": "SNAPSHOT_DETERMINISM_AND_PHYSICAL_INVENTORY",
        },
        "step4_gate_subject_commit": str(ctx["step4_receipt"].get("compiled_head_commit", "")).strip(),
        "step4_gate_evidence_commit": str(ctx["step4_evidence_commit"]).strip(),
        "compiled_head_commit": subject_commit,
        "current_head_commit": current_head_commit,
        "state_taint_status": taint_status,
        "claim_boundary": (
            "This receipt validates Step 5 snapshot determinism and physical inventory for compiled_head_commit only. "
            "A later repository head that contains this receipt is evidence about compiled_head_commit, not automatically that compiled head."
        ),
        "planned_mutates": list(PLANNED_MUTATES),
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "checks": checks,
        "next_lawful_step": {
            "step_id": 6,
            "step_name": "STRUCTURAL_PARSE_TAG_CATALOG_AND_GRAPH_COMPILATION",
            "status_after_step_5": next_step_status,
        },
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile deterministic snapshot manifest, physical inventory, parse results, and parse failures.")
    parser.add_argument("--root", default="", help="Optional repository root override.")
    parser.add_argument("--emit-receipt", action="store_true", help="Write the Step 5 receipt instead of the subject deliverables.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(str(args.root)).resolve() if str(args.root).strip() else repo_root()

    if bool(args.emit_receipt):
        report = build_snapshot_inventory_report(root=root)
        write_json_stable((root / Path(RECEIPT_REL)).resolve(), report)
        print(
            json.dumps(
                {
                    "status": report["status"],
                    "pass_verdict": report["pass_verdict"],
                    "compiled_head_commit": report["compiled_head_commit"],
                    "current_head_commit": report["current_head_commit"],
                    "state_taint_status": report["state_taint_status"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if report["status"] == "PASS" else 1

    reports = build_snapshot_reports(root=root)
    payloads = {
        SNAPSHOT_MANIFEST_REL: reports["manifest"],
        PHYSICAL_INVENTORY_REL: reports["physical_inventory"],
        PARSE_RESULTS_REL: reports["parse_results"],
        PARSE_FAILURES_REL: reports["parse_failures"],
    }

    writes: List[Dict[str, Any]] = []
    for rel, payload in payloads.items():
        changed = write_json_stable((root / Path(rel)).resolve(), payload)
        writes.append({"artifact_ref": rel, "updated": changed, "schema_id": str(payload.get("schema_id", "")).strip()})

    print(json.dumps({"status": "PASS", "artifacts_written": writes}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
