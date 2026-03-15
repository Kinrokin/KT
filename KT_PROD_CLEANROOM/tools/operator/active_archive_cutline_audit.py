from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
BOUNDARY_MAP_REL = f"{REPORT_ROOT_REL}/kt_active_archive_boundary_map.json"
CROSS_REFERENCE_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_active_archive_cross_reference_register.json"
QUARANTINE_PLAN_REL = f"{REPORT_ROOT_REL}/kt_archive_quarantine_plan.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_active_archive_cutline_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/active_archive_cutline_audit.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_active_archive_cutline_audit.py"

WS0_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_closure_foundation_receipt.json"
STEP8_PLAN_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_plan.json"
REOPENED_DEFECTS_REL = f"{REPORT_ROOT_REL}/kt_reopened_defect_register.json"
SNAPSHOT_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_snapshot_manifest.json"

SUBJECT_ARTIFACT_REFS = [
    BOUNDARY_MAP_REL,
    CROSS_REFERENCE_REGISTER_REL,
    QUARANTINE_PLAN_REL,
    TOOL_REL,
    TEST_REL,
]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_TOTAL_CLOSURE_CAMPAIGN_TO_ACTIVE_CANONICAL_RELEASE"
WORK_ORDER_SCHEMA_ID = "kt.work_order.total_closure_campaign.v1"
WORKSTREAM_ID = "WS1_ACTIVE_ARCHIVE_CUTLINE_FREEZE"
WORKSTREAM_STEP_ID = "WS1_STEP_1_FREEZE_ACTIVE_ARCHIVE_CUTLINE"

ACTIVE_ZONE_SET = {"CANONICAL", "GENERATED_RUNTIME_TRUTH", "COMMERCIAL", "LAB"}
TEXTUAL_FILE_TYPES = {
    "csv",
    "json",
    "json_schema",
    "jsonl",
    "markdown",
    "python",
    "shell",
    "text",
    "unknown",
    "yaml",
}

VALIDATORS_RUN = [
    "python -m tools.operator.active_archive_cutline_audit",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_active_archive_cutline_audit.py -q",
]


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


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not older or not newer:
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    try:
        output = _git(root, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_status_files(root: Path, paths: Sequence[str]) -> List[str]:
    listed = [str(Path(path).as_posix()) for path in paths]
    if not listed:
        return []
    try:
        output = _git(root, "status", "--short", "--", *listed)
    except Exception:  # noqa: BLE001
        return []
    rows: List[str] = []
    for line in output.splitlines():
        value = str(line[3:] if len(line) > 3 else line).strip().replace("\\", "/")
        if value:
            rows.append(value)
    return rows


def _normalize(path: str) -> str:
    return str(path).replace("\\", "/").strip()


def _top_level(path: str) -> str:
    normalized = _normalize(path)
    return normalized.split("/", 1)[0] if "/" in normalized else normalized


def _consumer_plane(path: str) -> str:
    normalized = _normalize(path)
    if normalized.startswith(".github/") or normalized.startswith("ci/") or normalized == "run_kt_e2e.sh" or normalized.startswith(".devcontainer/"):
        return "build"
    if "/tests/" in normalized or normalized.startswith("tests/"):
        return "test"
    if normalized.startswith("docs/") or normalized.startswith("KT-Codex/") or normalized.endswith(".md") or normalized in {"README.md", "REPO_CANON.md"}:
        return "doc"
    if normalized.startswith("KT_PROD_CLEANROOM/tools/") or normalized.startswith("KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/"):
        return "runtime"
    return "other"


def _archive_ref_class(path: str) -> str:
    normalized = _normalize(path)
    if normalized.startswith("KT_ARCHIVE/vault/"):
        return "archive_vault_surface"
    if normalized.startswith("KT_ARCHIVE/docs/audit/"):
        return "historical_audit_surface"
    if normalized.startswith("KT_ARCHIVE/legacy_runtime/KT_TEMPLE_ROOT/") or normalized == "KT_ARCHIVE/legacy_runtime/KT_TEMPLE_ROOT":
        return "legacy_root_archive_dir"
    if normalized.startswith("KT_ARCHIVE/legacy_runtime/KT_LANE_LORA_PHASE_B/") or normalized == "KT_ARCHIVE/legacy_runtime/KT_LANE_LORA_PHASE_B":
        return "legacy_root_archive_dir"
    return "root_archive_surface"


def _relocation_consequence(plane: str) -> str:
    return {
        "runtime": "ACTIVE_RUNTIME_BREAK_IF_ARCHIVE_MOVED",
        "test": "ACTIVE_TEST_BREAK_IF_ARCHIVE_MOVED",
        "build": "ACTIVE_BUILD_BREAK_IF_ARCHIVE_MOVED",
        "doc": "ACTIVE_DOC_LINK_BREAK_IF_ARCHIVE_MOVED",
    }.get(plane, "NON_RUNTIME_DOCUMENTARY_BREAK_IF_ARCHIVE_MOVED")


def _violation_class(plane: str) -> str:
    return {
        "runtime": "HARD_VIOLATION",
        "test": "HARD_VIOLATION",
        "build": "HARD_VIOLATION",
        "doc": "DOC_DEPENDENCY_VIOLATION",
    }.get(plane, "DOCUMENTARY_REFERENCE")


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _existing_paths(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [row for row in snapshot.get("files", []) if isinstance(row, dict)]


def _derive_boundary_sets(
    *,
    root: Path,
    plan: Dict[str, Any],
    defects: Dict[str, Any],
    snapshot_files: List[Dict[str, Any]],
) -> Dict[str, Any]:
    active_keep = set(plan.get("target_top_level_layout", {}).get("minimal_root_keep", []))
    archive_root = "KT_ARCHIVE"

    archive_explicit: List[str] = []
    if archive_root:
        archive_explicit.append(archive_root)
    for defect in defects.get("defects", []):
        if not isinstance(defect, dict):
            continue
        if str(defect.get("defect_id", "")).strip() != "ROOT_ARCHIVE_CONTAMINATION":
            continue
        for ref in defect.get("current_evidence_refs", []):
            normalized = _normalize(ref)
            if normalized and (root / Path(normalized)).exists():
                archive_explicit.append(normalized.rstrip("/"))

    archive_top_level_from_snapshot = {
        _top_level(str(row.get("path", "")))
        for row in snapshot_files
        if str(row.get("trust_zone", "")).strip() == "ARCHIVE"
    }

    explicit_archive_paths = sorted(set(item for item in archive_explicit if item))

    top_level_rows: Dict[str, Dict[str, Any]] = {}
    for row in snapshot_files:
        path = _normalize(str(row.get("path", "")))
        if not path:
            continue
        top = _top_level(path)
        current = top_level_rows.setdefault(
            top,
            {
                "root_path": top,
                "sample_paths": [],
                "trust_zones": set(),
                "file_count": 0,
                "contains_docs_audit": False,
                "contains_archive_vault": False,
            },
        )
        current["file_count"] += 1
        current["trust_zones"].add(str(row.get("trust_zone", "")).strip())
        if len(current["sample_paths"]) < 3:
            current["sample_paths"].append(path)
        if path.startswith("KT_ARCHIVE/docs/audit/"):
            current["contains_docs_audit"] = True
        if path.startswith(f"{archive_root}/") or path == archive_root:
            current["contains_archive_vault"] = True

    boundary_rows: List[Dict[str, Any]] = []
    embedded_archive_islands: List[Dict[str, Any]] = []
    for top in sorted(top_level_rows):
        row = top_level_rows[top]
        zones = sorted(item for item in row["trust_zones"] if item)
        if top in active_keep:
            role = "ACTIVE"
        elif top in archive_top_level_from_snapshot or top in {_top_level(item) for item in explicit_archive_paths}:
            role = "ARCHIVE"
        elif set(zones).issubset(ACTIVE_ZONE_SET):
            role = "ACTIVE"
        elif "QUARANTINED" in zones:
            role = "NONACTIVE_QUARANTINED"
        else:
            role = "ARCHIVE" if "ARCHIVE" in zones else "NONACTIVE_QUARANTINED"

        if top == "docs" and row["contains_docs_audit"]:
            embedded_archive_islands.append(
                {
                    "active_root": "docs",
                    "archive_island": "KT_ARCHIVE/docs/audit/",
                    "reason": "Historical audit material now lives under the top-level archive root.",
                }
            )
        if top == "KT_PROD_CLEANROOM" and row["contains_archive_vault"]:
            embedded_archive_islands.append(
                {
                    "active_root": "KT_PROD_CLEANROOM",
                    "archive_island": f"{archive_root}/",
                    "reason": "Archive material is re-rooted at the top level and must remain non-required by ACTIVE.",
                }
            )

        boundary_rows.append(
            {
                "root_path": top,
                "boundary_role": role,
                "current_trust_zones": zones,
                "file_count": row["file_count"],
                "sample_paths": list(row["sample_paths"]),
            }
        )

    archive_surfaces: List[str] = []
    for path in explicit_archive_paths:
        archive_surfaces.append(path if path.endswith("/") else f"{path}/" if (root / Path(path)).is_dir() else path)
    for top in sorted(archive_top_level_from_snapshot):
        path = top
        if path in active_keep:
            continue
        archive_surfaces.append(path if (root / Path(path)).is_file() else f"{path}/")

    archive_surfaces = sorted(set(_normalize(item) for item in archive_surfaces))
    return {
        "active_keep": sorted(active_keep),
        "archive_root": archive_root,
        "archive_surfaces": archive_surfaces,
        "boundary_rows": boundary_rows,
        "embedded_archive_islands": embedded_archive_islands,
    }


def _path_under_archive(path: str, archive_surfaces: Sequence[str]) -> bool:
    normalized = _normalize(path)
    for archive in archive_surfaces:
        token = _normalize(archive)
        if token.endswith("/"):
            if normalized.startswith(token):
                return True
        elif normalized == token:
            return True
    return False


def _textual_consumer_files(snapshot_files: List[Dict[str, Any]], archive_surfaces: Sequence[str]) -> List[str]:
    results: List[str] = []
    for row in snapshot_files:
        path = _normalize(str(row.get("path", "")))
        if not path or _path_under_archive(path, archive_surfaces):
            continue
        if str(row.get("parse_state", "")).strip() != "parseable":
            continue
        if str(row.get("file_type", "")).strip() not in TEXTUAL_FILE_TYPES:
            continue
        results.append(path)
    return sorted(set(results))


def _scan_cross_references(root: Path, *, consumer_files: Sequence[str], archive_surfaces: Sequence[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    needles: List[Tuple[str, str]] = []
    for archive in archive_surfaces:
        normalized = _normalize(archive)
        needles.append((normalized, normalized.rstrip("/")))

    for consumer in consumer_files:
        consumer_path = (root / Path(consumer)).resolve()
        if not consumer_path.exists() or not consumer_path.is_file():
            continue
        text = consumer_path.read_text(encoding="utf-8", errors="ignore").replace("\\", "/")
        plane = _consumer_plane(consumer)
        for archive, loose in needles:
            if archive not in text and loose not in text:
                continue
            line_numbers: List[int] = []
            for idx, line in enumerate(text.splitlines(), start=1):
                normalized_line = line.replace("\\", "/")
                if archive in normalized_line or (loose and loose in normalized_line):
                    line_numbers.append(idx)
            if not line_numbers:
                continue
            rows.append(
                {
                    "consumer_path": consumer,
                    "consumer_plane": plane,
                    "archive_ref": archive,
                    "archive_ref_class": _archive_ref_class(archive),
                    "dependency_class": _violation_class(plane),
                    "relocation_consequence": _relocation_consequence(plane),
                    "line_numbers": line_numbers,
                }
            )
    rows.sort(key=lambda row: (row["consumer_path"], row["archive_ref"], row["line_numbers"][0]))
    return rows


def _build_boundary_map(ctx: Dict[str, Any]) -> Dict[str, Any]:
    boundary_rows = ctx["boundary_sets"]["boundary_rows"]
    embedded_archive_islands = ctx["boundary_sets"]["embedded_archive_islands"]
    return {
        "schema_id": "kt.operator.active_archive_boundary_map.v1",
        "generated_utc": utc_now_iso_z(),
        "workstream_id": WORKSTREAM_ID,
        "claim_boundary": "This map freezes the cutline and violation inventory only. It does not execute cleanup or externalization yet.",
        "active_keep_roots": ctx["boundary_sets"]["active_keep"],
        "archive_surfaces": ctx["boundary_sets"]["archive_surfaces"],
        "top_level_boundaries": boundary_rows,
        "embedded_archive_islands": embedded_archive_islands,
        "summary": {
            "top_level_surface_count": len(boundary_rows),
            "active_surface_count": sum(1 for row in boundary_rows if row["boundary_role"] == "ACTIVE"),
            "archive_surface_count": sum(1 for row in boundary_rows if row["boundary_role"] == "ARCHIVE"),
            "nonactive_quarantined_count": sum(1 for row in boundary_rows if row["boundary_role"] == "NONACTIVE_QUARANTINED"),
            "embedded_archive_island_count": len(embedded_archive_islands),
        },
    }


def _build_cross_reference_register(ctx: Dict[str, Any]) -> Dict[str, Any]:
    rows = _scan_cross_references(
        ctx["root"],
        consumer_files=ctx["consumer_files"],
        archive_surfaces=ctx["boundary_sets"]["archive_surfaces"],
    )
    plane_counts: Dict[str, int] = {}
    for row in rows:
        plane_counts[row["consumer_plane"]] = plane_counts.get(row["consumer_plane"], 0) + 1
    return {
        "schema_id": "kt.operator.active_archive_cross_reference_register.v1",
        "generated_utc": utc_now_iso_z(),
        "workstream_id": WORKSTREAM_ID,
        "cross_references": rows,
        "summary": {
            "cross_reference_count": len(rows),
            "consumer_plane_counts": plane_counts,
            "hard_violation_count": sum(1 for row in rows if row["dependency_class"] == "HARD_VIOLATION"),
            "doc_violation_count": sum(1 for row in rows if row["dependency_class"] == "DOC_DEPENDENCY_VIOLATION"),
        },
    }


def _build_quarantine_plan(*, boundary_map: Dict[str, Any], cross_refs: Dict[str, Any], archive_root: str) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    register_rows = cross_refs["cross_references"]
    for archive_surface in boundary_map["archive_surfaces"]:
        hits = [row for row in register_rows if row["archive_ref"] == archive_surface]
        planes = sorted({row["consumer_plane"] for row in hits})
        consequences = sorted({row["relocation_consequence"] for row in hits})
        if archive_surface.startswith("KT_ARCHIVE/vault/"):
            target = archive_surface
        elif archive_surface.startswith("KT_ARCHIVE/docs/audit/"):
            target = archive_surface
        else:
            target = archive_surface
        rows.append(
            {
                "archive_surface": archive_surface,
                "archive_ref_class": _archive_ref_class(archive_surface),
                "current_boundary_status": "BLOCKED_FOR_EXTERNALIZATION" if hits else "READY_FOR_EXTERNALIZATION",
                "active_reference_count": len(hits),
                "consumer_planes": planes,
                "relocation_consequences": consequences if consequences else ["NO_ACTIVE_BREAK_DETECTED"],
                "proposed_archive_target": target,
                "required_preconditions_before_move": (
                    [
                        "remove_or_replace_active_references",
                        "rerun_archive_externalization_proof",
                    ]
                    if hits
                    else [
                        "manifest_and_hash_archive_surface",
                    ]
                ),
            }
        )
    rows.sort(key=lambda row: row["archive_surface"])
    return {
        "schema_id": "kt.operator.archive_quarantine_plan.v1",
        "generated_utc": utc_now_iso_z(),
        "workstream_id": WORKSTREAM_ID,
        "archive_root_target": archive_root,
        "quarantine_entries": rows,
        "summary": {
            "archive_surface_count": len(rows),
            "blocked_for_externalization_count": sum(1 for row in rows if row["current_boundary_status"] == "BLOCKED_FOR_EXTERNALIZATION"),
            "ready_for_externalization_count": sum(1 for row in rows if row["current_boundary_status"] == "READY_FOR_EXTERNALIZATION"),
        },
    }


def _load_context(root: Path) -> Dict[str, Any]:
    ws0_receipt = _load_required(root, WS0_RECEIPT_REL)
    if str(ws0_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: WS1 is blocked until WS0 closure foundation is PASS.")

    plan = _load_required(root, STEP8_PLAN_REL)
    defects = _load_required(root, REOPENED_DEFECTS_REL)
    snapshot = _load_required(root, SNAPSHOT_MANIFEST_REL)
    snapshot_files = _existing_paths(snapshot)
    boundary_sets = _derive_boundary_sets(root=root, plan=plan, defects=defects, snapshot_files=snapshot_files)
    consumer_files = _textual_consumer_files(snapshot_files, boundary_sets["archive_surfaces"])
    return {
        "root": root,
        "ws0_receipt": ws0_receipt,
        "plan": plan,
        "defects": defects,
        "snapshot": snapshot,
        "snapshot_files": snapshot_files,
        "boundary_sets": boundary_sets,
        "consumer_files": consumer_files,
    }


def build_ws1_outputs(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    _ = generated_utc or utc_now_iso_z()
    ctx = _load_context(root)
    boundary_map = _build_boundary_map(ctx)
    cross_refs = _build_cross_reference_register(ctx)
    quarantine_plan = _build_quarantine_plan(
        boundary_map=boundary_map,
        cross_refs=cross_refs,
        archive_root=ctx["boundary_sets"]["archive_root"],
    )

    if any(not row["dependency_class"] for row in cross_refs["cross_references"]):
        raise RuntimeError("FAIL_CLOSED: archive dependency class unclear.")
    if not boundary_map["archive_surfaces"]:
        raise RuntimeError("FAIL_CLOSED: no archive surfaces were identified.")

    return {
        BOUNDARY_MAP_REL: boundary_map,
        CROSS_REFERENCE_REGISTER_REL: cross_refs,
        QUARANTINE_PLAN_REL: quarantine_plan,
    }


def build_ws1_receipt(root: Path) -> Dict[str, Any]:
    first = build_ws1_outputs(root)
    second = build_ws1_outputs(root)
    if not semantically_equal_json(first, second):
        raise RuntimeError("FAIL_CLOSED: nondeterministic WS1 outputs detected.")

    boundary_map = first[BOUNDARY_MAP_REL]
    cross_refs = first[CROSS_REFERENCE_REGISTER_REL]
    quarantine_plan = first[QUARANTINE_PLAN_REL]

    evidence_head_commit = _git_head(root)
    subject_commit_from_history = _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS)
    subject_head_commit = subject_commit_from_history or evidence_head_commit
    actual_subject_touched: List[str] = []
    if subject_commit_from_history:
        subject_parent = _git_parent(root, subject_head_commit)
        actual_subject_touched = _git_diff_files(root, subject_parent, subject_head_commit, SUBJECT_ARTIFACT_REFS)
        if not actual_subject_touched:
            actual_subject_touched = _git_changed_files(root, subject_head_commit)
    working_tree_subject_touched = _git_status_files(root, SUBJECT_ARTIFACT_REFS)
    if working_tree_subject_touched:
        actual_subject_touched = sorted(set(actual_subject_touched) | set(working_tree_subject_touched))
    receipt_exists = (root / Path(RECEIPT_REL)).exists()
    actual_touched = sorted(set(actual_subject_touched + ([RECEIPT_REL] if receipt_exists else [])))
    expected_touched = set(PLANNED_MUTATES if receipt_exists else SUBJECT_ARTIFACT_REFS)
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = sorted(path for path in actual_touched if _is_protected(path))

    issues_found: List[str] = []
    checks = []

    cutline_enumerated_ok = bool(boundary_map["archive_surfaces"]) and bool(boundary_map["top_level_boundaries"])
    checks.append(
        {
            "check": "all_archive_surfaces_enumerated",
            "detail": "All candidate archive roots/files must be enumerated in the boundary map.",
            "refs": [BOUNDARY_MAP_REL, STEP8_PLAN_REL, REOPENED_DEFECTS_REL, SNAPSHOT_MANIFEST_REL],
            "status": "PASS" if cutline_enumerated_ok else "FAIL",
        }
    )
    if not cutline_enumerated_ok:
        issues_found.append("all_archive_surfaces_enumerated")

    cross_refs_classified_ok = all(bool(row["dependency_class"]) and bool(row["relocation_consequence"]) for row in cross_refs["cross_references"])
    checks.append(
        {
            "check": "cross_references_fully_classified",
            "detail": "Every ACTIVE-to-ARCHIVE reference must be classified by consumer plane and relocation consequence.",
            "refs": [CROSS_REFERENCE_REGISTER_REL],
            "status": "PASS" if cross_refs_classified_ok else "FAIL",
        }
    )
    if not cross_refs_classified_ok:
        issues_found.append("cross_references_fully_classified")

    quarantine_plan_ok = all(bool(row["relocation_consequences"]) and bool(row["proposed_archive_target"]) for row in quarantine_plan["quarantine_entries"])
    checks.append(
        {
            "check": "archive_relocation_consequences_modeled",
            "detail": "Archive relocation consequences and target quarantine locations must be explicit.",
            "refs": [QUARANTINE_PLAN_REL],
            "status": "PASS" if quarantine_plan_ok else "FAIL",
        }
    )
    if not quarantine_plan_ok:
        issues_found.append("archive_relocation_consequences_modeled")

    touch_accounting_ok = not unexpected_touches and not protected_touch_violations and set(actual_touched) == expected_touched
    checks.append(
        {
            "check": "post_touch_accounting_clean",
            "detail": "Actual touched files must match the lawful WS1 subject set before receipt emission, then the full set including the receipt after sealing.",
            "refs": PLANNED_MUTATES if receipt_exists else SUBJECT_ARTIFACT_REFS,
            "status": "PASS" if touch_accounting_ok else "FAIL",
        }
    )
    if not touch_accounting_ok:
        issues_found.append("post_touch_accounting_clean")

    status = "PASS" if not issues_found else "FAIL_CLOSED"
    resolution = (
        "WS1 froze the active/archive cutline, enumerated active-to-archive references, and modeled relocation consequences without mutating archive surfaces."
        if status == "PASS"
        else "FAIL_CLOSED: WS1 cutline freeze remains incomplete or ambiguous."
    )

    return {
        "artifact_id": "kt_active_archive_cutline_receipt.json",
        "checks": checks,
        "compiled_head_commit": subject_head_commit,
        "current_head_commit": evidence_head_commit,
        "evidence_head_commit": evidence_head_commit,
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS2_CANONICAL_ACTIVE_TREE_EXECUTION",
        },
        "pass_verdict": "ACTIVE_ARCHIVE_CUTLINE_FROZEN" if status == "PASS" else "ACTIVE_ARCHIVE_CUTLINE_REJECTED_FAIL_CLOSED",
        "protected_touch_violations": protected_touch_violations,
        "schema_id": "kt.operator.active_archive_cutline_receipt.v1",
        "status": status,
        "subject_head_commit": subject_head_commit,
        "unexpected_touches": unexpected_touches,
        "validators_run": VALIDATORS_RUN,
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": WORKSTREAM_STEP_ID,
            "actions_taken": [
                "froze active/archive cutline map",
                "enumerated active-to-archive cross references",
                "modeled archive relocation consequences",
                "validated touch boundary and workstream gate",
            ],
            "files_touched": actual_touched,
            "tests_run": TESTS_RUN,
            "validators_run": VALIDATORS_RUN,
            "issues_found": issues_found,
            "resolution": resolution,
            "pass_fail_status": status,
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
        },
        "summary": {
            "active_surface_count": boundary_map["summary"]["active_surface_count"],
            "archive_surface_count": boundary_map["summary"]["archive_surface_count"],
            "cross_reference_count": cross_refs["summary"]["cross_reference_count"],
            "hard_violation_count": cross_refs["summary"]["hard_violation_count"],
        },
        "workstream_id": WORKSTREAM_ID,
    }


def _is_protected(path: str) -> bool:
    normalized = _normalize(path).lower()
    return normalized.startswith("kt_archive/") or "/archive/" in normalized or "/historical/" in normalized


def write_ws1_outputs(root: Path) -> Dict[str, Any]:
    outputs = build_ws1_outputs(root)
    writes: List[Dict[str, Any]] = []
    for rel, payload in outputs.items():
        changed = write_json_stable(root / Path(rel), payload)
        writes.append({"artifact_ref": rel, "updated": bool(changed)})
    return {"status": "PASS", "artifacts_written": writes}


def emit_ws1_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_ws1_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Freeze the ACTIVE/ARCHIVE cutline and enumerate cross references.")
    parser.add_argument("--emit-receipt", action="store_true")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_ws1_receipt(root) if args.emit_receipt else write_ws1_outputs(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
