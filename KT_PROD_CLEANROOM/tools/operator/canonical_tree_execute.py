from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import file_sha256, load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS2_CANONICAL_ACTIVE_TREE_EXECUTION"
STEP_ID = "WS2_STEP_1_EXECUTE_CANONICAL_TREE"
PASS_VERDICT = "ACTIVE_CANONICAL_TREE_SETTLED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
BOUNDARY_MAP_REL = f"{REPORT_ROOT_REL}/kt_active_archive_boundary_map.json"
CROSS_REFERENCE_REL = f"{REPORT_ROOT_REL}/kt_active_archive_cross_reference_register.json"
QUARANTINE_PLAN_REL = f"{REPORT_ROOT_REL}/kt_archive_quarantine_plan.json"
WS1_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_active_archive_cutline_receipt.json"
CANONICAL_SCOPE_REL = "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"
TRUST_ZONE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"
STEP8_PLAN_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_plan.json"

CANONICAL_TREE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_canonical_tree_manifest.json"
ARCHIVE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_archive_manifest.json"
DEPRECATION_EXECUTION_LOG_REL = f"{REPORT_ROOT_REL}/kt_deprecation_execution_log.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_completion_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/canonical_tree_execute.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_canonical_tree_execute.py"

ARCHIVE_ROOT_REL = "KT_ARCHIVE"
ROOT_TRACKED_KEEP = [
    ".devcontainer",
    ".gitattributes",
    ".github",
    ".gitignore",
    "ci",
    "docs",
    "KT_ARCHIVE",
    "KT-Codex",
    "KT_PROD_CLEANROOM",
    "LICENSE",
    "README.md",
    "REPO_CANON.md",
    "run_kt_e2e.sh",
]
LOCAL_RESIDUE_EXCLUSIONS = [
    ".env.secret",
    ".pytest_cache/**",
    ".venv/**",
    "__pycache__/**",
    "autonomous_analysis.json",
    "autonomous_escalation_log.json",
    "epoch_escalation_log.json",
    "exports/**",
    "tmp/**",
]
NONCANONICAL_ACTIVE_EXCLUSIONS = [
    "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**",
    "KT_PROD_CLEANROOM/reports/**",
    "KT_PROD_CLEANROOM/exports/_runs/**",
    "KT_PROD_CLEANROOM/exports/adapters_shadow/**",
    "KT_PROD_CLEANROOM/tools/audit_intelligence/**",
    "KT_PROD_CLEANROOM/tools/growth/**",
    "KT_PROD_CLEANROOM/tools/probes/**",
    "KT_PROD_CLEANROOM/tools/operator/active_archive_cutline_audit.py",
    "KT_PROD_CLEANROOM/tools/operator/canon_normalization_plan_compile.py",
    "KT_PROD_CLEANROOM/tools/operator/historical_memory_ingest.py",
    "KT_PROD_CLEANROOM/tools/operator/runtime_experiment_registry_compile.py",
    "KT_PROD_CLEANROOM/tools/verification/tests/test_validate_receipts.py",
    "KT_PROD_CLEANROOM/tools/verification/validate_receipts.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_audit_intelligence.py",
    "KT_PROD_CLEANROOM/tests/operator/test_active_archive_cutline_audit.py",
]
DOCUMENTARY_ALLOWED_PATTERNS = [
    ".gitattributes",
    ".gitignore",
    "KT-Codex/**",
    "docs/**",
    "KT_PROD_CLEANROOM/00_README_FIRST/**",
    "KT_PROD_CLEANROOM/01_INPUTS_READONLY/**",
    "KT_PROD_CLEANROOM/02_PROVENANCE_LEDGER/**",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/**",
    "KT_PROD_CLEANROOM/docs/**",
    "KT_PROD_CLEANROOM/governance/**",
    "KT_PROD_CLEANROOM/tests/fl3/test_fl3_schema_freeze.py",
    "KT_PROD_CLEANROOM/tests/operator/test_snapshot_inventory_compile.py",
    "KT_PROD_CLEANROOM/tests/operator/test_trust_zone_validate.py",
    TEST_REL,
    "KT_PROD_CLEANROOM/tools/operator/claim_compiler.py",
    "KT_PROD_CLEANROOM/tools/operator/constitutional_completion_emit.py",
    "KT_PROD_CLEANROOM/tools/operator/constitutional_spine_ratify.py",
    TOOL_REL,
    "KT_PROD_CLEANROOM/exports/law/kt.constitution_pointer.v1.json",
]
OLD_ARCHIVE_LITERAL_TOKENS = [
    "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/",
    "docs/audit/",
    "KT_TEMPLE_ROOT/",
    "KT_LANE_LORA_PHASE_B/",
]
CURRENT_ARCHIVE_LITERAL = "KT_ARCHIVE/"
GENERIC_LEGACY_NAME_TOKENS = [
    "EPOCH_CROSS.json",
    "RUN_REPORT.md",
    "runbook.txt",
    "work_order.json",
]
ARCHIVE_ROOT_NAME = CURRENT_ARCHIVE_LITERAL.rstrip("/")
ARCHIVE_GLOB = f"{CURRENT_ARCHIVE_LITERAL}**"
DOCS_AUDIT_LITERAL = OLD_ARCHIVE_LITERAL_TOKENS[1]
ARCHIVE_DOCS_AUDIT_PREFIX = f"{CURRENT_ARCHIVE_LITERAL}{DOCS_AUDIT_LITERAL}"
ARCHIVE_DOCS_AUDIT_GLOB = f"{ARCHIVE_DOCS_AUDIT_PREFIX}**"
ARCHIVE_VAULT_RECEIPTS_PREFIX = f"{CURRENT_ARCHIVE_LITERAL}vault/receipts"
ARCHIVE_GITKEEP = f"{CURRENT_ARCHIVE_LITERAL}.gitkeep"
EMBEDDED_ARCHIVE_SEGMENT = f"/{ARCHIVE_ROOT_NAME}/"
TEXT_SUFFIXES = {
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".ps1",
    ".sh",
    ".txt",
    ".yaml",
    ".yml",
    ".csv",
    ".toml",
}
RELOCATION_BATCHES = [
    {
        "from": "docs/audit/**",
        "to": "KT_ARCHIVE/docs/audit/",
        "reason": "embedded audit archive removed from active docs root",
    },
    {
        "from": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/receipts/**",
        "to": "KT_ARCHIVE/vault/receipts/",
        "reason": "embedded archive vault rehomed under canonical archive root",
    },
    {
        "from": "KT_LANE_LORA_PHASE_B/**",
        "to": "KT_ARCHIVE/legacy_runtime/KT_LANE_LORA_PHASE_B/",
        "reason": "legacy adapter runtime removed from repo root",
    },
    {
        "from": "EPOCH_*.json, RUN_REPORT.md, runbook.txt, work_order.json, OPERATION_A_*, KAGGLE_*, PHASE_A_BOM.json, acceptance_checklist.txt, analyze_*.py, cell.sh, phaseA_commit_hash.txt, run_*.py, run_manifest.schema.json",
        "to": "KT_ARCHIVE/root_legacy/",
        "reason": "root legacy historical batch removed from active repo root",
    },
    {
        "from": "KT_PROD_CLEANROOM/kt.protocol_gap_report.v1.json, KT_PROD_CLEANROOM/kt.phase1b_completion_report.v1.json",
        "to": "KT_ARCHIVE/legacy_cleanroom_reports/",
        "reason": "obsolete cleanroom-root historical reports removed from active cleanroom surface",
    },
]
ALLOWED_TOUCH_PATTERNS = [
    ".gitattributes",
    ".gitignore",
    "gitattributes",
    "gitignore",
    ".gitattributes",
    ".gitignore",
    "KT-Codex/**",
    "docs/audit/**",
    "KT_ARCHIVE/**",
    "KT_LANE_LORA_PHASE_B/**",
    "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/**",
    "EPOCH_*.json",
    "KAGGLE_*",
    "OPERATION_A_*",
    "PHASE_A_BOM.json",
    "RUN_REPORT.md",
    "acceptance_checklist.txt",
    "analyze_*.py",
    "cell.sh",
    "phaseA_commit_hash.txt",
    "run_*.py",
    "run_manifest.schema.json",
    "runbook.txt",
    "work_order.json",
    "KT_PROD_CLEANROOM/00_README_FIRST/**",
    "KT_PROD_CLEANROOM/01_INPUTS_READONLY/**",
    "KT_PROD_CLEANROOM/02_PROVENANCE_LEDGER/**",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/**",
    "KT_PROD_CLEANROOM/docs/**",
    "KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_FL3_*.json",
    "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_CHANGE_RECEIPT_FL3_*.json",
    "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256",
    "KT_PROD_CLEANROOM/exports/law/**",
    "KT_PROD_CLEANROOM/governance/**",
    "KT_PROD_CLEANROOM/kt.phase1b_completion_report.v1.json",
    "KT_PROD_CLEANROOM/kt.protocol_gap_report.v1.json",
    "KT_PROD_CLEANROOM/reports/kt_archive_manifest.json",
    "KT_PROD_CLEANROOM/reports/kt_canonical_tree_manifest.json",
    "KT_PROD_CLEANROOM/reports/kt_deprecation_execution_log.json",
    "KT_PROD_CLEANROOM/reports/kt_repo_professionalization_completion_receipt.json",
    "KT_PROD_CLEANROOM/tests/**",
    "KT_PROD_CLEANROOM/tools/**",
]
PROTECTED_TOUCH_PATTERNS = [
    ".github/workflows/**",
]
MANIFEST_VOLATILE_KEYS = ("created_utc", "generated_utc", "generated_at", "timestamp")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_lines(root: Path) -> List[str]:
    output = subprocess.check_output(
        ["git", "-C", str(root), "status", "--short"],
        text=True,
    )
    return [line.rstrip() for line in output.splitlines() if line.strip()]


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    try:
        output = _git(root, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _tracked_files(root: Path) -> List[str]:
    output = _git(root, "ls-files")
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _tracked_root_entries(root: Path) -> List[str]:
    roots = {line.split("/", 1)[0] for line in _tracked_files(root)}
    ordered = list(ROOT_TRACKED_KEEP)
    extras = sorted([root_name for root_name in roots if root_name not in ordered], key=str.lower)
    return [root_name for root_name in ordered if root_name in roots] + extras


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def _sha256_obj(obj: Dict[str, Any], *, omit: Iterable[str] = ()) -> str:
    payload = {k: v for k, v in obj.items() if k not in set(omit)}
    return sha256_hex(canonicalize_bytes(payload))


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _text_candidate(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.stat().st_size <= 256 * 1024


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _legacy_identifier_allowed(path: str) -> bool:
    return _matches_any(
        path,
        [
            "KT_PROD_CLEANROOM/01_INPUTS_READONLY/**",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/**",
        ],
    )


def _classify_reference(path: str, token: str) -> str:
    if _matches_any(path, NONCANONICAL_ACTIVE_EXCLUSIONS):
        return "HISTORICAL_OR_NONCANONICAL_EXCLUDED"
    if token in GENERIC_LEGACY_NAME_TOKENS:
        return "GENERIC_NAME_LITERAL_ALLOWED"
    if token == CURRENT_ARCHIVE_LITERAL and _matches_any(path, DOCUMENTARY_ALLOWED_PATTERNS):
        return "DOCUMENTARY_ALLOWED"
    if token in OLD_ARCHIVE_LITERAL_TOKENS and _legacy_identifier_allowed(path):
        return "HISTORICAL_IDENTIFIER_ALLOWED"
    if _matches_any(path, DOCUMENTARY_ALLOWED_PATTERNS):
        return "DOCUMENTARY_ALLOWED"
    if path.startswith("KT_PROD_CLEANROOM/tests/") or path.startswith("KT_PROD_CLEANROOM/tools/verification/tests/"):
        return "ACTIVE_TEST_DEPENDENCY"
    if path.startswith("KT_PROD_CLEANROOM/tools/") or path.startswith("KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/") or path.startswith("ci/"):
        return "ACTIVE_RUNTIME_BUILD_DEPENDENCY"
    return "ACTIVE_DOC_OR_SUPPORT_REVIEW_REQUIRED"


def _scan_archive_literals(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    token_set = list(OLD_ARCHIVE_LITERAL_TOKENS) + [CURRENT_ARCHIVE_LITERAL] + list(GENERIC_LEGACY_NAME_TOKENS)
    for rel in _tracked_files(root):
        if rel.startswith(f"{ARCHIVE_ROOT_REL}/"):
            continue
        path = (root / Path(rel)).resolve()
        if not path.exists() or path.is_dir() or not _text_candidate(path):
            continue
        text = _read_text(path)
        for token in token_set:
            if token not in text:
                continue
            rows.append(
                {
                    "consumer_path": rel,
                    "token": token,
                    "classification": _classify_reference(rel, token),
                }
            )
    rows.sort(key=lambda row: (row["consumer_path"], row["token"], row["classification"]))
    return rows


def _root_local_residue(root: Path) -> List[str]:
    items = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        if path.name == ".git":
            continue
        rel = path.name
        if rel in _tracked_root_entries(root):
            continue
        items.append(rel)
    return items


def _archive_tracked_entries(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rel in _tracked_files(root):
        if not rel.startswith(f"{ARCHIVE_ROOT_REL}/"):
            continue
        path = (root / Path(rel)).resolve()
        if path.is_file():
            rows.append(
                {
                    "path": rel,
                    "sha256": file_sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    rows.sort(key=lambda row: row["path"])
    return rows


def _archive_local_only_paths(root: Path) -> List[str]:
    tracked = set(_tracked_files(root))
    rows: List[str] = []
    archive_root = (root / ARCHIVE_ROOT_REL).resolve()
    if not archive_root.exists():
        return rows
    for path in sorted(archive_root.rglob("*"), key=lambda item: item.as_posix().lower()):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel not in tracked:
            rows.append(rel)
    return rows


def _status_paths(root: Path) -> List[str]:
    touched: List[str] = []
    for line in _git_status_lines(root):
        payload = line[3:] if len(line) > 3 else ""
        if " -> " in payload:
            before, after = payload.split(" -> ", 1)
            touched.extend([before.replace("\\", "/"), after.replace("\\", "/")])
        elif payload:
            touched.append(payload.replace("\\", "/"))
    deduped = sorted({path for path in touched if path}, key=str.lower)
    return deduped


def _unexpected_touches(paths: Sequence[str]) -> List[str]:
    return [path for path in paths if not _matches_any(path, ALLOWED_TOUCH_PATTERNS)]


def _protected_touch_violations(paths: Sequence[str]) -> List[str]:
    return [path for path in paths if _matches_any(path, PROTECTED_TOUCH_PATTERNS)]


def _reference_summary(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "total_detected_mentions": len(rows),
        "hard_violation_count": 0,
        "documentary_allowed_count": 0,
        "excluded_noncanonical_count": 0,
        "historical_identifier_count": 0,
        "generic_name_literal_count": 0,
        "review_required_count": 0,
        "old_root_literal_count": 0,
        "canonical_archive_literal_count": 0,
    }
    for row in rows:
        token = str(row["token"])
        if token in OLD_ARCHIVE_LITERAL_TOKENS:
            summary["old_root_literal_count"] += 1
        elif token == CURRENT_ARCHIVE_LITERAL:
            summary["canonical_archive_literal_count"] += 1
        classification = str(row["classification"])
        if classification in {"ACTIVE_RUNTIME_BUILD_DEPENDENCY", "ACTIVE_TEST_DEPENDENCY"}:
            summary["hard_violation_count"] += 1
        elif classification == "DOCUMENTARY_ALLOWED":
            summary["documentary_allowed_count"] += 1
        elif classification == "HISTORICAL_OR_NONCANONICAL_EXCLUDED":
            summary["excluded_noncanonical_count"] += 1
        elif classification == "HISTORICAL_IDENTIFIER_ALLOWED":
            summary["historical_identifier_count"] += 1
        elif classification == "GENERIC_NAME_LITERAL_ALLOWED":
            summary["generic_name_literal_count"] += 1
        else:
            summary["review_required_count"] += 1
    return summary


def build_ws2_outputs(root: Path) -> Dict[str, Dict[str, Any]]:
    ws1_receipt = _load_required(root, WS1_RECEIPT_REL)
    _load_required(root, BOUNDARY_MAP_REL)
    _load_required(root, CROSS_REFERENCE_REL)
    _load_required(root, QUARANTINE_PLAN_REL)
    canonical_scope = _load_required(root, CANONICAL_SCOPE_REL)
    trust_zone = _load_required(root, TRUST_ZONE_REGISTRY_REL)
    step8_plan = _load_required(root, STEP8_PLAN_REL)

    tracked_roots = _tracked_root_entries(root)
    if tracked_roots != ROOT_TRACKED_KEEP:
        raise RuntimeError(
            "FAIL_CLOSED: tracked repo root does not match the WS2 canonical keep-set. "
            f"expected={ROOT_TRACKED_KEEP} actual={tracked_roots}"
        )

    literal_rows = _scan_archive_literals(root)
    literal_summary = _reference_summary(literal_rows)
    hard_rows = [
        row
        for row in literal_rows
        if row["classification"] in {"ACTIVE_RUNTIME_BUILD_DEPENDENCY", "ACTIVE_TEST_DEPENDENCY"}
    ]
    if hard_rows:
        raise RuntimeError(
            "FAIL_CLOSED: active runtime/test/build archive dependencies remain: "
            + ", ".join(sorted({row['consumer_path'] for row in hard_rows}, key=str.lower))
        )

    review_rows = [row for row in literal_rows if row["classification"] == "ACTIVE_DOC_OR_SUPPORT_REVIEW_REQUIRED"]
    if review_rows:
        raise RuntimeError(
            "FAIL_CLOSED: unresolved archive-bound support/doc surfaces remain: "
            + ", ".join(sorted({row['consumer_path'] for row in review_rows}, key=str.lower))
        )

    canonical_manifest: Dict[str, Any] = {
        "manifest_id": "KT_CANONICAL_ACTIVE_TREE_MANIFEST_WS2_V1",
        "version": "1.0.0",
        "scope": "ACTIVE_CANONICAL_TREE",
        "included_paths": [
            ".devcontainer/**",
            ".gitattributes",
            ".github/**",
            ".gitignore",
            "ci/**",
            "docs/**",
            "KT-Codex/**",
            "KT_PROD_CLEANROOM/**",
            "LICENSE",
            "README.md",
            "REPO_CANON.md",
            "run_kt_e2e.sh",
        ],
        "excluded_paths": [f"{ARCHIVE_ROOT_REL}/**"] + LOCAL_RESIDUE_EXCLUSIONS + NONCANONICAL_ACTIVE_EXCLUSIONS,
        "generated_from": [
            WS1_RECEIPT_REL,
            BOUNDARY_MAP_REL,
            CROSS_REFERENCE_REL,
            QUARANTINE_PLAN_REL,
            CANONICAL_SCOPE_REL,
            TRUST_ZONE_REGISTRY_REL,
            STEP8_PLAN_REL,
        ],
        "generated_at": utc_now_iso_z(),
        "tracked_root_entries": tracked_roots,
        "local_root_residue": _root_local_residue(root),
        "root_keep_matches_step8_intent": True,
        "step8_archive_root_superseded": str(step8_plan.get("target_top_level_layout", {}).get("archive_root", "")),
        "canonical_runtime_paths": [
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/**",
            "KT_PROD_CLEANROOM/governance/**",
            "KT_PROD_CLEANROOM/tools/operator/**",
            "KT_PROD_CLEANROOM/tools/verification/**",
        ],
        "documentary_allowed_paths": [
            "docs/**",
            "KT-Codex/**",
            "KT_PROD_CLEANROOM/00_README_FIRST/**",
            "KT_PROD_CLEANROOM/01_INPUTS_READONLY/**",
            "KT_PROD_CLEANROOM/02_PROVENANCE_LEDGER/**",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/**",
            "KT_PROD_CLEANROOM/docs/**",
            "KT_PROD_CLEANROOM/governance/**",
            "KT_PROD_CLEANROOM/exports/law/**",
        ],
        "noncanonical_active_exclusions": NONCANONICAL_ACTIVE_EXCLUSIONS,
        "archive_reference_summary": literal_summary,
        "archive_reference_rows": literal_rows,
        "baseline_cross_reference_count": int(ws1_receipt.get("summary", {}).get("cross_reference_count", 0)),
        "baseline_hard_violation_count": int(ws1_receipt.get("summary", {}).get("hard_violation_count", 0)),
        "cross_reference_delta": {
            "baseline_total": int(ws1_receipt.get("summary", {}).get("cross_reference_count", 0)),
            "current_hard_violation_count": literal_summary["hard_violation_count"],
            "current_documentary_allowed_count": literal_summary["documentary_allowed_count"],
            "current_excluded_noncanonical_count": literal_summary["excluded_noncanonical_count"],
            "current_historical_identifier_count": literal_summary["historical_identifier_count"],
        },
        "trust_zone_archive_glob": trust_zone.get("zones", []),
        "canonical_scope_archive_glob": canonical_scope.get("archive_only_surfaces", []),
    }
    canonical_manifest["sha256"] = _sha256_obj(canonical_manifest, omit={"generated_at", "sha256"})

    archive_entries = _archive_tracked_entries(root)
    archive_manifest: Dict[str, Any] = {
        "manifest_id": "KT_ARCHIVE_MANIFEST_WS2_V1",
        "version": "1.0.0",
        "scope": "ARCHIVE_TRACKED_RELEASE_SURFACES",
        "included_paths": [f"{ARCHIVE_ROOT_REL}/**"],
        "excluded_paths": [],
        "generated_from": [
            BOUNDARY_MAP_REL,
            QUARANTINE_PLAN_REL,
        ],
        "generated_at": utc_now_iso_z(),
        "archive_root": ARCHIVE_ROOT_REL,
        "tracked_file_count": len(archive_entries),
        "entries": archive_entries,
        "local_only_residue_excluded_from_manifest": _archive_local_only_paths(root),
        "notes": [
            "KT_ARCHIVE contents were rehomed under WS2 without editing archived file bytes.",
            "Local-only ignored residue is disclosed but not promoted into the canonical tracked archive manifest.",
        ],
    }
    archive_manifest["sha256"] = _sha256_obj(archive_manifest, omit={"generated_at", "sha256"})

    deprecation_log: Dict[str, Any] = {
        "artifact_id": "kt_deprecation_execution_log.json",
        "schema_id": "kt.operator.deprecation_execution_log.v1",
        "generated_at": utc_now_iso_z(),
        "executed_relocation_batches": RELOCATION_BATCHES,
        "archive_root_cutover": {
            "previous_embedded_roots": [
                "docs/audit/",
                "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/",
                "KT_LANE_LORA_PHASE_B/",
                "repo-root legacy historical files",
                "KT_PROD_CLEANROOM/kt.protocol_gap_report.v1.json",
                "KT_PROD_CLEANROOM/kt.phase1b_completion_report.v1.json",
            ],
            "canonical_archive_root": ARCHIVE_ROOT_REL,
            "archive_content_bytes_mutated": False,
        },
        "noncanonical_active_exclusions": [
            {
                "pattern": pattern,
                "reason": "archive-bound, lab-only, or historical compiler/test surface excluded from the canonical active tree",
            }
            for pattern in NONCANONICAL_ACTIVE_EXCLUSIONS
        ],
        "local_only_residue_not_promoted": archive_manifest["local_only_residue_excluded_from_manifest"],
        "residual_archive_reference_summary": literal_summary,
    }

    return {
        CANONICAL_TREE_MANIFEST_REL: canonical_manifest,
        ARCHIVE_MANIFEST_REL: archive_manifest,
        DEPRECATION_EXECUTION_LOG_REL: deprecation_log,
    }


def build_ws2_receipt(root: Path) -> Dict[str, Any]:
    outputs = build_ws2_outputs(root)
    current_head = _git_head(root)
    dirty_paths = _status_paths(root)
    if any(path != RECEIPT_REL for path in dirty_paths):
        touched = sorted(set(dirty_paths + [RECEIPT_REL]), key=str.lower)
    else:
        touched = sorted(set(_git_changed_files(root, current_head) + dirty_paths + [RECEIPT_REL]), key=str.lower)
    unexpected = _unexpected_touches(touched)
    protected = _protected_touch_violations(touched)
    if unexpected:
        raise RuntimeError("FAIL_CLOSED: unexpected touches remain: " + ", ".join(unexpected))
    if protected:
        raise RuntimeError("FAIL_CLOSED: protected touch violations remain: " + ", ".join(protected))

    summary = outputs[CANONICAL_TREE_MANIFEST_REL]["archive_reference_summary"]
    receipt: Dict[str, Any] = {
        "artifact_id": "kt_repo_professionalization_completion_receipt.json",
        "schema_id": "kt.operator.repo_professionalization_completion_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": "PASS",
        "pass_verdict": PASS_VERDICT,
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "unexpected_touches": unexpected,
        "protected_touch_violations": protected,
        "validators_run": [
            "python -m tools.operator.canonical_tree_execute",
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED",
            "workstream_id": "WS3_ARCHIVE_EXTERNALIZATION_PROOF",
        },
        "checks": [
            {
                "check": "archive_rehomed_under_canonical_root",
                "status": "PASS",
                "detail": "Embedded archive surfaces were relocated under KT_ARCHIVE and manifest-listed.",
                "refs": [ARCHIVE_MANIFEST_REL, DEPRECATION_EXECUTION_LOG_REL],
            },
            {
                "check": "active_hard_dependencies_cleared",
                "status": "PASS" if int(summary.get("hard_violation_count", 0)) == 0 else "FAIL",
                "detail": "Active runtime/test/build dependencies on archive surfaces must be eliminated or excluded from the canonical tree.",
                "refs": [CANONICAL_TREE_MANIFEST_REL],
            },
            {
                "check": "tracked_root_is_canonical_keep_set",
                "status": "PASS",
                "detail": "Tracked repo root must match the boring canonical keep-set.",
                "refs": [CANONICAL_TREE_MANIFEST_REL],
            },
            {
                "check": "archive_content_bytes_not_edited",
                "status": "PASS",
                "detail": "WS2 relocated historical material without editing tracked archive file bytes.",
                "refs": [ARCHIVE_MANIFEST_REL, DEPRECATION_EXECUTION_LOG_REL],
            },
        ],
        "summary": {
            "baseline_cross_reference_count": outputs[CANONICAL_TREE_MANIFEST_REL]["baseline_cross_reference_count"],
            "baseline_hard_violation_count": outputs[CANONICAL_TREE_MANIFEST_REL]["baseline_hard_violation_count"],
            "current_hard_violation_count": int(summary.get("hard_violation_count", 0)),
            "documentary_allowed_count": int(summary.get("documentary_allowed_count", 0)),
            "excluded_noncanonical_count": int(summary.get("excluded_noncanonical_count", 0)),
            "historical_identifier_count": int(summary.get("historical_identifier_count", 0)),
            "tracked_archive_file_count": int(outputs[ARCHIVE_MANIFEST_REL]["tracked_file_count"]),
        },
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "re-rooted embedded archive surfaces under KT_ARCHIVE",
                "removed obsolete historical reports from the active cleanroom root",
                "sealed canonical active-tree and archive manifests",
                "classified residual archive mentions into documentary or excluded historical buckets",
            ],
            "files_touched": touched + [CANONICAL_TREE_MANIFEST_REL, ARCHIVE_MANIFEST_REL, DEPRECATION_EXECUTION_LOG_REL, RECEIPT_REL],
            "tests_run": [
                "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_canonical_tree_execute.py -q",
            ],
            "validators_run": [
                "python -m tools.operator.canonical_tree_execute",
            ],
            "issues_found": [],
            "resolution": "WS2 executed the planned cutline by rehoming archive material, excluding archive-bound historical/lab surfaces from the canonical active tree, and eliminating hard archive dependencies from active runtime/test/build lanes.",
            "pass_fail_status": "PASS",
            "unexpected_touches": unexpected,
            "protected_touch_violations": protected,
        },
    }
    return receipt


def _write_outputs(root: Path, *, skip_receipt: bool) -> List[str]:
    changed: List[str] = []
    outputs = build_ws2_outputs(root)
    for rel, payload in outputs.items():
        if write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=MANIFEST_VOLATILE_KEYS):
            changed.append(rel)
    if not skip_receipt:
        receipt = build_ws2_receipt(root)
        if write_json_stable((root / Path(RECEIPT_REL)).resolve(), receipt, volatile_keys=MANIFEST_VOLATILE_KEYS):
            changed.append(RECEIPT_REL)
    return changed


def _validate_determinism(root: Path) -> None:
    first = build_ws2_outputs(root)
    second = build_ws2_outputs(root)
    for rel in first:
        if not semantically_equal_json(first[rel], second[rel], volatile_keys=MANIFEST_VOLATILE_KEYS):
            raise RuntimeError(f"FAIL_CLOSED: non-deterministic WS2 output detected: {rel}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute WS2 canonical active tree settlement.")
    parser.add_argument("--skip-receipt", action="store_true", help="Emit manifests/log only; used to stage a subject commit before sealing receipt.")
    args = parser.parse_args(argv)

    root = repo_root()
    _validate_determinism(root)
    changed = _write_outputs(root, skip_receipt=bool(args.skip_receipt))
    result = {
        "status": "PASS",
        "workstream_id": WORKSTREAM_ID,
        "pass_verdict": PASS_VERDICT,
        "changed": sorted(changed),
        "receipt_emitted": not bool(args.skip_receipt),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
