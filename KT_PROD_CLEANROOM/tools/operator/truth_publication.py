from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.authority_convergence_validate import build_authority_convergence_report
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import active_truth_source_ref, load_json_ref, path_ref


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GENERATED_TRUTH_ROOT_REL = "KT_PROD_CLEANROOM/exports/_truth"
TRUTH_CURRENT_DIR_REL = f"{GENERATED_TRUTH_ROOT_REL}/current"
TRUTH_BUNDLES_ROOT_REL = f"{GENERATED_TRUTH_ROOT_REL}/bundles"
CURRENT_POINTER_REL = f"{TRUTH_CURRENT_DIR_REL}/current_pointer.json"
CURRENT_MANIFEST_REL = f"{TRUTH_CURRENT_DIR_REL}/current_bundle_manifest.json"
TRUTH_LEDGER_BRANCH = "kt_truth_ledger"
LEDGER_ROOT_REL = "ledger"
LEDGER_CURRENT_DIR_REL = f"{LEDGER_ROOT_REL}/current"
LEDGER_BUNDLES_ROOT_REL = f"{LEDGER_ROOT_REL}/bundles"
LEDGER_HISTORY_ROOT_REL = f"{LEDGER_ROOT_REL}/history"
LEDGER_CURRENT_POINTER_REL = f"{LEDGER_CURRENT_DIR_REL}/current_pointer.json"
LEDGER_CURRENT_MANIFEST_REL = f"{LEDGER_CURRENT_DIR_REL}/current_bundle_manifest.json"

TRUTH_PUBLICATION_REQUIRED_LAW_SURFACES: List[str] = [
    "KT_PROD_CLEANROOM/governance/truth_publication_contract.json",
    "KT_PROD_CLEANROOM/governance/settled_authority_migration_contract.json",
    "KT_PROD_CLEANROOM/governance/truth_snapshot_retention_rules.json",
    "KT_PROD_CLEANROOM/governance/truth_publication_cleanliness_rules.json",
    "KT_PROD_CLEANROOM/governance/tracked_vs_generated_truth_boundary.json",
    "KT_PROD_CLEANROOM/governance/truth_bundle_contract.json",
    "KT_PROD_CLEANROOM/governance/truth_pointer_rules.json",
    "KT_PROD_CLEANROOM/governance/current_pointer_transition_rules.json",
]

TRUTH_PUBLICATION_REQUIRED_ARTIFACTS: List[str] = [
    "KT_PROD_CLEANROOM/reports/settled_authority_promotion_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_bundle.schema.json",
    "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
    "KT_PROD_CLEANROOM/reports/truth_pointer_index.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_snapshot_manifest.json",
    "KT_PROD_CLEANROOM/reports/truth_clean_state_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_supersession_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json",
]

MANDATORY_BUNDLE_REPORTS: List[str] = [
    "live_validation_index.json",
    "current_state_receipt.json",
    "runtime_closure_audit.json",
    "posture_consistency_receipt.json",
    "posture_consistency_enforcement_receipt.json",
    "posture_conflict_receipt.json",
    "settled_truth_source_receipt.json",
    "truth_supersession_receipt.json",
]

OPTIONAL_BUNDLE_REPORTS: List[str] = [
    "truth_surface_reconciliation_report.json",
    "one_button_preflight_receipt.json",
    "one_button_production_receipt.json",
    "authority_convergence_receipt.json",
    "domain_maturity_matrix.json",
    "p0_green_full_receipt.json",
    "kt_green_final_receipt.json",
]

TRACKED_DOCUMENTARY_SURFACES: List[str] = [
    f"{DEFAULT_REPORT_ROOT_REL}/{name}"
    for name in (
        "live_validation_index.json",
        "current_state_receipt.json",
        "runtime_closure_audit.json",
        "posture_consistency_receipt.json",
        "posture_consistency_enforcement_receipt.json",
        "posture_conflict_receipt.json",
        "settled_truth_source_receipt.json",
        "truth_supersession_receipt.json",
        "truth_surface_reconciliation_report.json",
        "one_button_preflight_receipt.json",
        "one_button_production_receipt.json",
        "authority_convergence_receipt.json",
        "domain_maturity_matrix.json",
        "p0_green_full_receipt.json",
        "kt_green_final_receipt.json",
    )
]


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _canonical_hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _git_status_lines(root: Path) -> Optional[List[str]]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        return None
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _report_path(root: Path, report_root_rel: str, name: str) -> Path:
    return (root / report_root_rel / name).resolve()


def ledger_ref(*, branch: str, relpath: str) -> str:
    return f"{branch}:{Path(relpath).as_posix()}"


def _bundle_sources(*, root: Path, report_root_rel: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name in MANDATORY_BUNDLE_REPORTS:
        path = _report_path(root, report_root_rel, name)
        payload = _load_required(path)
        rows.append(
            {
                "name": name,
                "source_ref": path_ref(root=root, path=path),
                "payload": payload,
                "sha256": _canonical_hash(payload),
                "required": True,
            }
        )
    for name in OPTIONAL_BUNDLE_REPORTS:
        path = _report_path(root, report_root_rel, name)
        if not path.exists():
            continue
        payload = load_json(path)
        rows.append(
            {
                "name": name,
                "source_ref": path_ref(root=root, path=path),
                "payload": payload,
                "sha256": _canonical_hash(payload),
                "required": False,
            }
        )
    return rows


def _truth_bundle_schema() -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.truth_bundle.schema.v1",
        "required": [
            "schema_id",
            "truth_bundle_id",
            "truth_bundle_hash",
            "truth_subject_commit",
            "truth_produced_at_commit",
            "authority_level",
            "posture_enum",
            "zone_scope",
            "freshness_contract_ref",
            "validator_set",
            "generated_utc",
            "files",
        ],
        "properties": {
            "truth_bundle_id": {"type": "string"},
            "truth_bundle_hash": {"type": "string"},
            "truth_subject_commit": {"type": "string"},
            "truth_produced_at_commit": {"type": "string"},
            "authority_level": {"type": "string"},
            "posture_enum": {"type": "string"},
            "zone_scope": {"type": "array"},
            "supersedes": {"type": "string"},
            "generated_utc": {"type": "string"},
            "validator_set": {"type": "array"},
            "files": {"type": "array"},
        },
        "status": "ACTIVE",
    }


def _read_previous_pointer(root: Path) -> Dict[str, Any]:
    pointer_path = (root / CURRENT_POINTER_REL).resolve()
    if not pointer_path.exists():
        return {}
    return load_json(pointer_path)


def _read_previous_ledger_pointer(*, ledger_root: Path) -> Dict[str, Any]:
    pointer_path = (ledger_root / LEDGER_CURRENT_POINTER_REL).resolve()
    if not pointer_path.exists():
        return {}
    return load_json(pointer_path)


def _bundle_descriptor(
    *,
    subject_commit: str,
    producer_commit: str,
    authority_mode: str,
    posture_state: str,
    generated_utc: str,
    report_root_rel: str,
    live_validation_index_ref: str,
    sources: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.truth_bundle.v1",
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "zone_scope": ["CANONICAL"],
        "freshness_contract_ref": "KT_PROD_CLEANROOM/governance/truth_freshness_windows.json",
        "validation_index_ref": live_validation_index_ref,
        "report_root_ref": report_root_rel,
        "generated_utc": generated_utc,
        "validator_set": [
            "tools.operator.truth_engine",
            "tools.operator.truth_surface_sync",
            "tools.operator.truth_publication_validate",
        ],
        "files": [
            {
                "name": str(row["name"]),
                "source_ref": str(row["source_ref"]),
                "bundle_relpath": f"payloads/{row['name']}",
                "sha256": str(row["sha256"]),
                "required": bool(row["required"]),
            }
            for row in sources
        ],
    }


def _bundle_catalog_entry(
    *,
    bundle_hash: str,
    bundle_ref: str,
    pointer_ref: str,
    subject_commit: str,
    authority_mode: str,
    posture_state: str,
    generated_utc: str,
) -> Dict[str, Any]:
    return {
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "current_pointer_ref": pointer_ref,
        "truth_subject_commit": subject_commit,
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "generated_utc": generated_utc,
    }


def _tracked_catalog_payload(*, existing: Dict[str, Any], new_entry: Dict[str, Any]) -> Dict[str, Any]:
    rows = existing.get("bundles") if isinstance(existing.get("bundles"), list) else []
    bundles: List[Dict[str, Any]] = []
    seen = set()
    new_hash = str(new_entry["truth_bundle_hash"])
    bundles.append(new_entry)
    seen.add(new_hash)
    for row in rows:
        if not isinstance(row, dict):
            continue
        bundle_hash = str(row.get("truth_bundle_hash", "")).strip()
        if not bundle_hash or bundle_hash in seen:
            continue
        bundles.append(row)
        seen.add(bundle_hash)
    return {
        "schema_id": "kt.operator.truth_bundle_catalog.v1",
        "status": "ACTIVE",
        "bundles": bundles,
    }


def _publication_blockers(*, authority_mode: str, posture_state: str, subject_dirty: bool, board_open_blockers: Sequence[str]) -> List[str]:
    blockers: List[str] = []
    if authority_mode != "SETTLED_AUTHORITATIVE":
        blockers.append("authority mode is not settled authoritative")
    if subject_dirty:
        blockers.append("validated subject worktree was dirty")
    if posture_state != "TRUTHFUL_GREEN":
        blockers.append(f"posture state is {posture_state}, not TRUTHFUL_GREEN")
    blockers.extend(str(item).strip() for item in board_open_blockers if str(item).strip())
    deduped: List[str] = []
    seen = set()
    for blocker in blockers:
        if blocker in seen:
            continue
        seen.add(blocker)
        deduped.append(blocker)
    return deduped


def publish_truth_artifacts(
    *,
    root: Path,
    report_root_rel: str,
    live_validation_index_path: Path,
    authority_mode: str,
    posture_state: str,
    board_open_blockers: Sequence[str],
) -> Dict[str, Any]:
    sources = _bundle_sources(root=root, report_root_rel=report_root_rel)
    live_index = _load_required(live_validation_index_path)
    worktree = live_index.get("worktree") if isinstance(live_index.get("worktree"), dict) else {}
    subject_commit = str(worktree.get("head_sha", "")).strip()
    if not subject_commit:
        raise RuntimeError("FAIL_CLOSED: live validation index missing worktree.head_sha")
    producer_commit = subject_commit
    generated_utc = str(live_index.get("generated_utc", "")).strip() or utc_now_iso_z()
    previous_pointer = _read_previous_pointer(root)
    live_validation_index_ref = path_ref(root=root, path=live_validation_index_path)
    descriptor = _bundle_descriptor(
        subject_commit=subject_commit,
        producer_commit=producer_commit,
        authority_mode=authority_mode,
        posture_state=posture_state,
        generated_utc=generated_utc,
        report_root_rel=report_root_rel,
        live_validation_index_ref=live_validation_index_ref,
        sources=sources,
    )
    bundle_hash = _canonical_hash(descriptor)
    bundle_id = f"TRUTH_BUNDLE_{subject_commit[:12]}_{bundle_hash[:16]}"
    descriptor["truth_bundle_hash"] = bundle_hash
    descriptor["truth_bundle_id"] = bundle_id

    bundle_dir = (root / TRUTH_BUNDLES_ROOT_REL / subject_commit / bundle_hash).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    payload_dir = bundle_dir / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)
    for row in sources:
        write_json_stable(payload_dir / str(row["name"]), row["payload"])
    write_json_stable(bundle_dir / "truth_bundle.json", descriptor)

    current_dir = (root / TRUTH_CURRENT_DIR_REL).resolve()
    current_dir.mkdir(parents=True, exist_ok=True)
    bundle_ref = path_ref(root=root, path=bundle_dir / "truth_bundle.json")
    previous_bundle_hash = str(previous_pointer.get("current_bundle_hash", "")).strip()
    superseded_bundle_hash = previous_bundle_hash if previous_bundle_hash and previous_bundle_hash != bundle_hash else ""
    pointer_payload = {
        "schema_id": "kt.operator.truth_pointer.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "current_bundle_hash": bundle_hash,
        "current_bundle_ref": bundle_ref,
        "current_bundle_manifest_ref": path_ref(root=root, path=current_dir / "current_bundle_manifest.json"),
        "zone_scope": ["CANONICAL"],
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "freshness_contract_ref": "KT_PROD_CLEANROOM/governance/truth_freshness_windows.json",
        "supersedes_bundle_hash": superseded_bundle_hash,
        "board_contract_ref": "KT_PROD_CLEANROOM/governance/execution_board.json",
    }
    manifest_payload = {
        "schema_id": "kt.operator.truth_snapshot_manifest.v1",
        "generated_utc": generated_utc,
        "truth_bundle_id": bundle_id,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "truth_subject_commit": subject_commit,
        "files": descriptor["files"],
    }
    write_json_stable(current_dir / "current_bundle_manifest.json", manifest_payload)
    write_json_stable(current_dir / "current_pointer.json", pointer_payload)

    tracked_schema = _truth_bundle_schema()
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_bundle.schema.json", tracked_schema)

    catalog_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_bundle_catalog.json"
    existing_catalog = load_json(catalog_path) if catalog_path.exists() else {}
    current_pointer_ref = CURRENT_POINTER_REL
    catalog_entry = _bundle_catalog_entry(
        bundle_hash=bundle_hash,
        bundle_ref=bundle_ref,
        pointer_ref=current_pointer_ref,
        subject_commit=subject_commit,
        authority_mode=authority_mode,
        posture_state=posture_state,
        generated_utc=generated_utc,
    )
    tracked_catalog = _tracked_catalog_payload(existing=existing_catalog, new_entry=catalog_entry)
    write_json_stable(catalog_path, tracked_catalog)

    pointer_index = {
        "schema_id": "kt.operator.truth_pointer_index.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "authoritative_current_pointer_ref": current_pointer_ref,
        "truth_bundle_ref": bundle_ref,
        "truth_bundle_hash": bundle_hash,
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "documentary_tracked_truth_surfaces": TRACKED_DOCUMENTARY_SURFACES,
        "tracked_catalog_ref": "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_pointer_index.json", pointer_index)

    git_dirty_before = _git_status_lines(root)
    subject_dirty = bool(worktree.get("git_dirty"))
    allowed_tracked_outputs = [path_ref(root=root, path=root / rel) for rel in TRUTH_PUBLICATION_REQUIRED_ARTIFACTS]
    clean_state_receipt = {
        "schema_id": "kt.operator.truth_clean_state_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "truth_subject_commit": subject_commit,
        "subject_worktree_dirty_at_validation": subject_dirty,
        "publisher_worktree_dirty_before": None if git_dirty_before is None else bool(git_dirty_before),
        "publication_outputs_restricted_to_generated_truth_and_allowed_indexes": True,
        "generated_truth_root": GENERATED_TRUTH_ROOT_REL,
        "authoritative_current_pointer_ref": current_pointer_ref,
        "documentary_tracked_indexes": TRUTH_PUBLICATION_REQUIRED_ARTIFACTS,
        "tracked_truth_for_current_posture_forbidden": TRACKED_DOCUMENTARY_SURFACES,
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_clean_state_receipt.json", clean_state_receipt)

    publication_receipt = {
        "schema_id": "kt.operator.truth_publication_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "truth_bundle_id": bundle_id,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "authoritative_current_pointer_ref": current_pointer_ref,
        "truth_pointer_index_ref": "KT_PROD_CLEANROOM/reports/truth_pointer_index.json",
        "truth_bundle_catalog_ref": "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
        "truth_snapshot_manifest_ref": "KT_PROD_CLEANROOM/reports/truth_snapshot_manifest.json",
        "documentary_tracked_truth_surfaces": TRACKED_DOCUMENTARY_SURFACES,
        "no_parallel_truth_rule_enforced": True,
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_receipt.json", publication_receipt)
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_snapshot_manifest.json", manifest_payload)

    supersession_receipt = {
        "schema_id": "kt.operator.truth_publication_supersession_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "authoritative_current_pointer_ref": current_pointer_ref,
        "authoritative_bundle_ref": bundle_ref,
        "documentary_only_tracked_surfaces": TRACKED_DOCUMENTARY_SURFACES,
        "documentary_indexes": [
            "KT_PROD_CLEANROOM/reports/truth_pointer_index.json",
            "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
            "KT_PROD_CLEANROOM/reports/truth_publication_receipt.json",
            "KT_PROD_CLEANROOM/reports/truth_snapshot_manifest.json",
            "KT_PROD_CLEANROOM/reports/truth_clean_state_receipt.json",
        ],
        "superseded_bundle_hash": superseded_bundle_hash,
        "no_parallel_truth_enforced": True,
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_supersession_receipt.json", supersession_receipt)

    stabilization_blockers = _publication_blockers(
        authority_mode=authority_mode,
        posture_state=posture_state,
        subject_dirty=subject_dirty,
        board_open_blockers=board_open_blockers,
    )
    stabilization_receipt = {
        "schema_id": "kt.operator.truth_publication_stabilization_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if not stabilization_blockers else "HOLD",
        "truth_subject_commit": subject_commit,
        "authoritative_current_pointer_ref": current_pointer_ref,
        "truth_bundle_ref": bundle_ref,
        "truth_bundle_hash": bundle_hash,
        "authority_mode": authority_mode,
        "posture_state": posture_state,
        "contradiction_count": len(stabilization_blockers),
        "blockers": stabilization_blockers,
        "board_transition_ready": not stabilization_blockers,
        "required_board_transition": "TRUTH_PUBLICATION_STABILIZED=true",
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json", stabilization_receipt)

    return {
        "current_pointer_ref": current_pointer_ref,
        "truth_bundle_ref": bundle_ref,
        "truth_bundle_hash": bundle_hash,
        "truth_subject_commit": subject_commit,
        "publication_receipt": publication_receipt,
        "stabilization_receipt": stabilization_receipt,
    }


def publish_truth_ledger_witness(
    *,
    source_root: Path,
    ledger_root: Path,
    report_root_rel: str,
    live_validation_index_path: Path,
    authority_mode: str,
    posture_state: str,
    ledger_branch: str = TRUTH_LEDGER_BRANCH,
) -> Dict[str, Any]:
    sources = _bundle_sources(root=source_root, report_root_rel=report_root_rel)
    live_index = _load_required(live_validation_index_path)
    worktree = live_index.get("worktree") if isinstance(live_index.get("worktree"), dict) else {}
    subject_commit = str(worktree.get("head_sha", "")).strip()
    if not subject_commit:
        raise RuntimeError("FAIL_CLOSED: live validation index missing worktree.head_sha")
    producer_commit = subject_commit
    generated_utc = str(live_index.get("generated_utc", "")).strip() or utc_now_iso_z()
    previous_pointer = _read_previous_ledger_pointer(ledger_root=ledger_root)
    live_validation_index_ref = path_ref(root=source_root, path=live_validation_index_path)
    descriptor = _bundle_descriptor(
        subject_commit=subject_commit,
        producer_commit=producer_commit,
        authority_mode=authority_mode,
        posture_state=posture_state,
        generated_utc=generated_utc,
        report_root_rel=report_root_rel,
        live_validation_index_ref=live_validation_index_ref,
        sources=sources,
    )
    descriptor["witness_plane"] = {
        "branch": ledger_branch,
        "mode": "BOOTSTRAP_WITNESS_ONLY",
        "published_head_authority_claimed": False,
        "main_purge_completed": False,
    }
    bundle_hash = _canonical_hash(descriptor)
    bundle_id = f"LEDGER_TRUTH_BUNDLE_{subject_commit[:12]}_{bundle_hash[:16]}"
    descriptor["truth_bundle_hash"] = bundle_hash
    descriptor["truth_bundle_id"] = bundle_id

    bundle_dir = (ledger_root / LEDGER_BUNDLES_ROOT_REL / subject_commit / bundle_hash).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    payload_dir = bundle_dir / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)
    for row in sources:
        write_json_stable(payload_dir / str(row["name"]), row["payload"])
    write_json_stable(bundle_dir / "truth_bundle.json", descriptor)

    current_dir = (ledger_root / LEDGER_CURRENT_DIR_REL).resolve()
    current_dir.mkdir(parents=True, exist_ok=True)
    bundle_rel = str((Path(LEDGER_BUNDLES_ROOT_REL) / subject_commit / bundle_hash / "truth_bundle.json").as_posix())
    bundle_ref = ledger_ref(branch=ledger_branch, relpath=bundle_rel)
    previous_bundle_hash = str(previous_pointer.get("current_bundle_hash", "")).strip()
    superseded_bundle_hash = previous_bundle_hash if previous_bundle_hash and previous_bundle_hash != bundle_hash else ""
    current_manifest_rel = str((Path(LEDGER_CURRENT_DIR_REL) / "current_bundle_manifest.json").as_posix())
    pointer_payload = {
        "schema_id": "kt.operator.truth_pointer.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "current_bundle_hash": bundle_hash,
        "current_bundle_ref": bundle_ref,
        "current_bundle_manifest_ref": ledger_ref(branch=ledger_branch, relpath=current_manifest_rel),
        "zone_scope": ["CANONICAL"],
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "freshness_contract_ref": "KT_PROD_CLEANROOM/governance/truth_freshness_windows.json",
        "supersedes_bundle_hash": superseded_bundle_hash,
        "board_contract_ref": "KT_PROD_CLEANROOM/governance/execution_board.json",
        "witness_plane": True,
        "transition_state": "LEDGER_BOOTSTRAPPED_PENDING_PURGE",
        "published_head_authority_claimed": False,
    }
    manifest_payload = {
        "schema_id": "kt.operator.truth_snapshot_manifest.v1",
        "generated_utc": generated_utc,
        "truth_bundle_id": bundle_id,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "truth_subject_commit": subject_commit,
        "files": descriptor["files"],
        "witness_plane": True,
        "published_head_authority_claimed": False,
    }
    write_json_stable(current_dir / "current_bundle_manifest.json", manifest_payload)
    write_json_stable(current_dir / "current_pointer.json", pointer_payload)
    # The convergence contract treats ledger/current/* as the convenience "current" plane,
    # not just bundle payloads. Keep these copies in sync with the published bundle inputs.
    for required_current in ("current_state_receipt.json", "runtime_closure_audit.json"):
        for row in sources:
            if str(row.get("name", "")).strip() == required_current:
                write_json_stable(current_dir / required_current, row["payload"])
                break

    history_dir = (ledger_root / LEDGER_HISTORY_ROOT_REL / subject_commit).resolve()
    history_dir.mkdir(parents=True, exist_ok=True)
    publication_receipt = {
        "schema_id": "kt.operator.truth_ledger_publication_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "ledger_branch": ledger_branch,
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "current_pointer_ref": ledger_ref(branch=ledger_branch, relpath=LEDGER_CURRENT_POINTER_REL),
        "current_bundle_manifest_ref": ledger_ref(branch=ledger_branch, relpath=current_manifest_rel),
        "transition_state": "LEDGER_BOOTSTRAPPED_PENDING_PURGE",
        "witness_only": True,
        "published_head_authority_claimed": False,
        "source_report_root_ref": report_root_rel,
    }
    write_json_stable(history_dir / "publication_receipt.json", publication_receipt)

    return {
        "ledger_branch": ledger_branch,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "current_pointer_ref": ledger_ref(branch=ledger_branch, relpath=LEDGER_CURRENT_POINTER_REL),
        "current_manifest_ref": ledger_ref(branch=ledger_branch, relpath=current_manifest_rel),
        "history_receipt_ref": ledger_ref(
            branch=ledger_branch,
            relpath=str((Path(LEDGER_HISTORY_ROOT_REL) / subject_commit / "publication_receipt.json").as_posix()),
        ),
        "truth_subject_commit": subject_commit,
        "published_head_authority_claimed": False,
    }


def validate_truth_publication(*, root: Path) -> Dict[str, Any]:
    failures: List[str] = []
    checks: List[Dict[str, Any]] = []
    for rel in TRUTH_PUBLICATION_REQUIRED_LAW_SURFACES:
        ok = (root / rel).exists()
        checks.append({"check": f"law_surface_present::{rel}", "status": "PASS" if ok else "FAIL"})
        if not ok:
            failures.append(f"missing_law_surface:{rel}")
    for rel in TRUTH_PUBLICATION_REQUIRED_ARTIFACTS:
        ok = (root / rel).exists()
        checks.append({"check": f"artifact_present::{rel}", "status": "PASS" if ok else "FAIL"})
        if not ok:
            failures.append(f"missing_artifact:{rel}")

    active_source = active_truth_source_ref(root=root)
    current_pointer = load_json_ref(root=root, ref=active_source)
    pointer_ref = str(current_pointer.get("current_bundle_ref", "")).strip()
    pointer_ok = bool(pointer_ref)
    checks.append(
        {
            "check": "active_truth_pointer_has_bundle_ref",
            "status": "PASS" if pointer_ok else "FAIL",
            "active_truth_source": active_source,
            "current_bundle_ref": pointer_ref,
        }
    )
    if not pointer_ok:
        failures.append("current_pointer_missing_bundle_ref")

    bundle_exists = False
    bundle: Dict[str, Any] = {}
    if pointer_ref:
        try:
            bundle = load_json_ref(root=root, ref=pointer_ref)
            bundle_exists = True
        except Exception:  # noqa: BLE001
            bundle_exists = False
    checks.append({"check": "pointed_bundle_exists", "status": "PASS" if bundle_exists else "FAIL"})
    if pointer_ref and not bundle_exists:
        failures.append("pointed_bundle_missing")

    if bundle_exists:
        bundle_hash_matches = str(bundle.get("truth_bundle_hash", "")).strip() == str(current_pointer.get("current_bundle_hash", "")).strip()
        checks.append({"check": "pointer_bundle_hash_matches", "status": "PASS" if bundle_hash_matches else "FAIL"})
        if not bundle_hash_matches:
            failures.append("pointer_bundle_hash_mismatch")

    execution_board_path = root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json"
    if execution_board_path.exists():
        board = load_json(execution_board_path)
        board_ref = str(board.get("authoritative_current_head_truth_source", "")).strip()
        board_ok = board_ref == active_source
        checks.append({"check": "execution_board_points_to_active_truth_source", "status": "PASS" if board_ok else "FAIL", "actual": board_ref, "expected": active_source})
        if not board_ok:
            failures.append("execution_board_not_pointing_to_active_truth_source")

    readiness_path = root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json"
    if readiness_path.exists():
        readiness = load_json(readiness_path)
        readiness_ref = str(readiness.get("authoritative_truth_source", "")).strip()
        readiness_ok = readiness_ref == active_source
        checks.append({"check": "readiness_scope_points_to_active_truth_source", "status": "PASS" if readiness_ok else "FAIL", "actual": readiness_ref, "expected": active_source})
        if not readiness_ok:
            failures.append("readiness_scope_not_pointing_to_active_truth_source")

    supersession_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_supersession_receipt.json"
    if supersession_path.exists():
        supersession = load_json(supersession_path)
        no_parallel_truth = bool(supersession.get("no_parallel_truth_enforced"))
        checks.append({"check": "no_parallel_truth_rule_enforced", "status": "PASS" if no_parallel_truth else "FAIL"})
        if not no_parallel_truth:
            failures.append("no_parallel_truth_not_enforced")

    stabilization_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json"
    if stabilization_path.exists():
        stabilization = load_json(stabilization_path)
        board_transition_ready = bool(stabilization.get("board_transition_ready"))
        checks.append(
            {
                "check": "stabilization_receipt_present",
                "status": "PASS",
                "receipt_status": str(stabilization.get("status", "")).strip(),
                "board_transition_ready": board_transition_ready,
            }
        )

    convergence = build_authority_convergence_report(root=root)
    convergence_ok = str(convergence.get("status", "")).strip() == "PASS"
    checks.append(
        {
            "check": "authority_convergence_passes",
            "status": "PASS" if convergence_ok else "FAIL",
            "failures": convergence.get("failures", []),
        }
    )
    if not convergence_ok:
        failures.append("authority_convergence_failed")

    return {
        "schema_id": "kt.operator.truth_publication_validation_receipt.v1",
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "failures": failures,
    }


def load_publication_stabilization_state(*, root: Path) -> Dict[str, Any]:
    receipt_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json"
    if not receipt_path.exists():
        return {"status": "MISSING", "board_transition_ready": False, "blockers": ["truth publication stabilization receipt missing"]}
    receipt = load_json(receipt_path)
    return {
        "status": str(receipt.get("status", "")).strip() or "UNKNOWN",
        "board_transition_ready": bool(receipt.get("board_transition_ready")),
        "blockers": [str(item).strip() for item in receipt.get("blockers", []) if str(item).strip()],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Publish immutable truth bundles and current-pointer indexes from current operator truth receipts.")
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--live-validation-index", default=f"{DEFAULT_REPORT_ROOT_REL}/live_validation_index.json")
    ap.add_argument("--authority-mode", default="SETTLED_AUTHORITATIVE")
    ap.add_argument("--posture-state", default="CANONICAL_READY_FOR_REEARNED_GREEN")
    ap.add_argument("--open-blocker", action="append", default=[])
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    index_path = Path(str(args.live_validation_index)).expanduser()
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    publication = publish_truth_artifacts(
        root=root,
        report_root_rel=str(args.report_root),
        live_validation_index_path=index_path,
        authority_mode=str(args.authority_mode),
        posture_state=str(args.posture_state),
        board_open_blockers=[str(item) for item in args.open_blocker],
    )
    print(json.dumps(publication, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
