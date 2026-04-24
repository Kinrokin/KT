from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_02_dual_audit_scope_packet_tranche as scope_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_02_SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION_REPORT.md"
OUTPUT_BASELINE_VIEW = "cohort0_post_f_track_02_frozen_baseline_evidence_view.json"
OUTPUT_CURRENT_VIEW = "cohort0_post_f_track_02_current_truth_evidence_view.json"

EXECUTION_STATUS = "PASS__POST_F_TRACK_02_SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION_COMPLETE"
EXECUTION_OUTCOME = "POST_F_TRACK_02_SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION_COMPLETE__DUAL_VIEWS_MATERIALIZED"
TRACK_ID = scope_tranche.TRACK_ID
NEXT_MOVE = "EXECUTE_POST_F_TRACK_02_FROZEN_BASELINE_AND_CURRENT_TRUTH_AUDITS"

_ENV_PATTERN = re.compile(r"\$\{([^}:]+):-([^}]+)\}")


def _require_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _current_branch_name(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception:
        return "UNKNOWN_BRANCH"
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _resolve_template(raw: str, *, root: Path) -> Path:
    def replace(match: re.Match[str]) -> str:
        env_name = match.group(1)
        fallback = match.group(2)
        return os.environ.get(env_name, fallback)

    resolved = _ENV_PATTERN.sub(replace, raw)
    path = Path(resolved)
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _iter_matches(base: Path, patterns: Iterable[str]) -> List[Path]:
    seen: Dict[str, Path] = {}
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        for pattern in patterns:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern):
                seen[rel] = path
                break
    return [seen[key] for key in sorted(seen)]


def _matches_any(rel_path: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(Path(rel_path).name, pattern):
            return True
    return False


def _json_normalized_bytes(path: Path) -> bytes:
    payload = json.loads(path.read_text(encoding="utf-8"))
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return normalized.encode("utf-8")


def _hash_artifact(path: Path) -> Tuple[str, int, str]:
    if path.suffix.lower() == ".json":
        try:
            content = _json_normalized_bytes(path)
            return hashlib.sha256(content).hexdigest(), len(content), "JSON_SORTED_KEY_COMPACT_COMPAT"
        except Exception:
            pass
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw), "RAW_BYTES"


def _classify_current_truth_paths(root: Path) -> Dict[str, List[str]]:
    classes = {
        "live_header_packets": [
            f"{common.REPORTS_ROOT_REL}/cohort0_successor_gate_d_post_clear_branch_law_packet.json",
            f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json",
        ],
        "supersession_notes": [
            f"{common.REPORTS_ROOT_REL}/cohort0_successor_gate_d_post_clear_supersession_note.json",
            f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_supersession_note.json",
        ],
        "orchestrator_receipt_and_predicate_board": [
            f"{common.REPORTS_ROOT_REL}/cohort0_successor_master_orchestrator_receipt.json",
            f"{common.REPORTS_ROOT_REL}/cohort0_successor_master_predicate_board.json",
        ],
        "gate_d_gate_e_gate_f_receipts": [
            f"{common.REPORTS_ROOT_REL}/cohort0_successor_full_gate_d_readjudication_receipt.json",
            f"{common.REPORTS_ROOT_REL}/cohort0_gate_e_admissibility_screen_receipt.json",
            f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_one_narrow_wedge_review_receipt.json",
        ],
        "post_f_live_product_truth": [
            f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json",
            f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_receipt.json",
        ],
        "post_f_broad_canonical_reaudit_receipt": [
            f"{common.REPORTS_ROOT_REL}/cohort0_post_f_broad_canonical_reaudit_receipt.json",
        ],
        "track_01_final_summary_packet": [
            f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_01_final_summary_packet.json",
            f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_01_final_summary_receipt.json",
        ],
    }
    out: Dict[str, List[str]] = {}
    for class_id, paths in classes.items():
        out[class_id] = [p for p in paths if common.resolve_path(root, p).is_file()]
    return out


def _source_summary(
    *,
    source_id: str,
    source_type: str,
    location: str,
    required: bool,
    capture_mode: str,
    include_globs: List[str],
    harvested_count: int,
    optional_missing: bool,
    metadata_only_count: int,
    excluded_secret_count: int,
) -> Dict[str, Any]:
    return {
        "source_id": source_id,
        "source_type": source_type,
        "location": location,
        "required": required,
        "capture_mode": capture_mode,
        "include_globs": include_globs,
        "harvested_count": harvested_count,
        "optional_missing": optional_missing,
        "metadata_only_count": metadata_only_count,
        "excluded_secret_count": excluded_secret_count,
    }


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    subject_head: str,
    scope_packet: Dict[str, Any],
    work_order: Dict[str, Any],
    work_order_path: Path,
    git_state: Dict[str, Any],
    evidence_manifest: Dict[str, Any],
    content_hash_manifest: Dict[str, Any],
    authority_partition: Dict[str, Any],
    baseline_view: Dict[str, Any],
    current_view: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(scope_packet.get("authority_header", {}))
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "claim_boundary": (
            "This packet records only the shared evidence harvest, authority partition, and dual evidence-view materialization for Track 02. "
            "It does not execute either audit verdict and does not collapse baseline and current-truth authority."
        ),
        "track_id": TRACK_ID,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "authority_header": {
            "canonical_authority_branch": "main",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
            "gate_d_cleared_on_successor_line": bool(authority_header.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(authority_header.get("gate_e_open_on_successor_line", False)),
            "gate_f_narrow_wedge_confirmed": bool(authority_header.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_open": bool(authority_header.get("gate_f_open", False)),
            "track_01_closed_as_bounded_proof_packet": bool(authority_header.get("track_01_closed_as_bounded_proof_packet", False)),
        },
        "git_state": git_state,
        "artifact_refs": {
            "evidence_manifest_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_evidence_manifest.json",
            "content_hash_manifest_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_content_hash_manifest.json",
            "authority_partition_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_authority_partition.json",
            "frozen_baseline_view_ref": f"{common.REPORTS_ROOT_REL}/{OUTPUT_BASELINE_VIEW}",
            "current_truth_view_ref": f"{common.REPORTS_ROOT_REL}/{OUTPUT_CURRENT_VIEW}",
        },
        "harvest_summary": {
            "source_count": len(evidence_manifest.get("source_summaries", [])),
            "content_hash_count": len(content_hash_manifest.get("artifacts", [])),
            "metadata_only_secret_sentinel_present": authority_partition.get("secret_presence_note", {}).get("exists", False),
            "dual_views_materialized": True,
        },
        "subject_head": subject_head,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "content_hash_count": len(content_hash_manifest.get("artifacts", [])),
        "source_count": len(evidence_manifest.get("source_summaries", [])),
        "baseline_view_materialized": True,
        "current_truth_view_materialized": True,
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 02 Shared Evidence Harvest And Authority Partition Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Execution outcome: `{EXECUTION_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Sources harvested: `{len(evidence_manifest.get('source_summaries', []))}`",
            f"- Content hashes emitted: `{len(content_hash_manifest.get('artifacts', []))}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {
        "packet": packet,
        "receipt": receipt,
        "report": report,
    }


def run(
    *,
    reports_root: Path,
    scope_packet_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    scope_packet = common.load_json_required(root, scope_packet_path, label="Track 02 dual audit scope packet")
    _require_pass(scope_packet, label="Track 02 dual audit scope packet")
    if str(scope_packet.get("scope_outcome", "")).strip() != scope_tranche.SCOPE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest requires the bound dual-audit scope packet")
    if str(scope_packet.get("next_lawful_move", "")).strip() != "EXECUTE_POST_F_TRACK_02_SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION":
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest requires the scope packet to point here next")

    branch_name = _current_branch_name(root)
    if branch_name != "expansion/post-f-track-01":
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest must run on expansion/post-f-track-01")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest requires a clean worktree")

    work_order_path = Path(str(scope_packet.get("work_order_binding", {}).get("work_order_path", "")).strip())
    if not work_order_path.is_file():
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest requires the bound work order file to remain present")
    work_order = json.loads(work_order_path.read_text(encoding="utf-8"))
    if not isinstance(work_order, dict):
        raise RuntimeError("FAIL_CLOSED: Track 02 work order must be a JSON object")

    repo_cfg = dict(work_order.get("repo", {}))
    if bool(repo_cfg.get("require_clean_worktree", False)) and _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest work order requires a clean worktree")

    prompt_binding = dict(scope_packet.get("prompt_artifact_binding", {}))
    baseline_prompt_path = Path(str(prompt_binding.get("baseline_frozen", {}).get("source_path", "")).strip())
    current_prompt_path = Path(str(prompt_binding.get("current_truth_hardened", {}).get("source_path", "")).strip())
    for path, expected, label in [
        (
            baseline_prompt_path,
            str(prompt_binding.get("baseline_frozen", {}).get("expected_sha256", "")).strip().lower(),
            "baseline prompt",
        ),
        (
            current_prompt_path,
            str(prompt_binding.get("current_truth_hardened", {}).get("expected_sha256", "")).strip().lower(),
            "current-truth prompt",
        ),
    ]:
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest().lower()
        if actual != expected:
            raise RuntimeError(f"FAIL_CLOSED: {label} hash drift detected")

    subject_head = str(scope_packet.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest requires a subject head")

    anchors = dict(scope_packet.get("anchor_binding", {}))
    frozen_baseline_ref = str(anchors.get("frozen_baseline", {}).get("ref_name", "")).strip()
    current_truth_ref = str(anchors.get("current_truth", {}).get("ref_name", "")).strip()
    if not frozen_baseline_ref or not current_truth_ref:
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest requires both anchors to be bound")

    git_state = {
        "current_branch": branch_name,
        "current_head_commit": _git_rev_parse(root, "HEAD"),
        "current_truth_anchor_ref": current_truth_ref,
        "current_truth_anchor_commit": _git_rev_parse(root, current_truth_ref),
        "frozen_baseline_anchor_ref": frozen_baseline_ref,
        "frozen_baseline_anchor_commit": _git_rev_parse(root, frozen_baseline_ref),
        "canonical_authority_branch": str(scope_packet.get("authority_header", {}).get("canonical_authority_branch", "")).strip(),
        "worktree_clean": True,
    }

    shared_harvest_cfg = dict(work_order.get("shared_evidence_harvest", {}))
    sources = shared_harvest_cfg.get("sources", [])
    if not isinstance(sources, list) or not sources:
        raise RuntimeError("FAIL_CLOSED: Track 02 harvest requires shared evidence sources")
    secret_policy = dict(shared_harvest_cfg.get("secret_policy", {}))
    never_read_globs = list(secret_policy.get("never_read_globs", []))
    metadata_only_globs = list(secret_policy.get("metadata_only_globs", []))

    evidence_entries: List[Dict[str, Any]] = []
    hash_entries: List[Dict[str, Any]] = []
    source_summaries: List[Dict[str, Any]] = []
    secret_presence_note: Dict[str, Any] = {
        "path": "",
        "exists": False,
    }

    for source in sources:
        if not isinstance(source, dict):
            continue
        source_id = str(source.get("source_id", "")).strip()
        source_type = str(source.get("source_type", "")).strip()
        location_raw = str(source.get("location", "")).strip()
        capture_mode = str(source.get("capture_mode", "")).strip()
        required = bool(source.get("required", False))
        include_globs = list(source.get("include_globs", [])) if isinstance(source.get("include_globs", []), list) else []
        location = _resolve_template(location_raw, root=root)

        harvested_count = 0
        metadata_only_count = 0
        excluded_secret_count = 0
        optional_missing = False

        if source_id == "git_state":
            evidence_entries.append(
                {
                    "artifact_ref": "git_state",
                    "source_id": source_id,
                    "capture_mode": capture_mode,
                    "kind": "metadata_only",
                    "metadata": git_state,
                }
            )
            harvested_count = 1
        elif source_id == "secret_presence_note":
            exists = location.is_file()
            secret_presence_note = {
                "path": location.as_posix(),
                "exists": exists,
                "metadata_only": True,
            }
            evidence_entries.append(
                {
                    "artifact_ref": location.as_posix(),
                    "source_id": source_id,
                    "capture_mode": "metadata_only",
                    "kind": "secret_presence_note",
                    "metadata": secret_presence_note,
                }
            )
            harvested_count = 1
            metadata_only_count = 1
        else:
            if not location.exists():
                if required:
                    raise RuntimeError(f"FAIL_CLOSED: missing required shared-evidence source {source_id}: {location.as_posix()}")
                optional_missing = True
            else:
                if location.is_file():
                    candidates = [location]
                    base = location.parent
                else:
                    base = location
                    candidates = _iter_matches(location, include_globs or ["**/*"])

                for path in candidates:
                    rel = path.relative_to(base).as_posix() if path.is_relative_to(base) else path.name
                    if _matches_any(rel, never_read_globs):
                        excluded_secret_count += 1
                        evidence_entries.append(
                            {
                                "artifact_ref": path.as_posix(),
                                "source_id": source_id,
                                "capture_mode": "excluded_secret",
                                "kind": "excluded",
                            }
                        )
                        continue
                    if _matches_any(rel, metadata_only_globs):
                        metadata_only_count += 1
                        harvested_count += 1
                        evidence_entries.append(
                            {
                                "artifact_ref": path.as_posix(),
                                "source_id": source_id,
                                "capture_mode": "metadata_only",
                                "kind": "metadata_only",
                                "metadata": {
                                    "size_bytes": path.stat().st_size,
                                },
                            }
                        )
                        continue

                    digest, size_bytes, hash_mode = _hash_artifact(path)
                    harvested_count += 1
                    hash_ref = f"{source_id}:{path.as_posix()}"
                    evidence_entries.append(
                        {
                            "artifact_ref": path.as_posix(),
                            "source_id": source_id,
                            "capture_mode": capture_mode,
                            "kind": "content_hashed",
                            "hash_ref": hash_ref,
                        }
                    )
                    hash_entries.append(
                        {
                            "hash_ref": hash_ref,
                            "artifact_ref": path.as_posix(),
                            "source_id": source_id,
                            "sha256": digest,
                            "size_bytes": size_bytes,
                            "hash_mode": hash_mode,
                        }
                    )

        source_summaries.append(
            _source_summary(
                source_id=source_id,
                source_type=source_type,
                location=location.as_posix(),
                required=required,
                capture_mode=capture_mode,
                include_globs=include_globs,
                harvested_count=harvested_count,
                optional_missing=optional_missing,
                metadata_only_count=metadata_only_count,
                excluded_secret_count=excluded_secret_count,
            )
        )

    evidence_manifest = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_evidence_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "harvest_mode": str(shared_harvest_cfg.get("mode", "")).strip(),
        "one_harvest_two_views": bool(shared_harvest_cfg.get("one_harvest_two_views", False)),
        "source_summaries": source_summaries,
        "evidence_entries": evidence_entries,
        "external_contract_assets": {
            "work_order_path": work_order_path.as_posix(),
            "work_order_sha256": hashlib.sha256(work_order_path.read_bytes()).hexdigest().lower(),
            "baseline_prompt_path": baseline_prompt_path.as_posix(),
            "current_truth_prompt_path": current_prompt_path.as_posix(),
        },
    }
    content_hash_manifest = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_content_hash_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "artifacts": sorted(hash_entries, key=lambda row: row["hash_ref"]),
    }

    current_truth_paths = _classify_current_truth_paths(root)
    current_truth_authoritative_paths = sorted(
        {
            path
            for rows in current_truth_paths.values()
            for path in rows
        }
    )
    supporting_boundary_paths = [
        rel
        for rel in [".gitignore", "docs/REPO_BOUNDARY.md"]
        if common.resolve_path(root, rel).is_file()
    ]
    current_generation_logic = [
        ref
        for ref in evidence_entries
        if ref.get("source_id") in {"operator_tranches", "operator_tests"}
        and ref.get("kind") == "content_hashed"
    ]
    optional_supporting_sources = {
        summary["source_id"]: {
            "optional_missing": summary["optional_missing"],
            "harvested_count": summary["harvested_count"],
        }
        for summary in source_summaries
        if summary["source_id"] in {"google_drive_exports", "chat_log_exports"}
    }
    authority_partition = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_authority_partition.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "anchor_resolution": git_state,
        "authoritative_current_truth_classes": current_truth_paths,
        "authoritative_current_truth_paths": current_truth_authoritative_paths,
        "supporting_current_boundary_paths": supporting_boundary_paths,
        "supporting_current_generation_logic_count": len(current_generation_logic),
        "optional_supporting_sources": optional_supporting_sources,
        "secret_presence_note": secret_presence_note,
        "view_rules": dict(scope_packet.get("execution_plan", {}).get("authority_partition", {}).get("view_rules", {})),
        "precedence_order": list(scope_packet.get("execution_plan", {}).get("authority_partition", {}).get("precedence_order", [])),
        "stale_if": list(scope_packet.get("execution_plan", {}).get("authority_partition", {}).get("stale_if", [])),
    }
    baseline_view = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_frozen_baseline_evidence_view.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "view_id": "frozen_baseline_view",
        "anchor_ref": frozen_baseline_ref,
        "anchor_commit": git_state["frozen_baseline_anchor_commit"],
        "baseline_prompt_ref": baseline_prompt_path.as_posix(),
        "baseline_prompt_sha256": hashlib.sha256(baseline_prompt_path.read_bytes()).hexdigest().lower(),
        "shared_evidence_manifest_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_evidence_manifest.json",
        "content_hash_manifest_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_content_hash_manifest.json",
        "authority_partition_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_authority_partition.json",
        "reject_post_anchor_authority": True,
        "historical_receipts_can_inform_lineage_not_override_baseline_anchor": True,
    }
    current_view = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_current_truth_evidence_view.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "view_id": "current_truth_live_view",
        "anchor_ref": current_truth_ref,
        "anchor_commit": git_state["current_truth_anchor_commit"],
        "current_truth_prompt_ref": current_prompt_path.as_posix(),
        "current_truth_prompt_sha256": hashlib.sha256(current_prompt_path.read_bytes()).hexdigest().lower(),
        "shared_evidence_manifest_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_evidence_manifest.json",
        "content_hash_manifest_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_content_hash_manifest.json",
        "authority_partition_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_authority_partition.json",
        "authorized_current_truth_classes": current_truth_paths,
        "live_header_precedence_enforced": True,
    }

    write_json_stable((reports_root / "cohort0_post_f_track_02_dual_audit_evidence_manifest.json").resolve(), evidence_manifest)
    write_json_stable((reports_root / "cohort0_post_f_track_02_dual_audit_content_hash_manifest.json").resolve(), content_hash_manifest)
    write_json_stable((reports_root / "cohort0_post_f_track_02_dual_audit_authority_partition.json").resolve(), authority_partition)
    write_json_stable((reports_root / OUTPUT_BASELINE_VIEW).resolve(), baseline_view)
    write_json_stable((reports_root / OUTPUT_CURRENT_VIEW).resolve(), current_view)

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        subject_head=subject_head,
        scope_packet=scope_packet,
        work_order=work_order,
        work_order_path=work_order_path,
        git_state=git_state,
        evidence_manifest=evidence_manifest,
        content_hash_manifest=content_hash_manifest,
        authority_partition=authority_partition,
        baseline_view=baseline_view,
        current_view=current_view,
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "execution_outcome": EXECUTION_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the Track 02 shared evidence harvest and authority partition.")
    parser.add_argument(
        "--scope-packet",
        default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        scope_packet_path=common.resolve_path(root, args.scope_packet),
    )
    print(result["execution_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
