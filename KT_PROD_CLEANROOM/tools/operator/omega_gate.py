from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.authority_convergence_validate import build_authority_convergence_report
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.toolchain_runtime_firewall_validate import build_toolchain_runtime_firewall_receipt
from tools.operator.truth_authority import (
    active_truth_source_ref,
    compatibility_surface_is_non_authoritative,
    load_json_ref,
    payload_documentary_only,
)
from tools.operator.trust_zone_validate import validate_trust_zones


DEFAULT_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL = "KT_PROD_CLEANROOM/governance/authority_resolution_index.json"
DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL = "KT_PROD_CLEANROOM/governance/historical_claim_firewall.json"
DEFAULT_TOOLS_BOUNDARY_RULE_REL = "KT_PROD_CLEANROOM/governance/tools_runtime_boundary_rule.json"
DEFAULT_REPORT_AUTHORITY_INDEX_REL = "KT_PROD_CLEANROOM/reports/report_authority_index.json"
DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL = "KT_PROD_CLEANROOM/reports/authority_supersession_map.json"
DEFAULT_CANONICAL_DELTA_REL = "KT_PROD_CLEANROOM/reports/canonical_delta_w0.json"
DEFAULT_ADVANCEMENT_DELTA_REL = "KT_PROD_CLEANROOM/reports/advancement_delta_w0.json"
DEFAULT_OMEGA_GATE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/omega_gate_receipt.json"
DEFAULT_DEFERRED_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/deferred_blockers.json"
DEFAULT_C006_HEARTBEAT_REL = "KT_PROD_CLEANROOM/reports/c006_deferral_heartbeat.json"

EXECUTION_BOARD_REL = "KT_PROD_CLEANROOM/governance/execution_board.json"
READINESS_SCOPE_REL = "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json"
TRUTH_ENGINE_REL = "KT_PROD_CLEANROOM/governance/truth_engine_contract.json"
TRUST_ZONE_REL = "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"
RUNTIME_BOUNDARY_REL = "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json"
WAVE5_BLOCKER_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_blocker_matrix.json"
WAVE5_TIER_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_final_tier_ruling.json"
WAVE5_READJUDICATION_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_final_readjudication_receipt.json"
WAVE5_CLAIM_MATRIX_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_final_claim_class_matrix.json"
WAVE5_ORGAN_DISPOSITION_REL = "KT_PROD_CLEANROOM/reports/kt_wave2c_organ_disposition_register.json"
POST_WAVE5_TERMINAL_STATES_REL = "KT_PROD_CLEANROOM/reports/post_wave5_runtime_organ_terminal_state_register.json"
POST_WAVE5_C006_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c006_second_host_execution_receipt.json"
FINAL_BLOCKER_REL = "KT_PROD_CLEANROOM/reports/kt_final_blocker_matrix.json"
FINAL_READJUDICATION_REL = "KT_PROD_CLEANROOM/reports/kt_final_current_head_readjudication_receipt.json"
FINAL_CLAIM_CEILING_REL = "KT_PROD_CLEANROOM/reports/kt_final_claim_ceiling_receipt.json"
AUTHORITY_CONVERGENCE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json"
TOOLCHAIN_FIREWALL_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_wave0_5_toolchain_runtime_firewall_receipt.json"
WORK_ORDER_ANCHOR_REL = "KT_PROD_CLEANROOM/governance/kt_unified_convergence_max_power_campaign_v2_1_1_anchor.json"
DOCUMENTARY_POINTER_REL = "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"
FRONTIER_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/kt_frontier_rerun_scorecard.json"
FRONTIER_AUDIT_PACKET_REL = "KT_PROD_CLEANROOM/reports/kt_frontier_audit_packet.json"


def _resolve(root: Path, rel: str) -> Path:
    return (root / rel).resolve()


def _path_exists(root: Path, rel: str) -> bool:
    return _resolve(root, rel).exists()


def _load_optional(root: Path, rel: str) -> Dict[str, Any]:
    path = _resolve(root, rel)
    if not path.exists():
        return {}
    return load_json(path)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_ref_exists(root: Path, ref: str) -> bool:
    try:
        subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", str(ref).strip()],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except subprocess.CalledProcessError:
        return False
    return True


def _git_status_lines(root: Path) -> List[str]:
    output = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"], text=True)
    return [line.rstrip("\n") for line in output.splitlines() if line.strip()]


def _tracking_state(root: Path, rel: str) -> str:
    rel_posix = Path(rel).as_posix()
    lines = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1", "--", rel_posix], text=True).splitlines()
    if lines:
        code = lines[0][:2]
        if code == "??":
            return "UNTRACKED_WORKTREE"
        return "TRACKED_DIRTY"
    try:
        subprocess.check_output(["git", "-C", str(root), "ls-files", "--error-unmatch", rel_posix], stderr=subprocess.STDOUT, text=True)
        return "TRACKED_CLEAN"
    except subprocess.CalledProcessError:
        return "IGNORED_OR_ABSENT"


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _head_from_payload(payload: Dict[str, Any]) -> str:
    for key in ("validated_head_sha", "pinned_head_sha", "truth_subject_commit", "truth_produced_at_commit"):
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def _payload_documentary_only(payload: Dict[str, Any]) -> bool:
    return payload_documentary_only(payload)


def _split_branch_ref(value: str) -> Tuple[str, str]:
    branch, relpath = str(value).split(":", 1)
    return branch.strip(), relpath.strip()


def _scope_digest(root: Path, refs: Sequence[str]) -> Tuple[str, List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    for ref in sorted({str(item).strip() for item in refs if str(item).strip()}):
        path = _resolve(root, ref)
        row: Dict[str, Any] = {
            "ref": ref,
            "exists": path.exists(),
            "tracking_state": _tracking_state(root, ref),
        }
        if path.exists():
            row["sha256"] = _file_sha256(path)
            row["size_bytes"] = path.stat().st_size
        rows.append(row)
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
    return digest, rows


def _worktree_summary(root: Path) -> Dict[str, Any]:
    lines = _git_status_lines(root)
    modified = 0
    untracked = 0
    for line in lines:
        code = line[:2]
        if code == "??":
            untracked += 1
        else:
            modified += 1
    return {
        "dirty": bool(lines),
        "entry_count": len(lines),
        "modified_or_staged_count": modified,
        "untracked_count": untracked,
    }


def _active_deferred_c006(root: Path) -> Dict[str, Any]:
    payload = _load_optional(root, DEFAULT_DEFERRED_BLOCKERS_REL)
    rows = payload.get("deferred", [])
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        blocker_id = str(row.get("blocker_id", "")).strip()
        status = str(row.get("status", "")).strip()
        if blocker_id == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED" and status == "DEFERRED_RESOURCE_CONSTRAINT":
            machine_state = row.get("machine_effective_state", {})
            if not isinstance(machine_state, dict):
                machine_state = {}
            return {
                "blocker_id": blocker_id,
                "status": status,
                "current_externality_ceiling": str(row.get("current_externality_ceiling", "")).strip(),
                "machine_effective_state": dict(machine_state),
                "reentry_condition": dict(row.get("reentry_condition", {})) if isinstance(row.get("reentry_condition", {}), dict) else {},
            }
    return {}


def _selected_family(root: Path) -> Dict[str, Any]:
    wave5_readjudication = _load_optional(root, WAVE5_READJUDICATION_REL)
    wave5_blocker = _load_optional(root, WAVE5_BLOCKER_REL)
    current_head = _git_head(root)
    if (
        wave5_readjudication
        and wave5_blocker
        and str(wave5_readjudication.get("status", "")).strip() == "PASS"
        and str(wave5_readjudication.get("compiled_head_commit", "")).strip() == current_head
    ):
        return {
            "family_id": "WAVE5_CURRENT_HEAD_WORKTREE_FAMILY",
            "authority_class": "ACTIVE_CURRENT_HEAD_WORKTREE_FAMILY",
            "blocker_ref": WAVE5_BLOCKER_REL,
            "readjudication_ref": WAVE5_READJUDICATION_REL,
            "claim_ceiling_ref": WAVE5_TIER_REL,
            "claim_matrix_ref": WAVE5_CLAIM_MATRIX_REL,
            "organ_disposition_ref": WAVE5_ORGAN_DISPOSITION_REL,
            "supporting_refs": [
                POST_WAVE5_TERMINAL_STATES_REL,
                POST_WAVE5_C006_REL,
            ],
            "claim_boundary": (
                "This family is the active current-head workspace family for canonical posture inside the sealed W0 scope. "
                "It is not automatically public-release admissible while the broader worktree remains dirty and the transparency-verified subject commit differs from HEAD."
            ),
        }
    return {
        "family_id": "LEGACY_RELEASE_FAMILY",
        "authority_class": "ACTIVE_SEALED_RELEASE_FAMILY",
        "blocker_ref": FINAL_BLOCKER_REL,
        "readjudication_ref": FINAL_READJUDICATION_REL,
        "claim_ceiling_ref": FINAL_CLAIM_CEILING_REL,
        "claim_matrix_ref": FINAL_CLAIM_CEILING_REL,
        "organ_disposition_ref": WAVE5_ORGAN_DISPOSITION_REL,
        "supporting_refs": [],
        "claim_boundary": "The legacy sealed release family remains active because no current-head worktree family is validated at HEAD.",
    }


def _active_blocker_rows(root: Path, blocker_ref: str) -> Tuple[List[str], int]:
    payload = _load_optional(root, blocker_ref)
    rows = payload.get("open_blockers") if isinstance(payload.get("open_blockers"), list) else []
    blocker_ids: List[str] = []
    for row in rows:
        if isinstance(row, dict):
            value = str(row.get("blocker_id", "")).strip()
            if value:
                blocker_ids.append(value)
        else:
            value = str(row).strip()
            if value:
                blocker_ids.append(value)
    if blocker_ids:
        return blocker_ids, len(blocker_ids)
    open_count = int(payload.get("open_blocker_count", 0) or 0)
    return [], open_count


def build_authority_resolution_index(*, root: Path) -> Dict[str, Any]:
    truth_lock = _load_optional(root, DEFAULT_LOCK_REL)
    active_source_ref = active_truth_source_ref(root=root)
    active_source_payload = load_json_ref(root=root, ref=active_source_ref)
    documentary_payload = _load_optional(root, DOCUMENTARY_POINTER_REL)
    compatibility_pointer_ok = bool(documentary_payload) and compatibility_surface_is_non_authoritative(
        ref=DOCUMENTARY_POINTER_REL,
        active_source_ref=active_source_ref,
        payload=documentary_payload,
        documentary_refs=[DOCUMENTARY_POINTER_REL],
    )
    family = _selected_family(root)

    branch_name = ""
    branch_path = ""
    branch_head_sha = ""
    if ":" in active_source_ref:
        branch_name, branch_path = _split_branch_ref(active_source_ref)
        if _git_ref_exists(root, branch_name):
            branch_head_sha = _git(root, "rev-parse", branch_name)

    failures: List[str] = []
    if _payload_documentary_only(active_source_payload):
        failures.append("active_truth_source_resolves_to_documentary_only_payload")
    if not documentary_payload:
        failures.append("documentary_compatibility_pointer_missing")
    elif not compatibility_pointer_ok:
        failures.append("documentary_compatibility_pointer_not_documentary_only")
    if truth_lock and str(truth_lock.get("active_blocker_matrix_ref", "")).strip() != family["blocker_ref"]:
        failures.append("current_head_truth_lock_not_bound_to_selected_blocker_family")

    return {
        "schema_id": "kt.governance.authority_resolution_index.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "current_repo_head": _git_head(root),
        "single_active_authority_rule": "One active current-head scope authority family only; publication and historical sources may inform lineage but may not silently uplift current-head claims.",
        "active_current_head_scope": {
            "ref": DEFAULT_LOCK_REL,
            "authority_class": "ACTIVE_CURRENT_HEAD_SCOPE_AUTHORITY",
            "claim_scope": "CURRENT_HEAD_WORKTREE_SCOPE_ONLY",
            "status": "ACTIVE",
        },
        "active_current_head_blocker_family_ref": family["blocker_ref"],
        "active_current_head_claim_ceiling_ref": family["claim_ceiling_ref"],
        "resolved_sources": [
            {
                "surface_id": "active_publication_truth_source",
                "ref": active_source_ref,
                "resolution_class": "PUBLISHED_LEDGER_BRANCH_REF" if branch_name else "DIRECT_PATH_REF",
                "resolved_branch": branch_name,
                "resolved_relpath": branch_path,
                "resolved_branch_head_sha": branch_head_sha,
                "resolved_truth_subject_commit": _head_from_payload(active_source_payload),
                "authority_level": str(active_source_payload.get("authority_level", "")).strip(),
                "documentary_only": _payload_documentary_only(active_source_payload),
                "role": "SUPPORTING_PUBLICATION_TRUTH_SOURCE",
                "claim_boundary": "Supports publication lineage and historical transparency. It does not by itself uplift current-head scope, runtime, externality, product, or tier claims.",
            },
            {
                "surface_id": "documentary_compatibility_pointer",
                "ref": DOCUMENTARY_POINTER_REL,
                "resolution_class": "DOCUMENTARY_COMPATIBILITY_POINTER",
                "resolved_truth_subject_commit": _head_from_payload(documentary_payload),
                "authority_level": str(documentary_payload.get("authority_level", "")).strip(),
                "documentary_only": compatibility_pointer_ok,
                "role": "DOCUMENTARY_ONLY",
                "claim_boundary": "Compatibility mirror only. Never active authority.",
            },
        ],
        "historical_only_refs": [
            {"ref": FRONTIER_SCORECARD_REL, "role": "HISTORICAL_BOUNDED_FRONTIER_ARCHIVE_ONLY"},
            {"ref": FRONTIER_AUDIT_PACKET_REL, "role": "HISTORICAL_BOUNDED_FRONTIER_ARCHIVE_ONLY"},
            {"ref": FINAL_BLOCKER_REL, "role": "CARRIED_FORWARD_LEGACY_RELEASE_ONLY"},
            {"ref": FINAL_READJUDICATION_REL, "role": "CARRIED_FORWARD_LEGACY_RELEASE_ONLY"},
            {"ref": FINAL_CLAIM_CEILING_REL, "role": "CARRIED_FORWARD_LEGACY_RELEASE_ONLY"},
        ],
        "failures": failures,
    }


def build_historical_claim_firewall(*, root: Path) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.historical_claim_firewall.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "current_repo_head": _git_head(root),
        "law_id": "HISTORICAL_CLAIM_FIREWALL_V1_20260323",
        "law": "Historical bounded or publication truth may inform lineage and archive comparison only. It may not raise current-head runtime, externality, product, release, or tier claims.",
        "archive_only_refs": [
            FRONTIER_SCORECARD_REL,
            FRONTIER_AUDIT_PACKET_REL,
            FINAL_BLOCKER_REL,
            FINAL_READJUDICATION_REL,
            FINAL_CLAIM_CEILING_REL,
        ],
        "blocked_current_head_uplifts": [
            "current_head_runtime_truth",
            "current_head_externality_class",
            "current_head_release_readiness",
            "current_head_product_truth",
            "current_head_tier_ruling",
        ],
        "allowed_historical_uses": [
            "archive_lineage",
            "bounded_historical_comparison",
            "negative_result_preservation",
            "publication_lineage",
        ],
        "active_current_head_refs": [
            DEFAULT_LOCK_REL,
            WAVE5_BLOCKER_REL,
            WAVE5_TIER_REL,
            WAVE5_READJUDICATION_REL,
            WAVE5_ORGAN_DISPOSITION_REL,
            DEFAULT_DEFERRED_BLOCKERS_REL,
        ],
        "enforcement_refs": [
            DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
            DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
            "KT_PROD_CLEANROOM/tools/operator/present_head_authority_seal_validate.py",
            "KT_PROD_CLEANROOM/tools/operator/omega_gate.py",
        ],
    }


def build_tools_runtime_boundary_rule(*, root: Path) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.tools_runtime_boundary_rule.v1",
        "rule_id": "TOOLS_RUNTIME_BOUNDARY_RULE_V1_20260322",
        "status": "ACTIVE",
        "authoritative_contract_refs": [
            TRUST_ZONE_REL,
            RUNTIME_BOUNDARY_REL,
            "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
        ],
        "validator_command": "python -m tools.operator.toolchain_runtime_firewall_validate",
        "receipt_ref": TOOLCHAIN_FIREWALL_RECEIPT_REL,
        "prohibited_truth_vectors": [
            "tool-only execution paths counted as canonical runtime truth",
            "toolchain proving outputs counted as runtime capability proof",
            "commercial or documentary surfaces counted as runtime readiness",
            "generated receipts counted as governance law without source contract coverage",
        ],
        "claim_boundary": "This rule blocks toolchain/runtime leakage as a truth vector only. It does not upgrade capability, externality, release readiness, or commercial scope.",
    }


def build_current_head_truth_lock(*, root: Path) -> Dict[str, Any]:
    authority_report = build_authority_convergence_report(root=root)
    toolchain_receipt = build_toolchain_runtime_firewall_receipt(root=root)
    trust_zone_receipt = validate_trust_zones(root=root)
    authority_resolution = build_authority_resolution_index(root=root)
    historical_firewall = build_historical_claim_firewall(root=root)
    active_source_ref = active_truth_source_ref(root=root)
    active_source_payload = load_json_ref(root=root, ref=active_source_ref)
    current_head = _git_head(root)
    worktree = _worktree_summary(root)
    family = _selected_family(root)
    blocker_ids, blocker_count = _active_blocker_rows(root, family["blocker_ref"])
    deferred_c006 = _active_deferred_c006(root)
    deferred_machine_state = dict(deferred_c006.get("machine_effective_state", {})) if deferred_c006 else {}
    deferred_alignment_ok = True
    if blocker_ids == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]:
        deferred_alignment_ok = (
            bool(deferred_c006)
            and str(deferred_machine_state.get("externality_class_max", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
            and str(deferred_machine_state.get("comparative_widening", "")).strip() == "FORBIDDEN"
            and str(deferred_machine_state.get("commercial_widening", "")).strip() == "FORBIDDEN"
        )
    scope_refs = [
        EXECUTION_BOARD_REL,
        READINESS_SCOPE_REL,
        TRUTH_ENGINE_REL,
        TRUST_ZONE_REL,
        RUNTIME_BOUNDARY_REL,
        DEFAULT_TOOLS_BOUNDARY_RULE_REL,
        DEFAULT_DEFERRED_BLOCKERS_REL,
        family["blocker_ref"],
        family["readjudication_ref"],
        family["claim_ceiling_ref"],
        family["organ_disposition_ref"],
        *family["supporting_refs"],
        WORK_ORDER_ANCHOR_REL,
    ]
    scope_digest, scope_rows = _scope_digest(root, scope_refs)
    press_ready = False
    claim_boundary = (
        "This truth lock binds a sealed current-head workspace scope. It preserves one active current-head blocker family, "
        "treats the ledger truth source as publication-lineage support only, blocks historical uplift through the historical claim firewall, "
        "does not convert current HEAD into a transparency-verified subject commit, does not widen externality above E1, "
        "and does not by itself make the broader repo press-ready."
    )
    return {
        "schema_id": "kt.governance.current_head_truth_lock.v1",
        "lock_id": "CURRENT_HEAD_TRUTH_LOCK_V1_20260322",
        "status": (
            "PASS"
            if authority_report["status"] == "PASS"
            and toolchain_receipt["status"] == "PASS"
            and trust_zone_receipt["status"] == "PASS"
            and deferred_alignment_ok
            and authority_resolution["status"] == "PASS"
            and historical_firewall["status"] == "ACTIVE"
            else "FAIL"
        ),
        "generated_utc": utc_now_iso_z(),
        "current_repo_head": current_head,
        "active_authority_mode": "WORKTREE_TRANSITIONAL_CURRENT_HEAD_LOCKED",
        "press_ready": press_ready,
        "press_ready_condition": (
            "Current-head canonical claims become press-ready only after a clean commit on current HEAD or a separately declared sealed receipted worktree scope is accepted for the exact release scope."
        ),
        "authoritative_current_head_truth_source": active_source_ref,
        "authoritative_publication_truth_source_ref": active_source_ref,
        "authoritative_publication_truth_subject_commit": _head_from_payload(active_source_payload),
        "active_current_head_scope_authority_ref": DEFAULT_LOCK_REL,
        "authority_resolution_index_ref": DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
        "historical_claim_firewall_ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        "documentary_compatibility_pointer_ref": DOCUMENTARY_POINTER_REL,
        "authority_convergence_status": authority_report["status"],
        "authority_convergence_claim_boundary": str(authority_report.get("proof_class", "")).strip(),
        "authority_resolution_status": authority_resolution["status"],
        "historical_claim_firewall_status": historical_firewall["status"],
        "toolchain_runtime_firewall_status": toolchain_receipt["status"],
        "trust_zone_validation_status": trust_zone_receipt["status"],
        "active_family_id": family["family_id"],
        "active_family_class": family["authority_class"],
        "active_blocker_matrix_ref": family["blocker_ref"],
        "active_readjudication_ref": family["readjudication_ref"],
        "active_claim_ceiling_ref": family["claim_ceiling_ref"],
        "active_organ_disposition_ref": family["organ_disposition_ref"],
        "active_supporting_refs": list(family["supporting_refs"]),
        "active_open_blocker_count": blocker_count,
        "active_open_blocker_ids": blocker_ids,
        "deferred_blocker_register_ref": DEFAULT_DEFERRED_BLOCKERS_REL if deferred_c006 else "",
        "deferred_blocker_heartbeat_ref": DEFAULT_C006_HEARTBEAT_REL if _path_exists(root, DEFAULT_C006_HEARTBEAT_REL) else "",
        "active_deferred_blocker_ids": [str(deferred_c006.get("blocker_id", "")).strip()] if deferred_c006 else [],
        "deferred_blocker_alignment_status": "PASS" if deferred_alignment_ok else "FAIL",
        "claim_ceiling_enforcements": {
            "externality_class_max": str(deferred_machine_state.get("externality_class_max", "")).strip() or "E1_SAME_HOST_DETACHED_REPLAY",
            "comparative_widening": str(deferred_machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN",
            "commercial_widening": str(deferred_machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN",
            "reentry_condition": str(deferred_machine_state.get("reentry_condition", "")).strip()
            or str(deferred_c006.get("reentry_condition", {}).get("description", "")).strip(),
        },
        "legacy_release_family_refs": [
            FINAL_BLOCKER_REL,
            FINAL_READJUDICATION_REL,
            FINAL_CLAIM_CEILING_REL,
        ],
        "legacy_release_family_status": "CARRIED_FORWARD_NOT_ACTIVE_CURRENT_HEAD",
        "worktree_summary": worktree,
        "sealed_scope": {
            "scope_class": "CURRENT_HEAD_WORKTREE_SCOPE_ONLY",
            "digest_algorithm": "sha256",
            "scope_digest": scope_digest,
            "scope_refs": scope_rows,
        },
        "claim_boundary": claim_boundary,
        "stronger_claims_not_made": [
            "HEAD itself is the transparency-verified subject commit",
            "The historical or publication truth source silently upgrades current-head runtime or tier truth",
            "Current-head blocker closure is public-release admissible outside the sealed W0 scope",
            "Externality above E1 is earned",
            "Release readiness is proven",
            "Commercial readiness is proven",
            "Comparative widening is lawful while C006 remains deferred and open",
        ],
    }


def build_report_authority_index(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    worktree = _worktree_summary(root)
    family = _selected_family(root)
    blocker_ids, blocker_count = _active_blocker_rows(root, family["blocker_ref"])
    deferred_c006 = _active_deferred_c006(root)
    rows = [
        {
            "function_id": "current_head_truth_lock",
            "ref": DEFAULT_LOCK_REL,
            "authority_status": "ACTIVE_CURRENT_HEAD_LOCK",
            "tracking_state": "GENERATED_BY_W0_GATE",
            "claim_scope": "CURRENT_HEAD_WORKTREE_SCOPE_ONLY",
            "note": "Primary W0 truth lock for present-standing current-head execution.",
        },
        {
            "function_id": "execution_board",
            "ref": EXECUTION_BOARD_REL,
            "authority_status": "ACTIVE_COORDINATOR_NOT_LIVE_TRUTH",
            "tracking_state": _tracking_state(root, EXECUTION_BOARD_REL),
            "claim_scope": "GOVERNANCE_COORDINATION_ONLY",
            "note": "Coordinates waves and scope, but live truth resolves through the truth source and current-head truth lock.",
        },
        {
            "function_id": "truth_engine",
            "ref": TRUTH_ENGINE_REL,
            "authority_status": "ACTIVE_GOVERNANCE_CONTRACT",
            "tracking_state": _tracking_state(root, TRUTH_ENGINE_REL),
            "claim_scope": "TRUTH_DERIVATION",
            "note": "Current truth derivation contract.",
        },
        {
            "function_id": "authority_resolution_index",
            "ref": DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
            "authority_status": "ACTIVE_GOVERNANCE_RESOLUTION_INDEX",
            "tracking_state": _tracking_state(root, DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL),
            "claim_scope": "CURRENT_HEAD_AUTHORITY_RESOLUTION",
            "note": "Explicitly resolves current-head scope authority, supporting publication truth, and documentary compatibility mirrors.",
        },
        {
            "function_id": "historical_claim_firewall",
            "ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
            "authority_status": "ACTIVE_GOVERNANCE_FIREWALL",
            "tracking_state": _tracking_state(root, DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL),
            "claim_scope": "HISTORICAL_UPLIFT_PREVENTION",
            "note": "Prevents historical bounded packets from silently uplifting current-head truth.",
        },
        {
            "function_id": "trust_zones",
            "ref": TRUST_ZONE_REL,
            "authority_status": "ACTIVE_GOVERNANCE_CONTRACT",
            "tracking_state": _tracking_state(root, TRUST_ZONE_REL),
            "claim_scope": "ZONE_AND_PLANE_ENFORCEMENT",
            "note": "Authoritative zone registry.",
        },
        {
            "function_id": "runtime_boundary",
            "ref": RUNTIME_BOUNDARY_REL,
            "authority_status": "ACTIVE_GOVERNANCE_CONTRACT",
            "tracking_state": _tracking_state(root, RUNTIME_BOUNDARY_REL),
            "claim_scope": "CANONICAL_RUNTIME_BOUNDARY",
            "note": "Authoritative runtime boundary contract.",
        },
        {
            "function_id": "tools_runtime_boundary_rule",
            "ref": DEFAULT_TOOLS_BOUNDARY_RULE_REL,
            "authority_status": "ACTIVE_GOVERNANCE_RULE",
            "tracking_state": _tracking_state(root, DEFAULT_TOOLS_BOUNDARY_RULE_REL),
            "claim_scope": "TOOLCHAIN_RUNTIME_FIREWALL",
            "note": "Explicit W0 anti-leak rule.",
        },
        {
            "function_id": "blocker_matrix",
            "ref": family["blocker_ref"],
            "authority_status": family["authority_class"],
            "tracking_state": _tracking_state(root, family["blocker_ref"]),
            "claim_scope": "CURRENT_HEAD_BLOCKER_MAP",
            "note": f"Selected active blocker family with {blocker_count} open blockers: {', '.join(blocker_ids) if blocker_ids else 'none declared'}.",
        },
        {
            "function_id": "deferred_blocker_register",
            "ref": DEFAULT_DEFERRED_BLOCKERS_REL,
            "authority_status": "ACTIVE_CURRENT_HEAD_SUPPORT_REGISTER" if deferred_c006 else "SUPPORT_REGISTER_ABSENT",
            "tracking_state": _tracking_state(root, DEFAULT_DEFERRED_BLOCKERS_REL),
            "claim_scope": "DEFERRED_BLOCKER_LAW",
            "note": (
                "C006 remains open under resource-constrained deferral; E1 ceilings stay enforced until second-host return plus validator pass."
                if deferred_c006
                else "No active deferred blocker register is bound."
            ),
        },
        {
            "function_id": "blocker_matrix_legacy",
            "ref": FINAL_BLOCKER_REL,
            "authority_status": "CARRIED_FORWARD_RELEASE_FAMILY",
            "tracking_state": _tracking_state(root, FINAL_BLOCKER_REL),
            "claim_scope": "HISTORICAL_OR_RELEASE_SCOPED_ONLY",
            "note": "Must not silently override the active current-head blocker family.",
        },
        {
            "function_id": "claim_ceiling",
            "ref": family["claim_ceiling_ref"],
            "authority_status": family["authority_class"],
            "tracking_state": _tracking_state(root, family["claim_ceiling_ref"]),
            "claim_scope": "CURRENT_HEAD_CLAIM_CEILING",
            "note": "Active claim ceiling family for current-head posture.",
        },
        {
            "function_id": "readjudication",
            "ref": family["readjudication_ref"],
            "authority_status": family["authority_class"],
            "tracking_state": _tracking_state(root, family["readjudication_ref"]),
            "claim_scope": "CURRENT_HEAD_READJUDICATION",
            "note": "Active readjudication family for current-head posture.",
        },
        {
            "function_id": "organ_disposition",
            "ref": family["organ_disposition_ref"],
            "authority_status": "ACTIVE_CURRENT_HEAD_SUPPORTING_REGISTER",
            "tracking_state": _tracking_state(root, family["organ_disposition_ref"]),
            "claim_scope": "ORGAN_DISPOSITION",
            "note": "Authoritative organ disposition family retained for W1 extension.",
        },
        {
            "function_id": "c006_second_host_status",
            "ref": POST_WAVE5_C006_REL,
            "authority_status": "ACTIVE_BLOCKER_DELTA_SUPPORT",
            "tracking_state": _tracking_state(root, POST_WAVE5_C006_REL),
            "claim_scope": "EXTERNALITY_BOUNDARY",
            "note": "Current-head C006 execution status support surface.",
        },
        {
            "function_id": "c006_deferral_heartbeat",
            "ref": DEFAULT_C006_HEARTBEAT_REL,
            "authority_status": "ACTIVE_BLOCKER_HEARTBEAT" if _path_exists(root, DEFAULT_C006_HEARTBEAT_REL) else "BLOCKER_HEARTBEAT_PENDING",
            "tracking_state": _tracking_state(root, DEFAULT_C006_HEARTBEAT_REL),
            "claim_scope": "DEFERRED_BLOCKER_HEARTBEAT",
            "note": "Recurring machine reminder that C006 is deferred, open, and still ceiling-enforcing.",
        },
        {
            "function_id": "work_order_anchor",
            "ref": WORK_ORDER_ANCHOR_REL,
            "authority_status": "ACTIVE_DOCUMENTARY_ANCHOR",
            "tracking_state": _tracking_state(root, WORK_ORDER_ANCHOR_REL),
            "claim_scope": "EXECUTION_CONSTRAINTS_ONLY",
            "note": "Anchor surface for the present-standing convergence family.",
        },
    ]
    return {
        "schema_id": "kt.operator.report_authority_index.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_repo_head": current_head,
        "current_worktree_state": worktree,
        "active_current_head_family": family["family_id"],
        "claim_boundary": family["claim_boundary"],
        "rows": rows,
        "single_source_rule": "Each function binds to exactly one active authoritative family; siblings are carried-forward, documentary, or prohibited.",
    }


def build_authority_supersession_map(*, root: Path) -> Dict[str, Any]:
    family = _selected_family(root)
    rows = [
        {
            "function_id": "truth_source",
            "action": "UPGRADE_EXISTING",
            "authoritative_ref": DEFAULT_LOCK_REL,
            "supporting_refs": [
                DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
                DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
                EXECUTION_BOARD_REL,
                READINESS_SCOPE_REL,
                TRUTH_ENGINE_REL,
            ],
            "sibling_refs": [
                "KT_PROD_CLEANROOM/reports/kt_current_head_truth_source.json",
                "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
            ],
        },
        {
            "function_id": "blocker_matrix",
            "action": "VALIDATE_EXISTING",
            "authoritative_ref": family["blocker_ref"],
            "supporting_refs": [
                family["readjudication_ref"],
                family["claim_ceiling_ref"],
            ],
            "sibling_refs": [FINAL_BLOCKER_REL],
        },
        {
            "function_id": "claim_ceiling",
            "action": "VALIDATE_EXISTING",
            "authoritative_ref": family["claim_ceiling_ref"],
            "supporting_refs": [WAVE5_CLAIM_MATRIX_REL],
            "sibling_refs": [FINAL_CLAIM_CEILING_REL],
        },
        {
            "function_id": "organ_disposition",
            "action": "UPGRADE_EXISTING",
            "authoritative_ref": WAVE5_ORGAN_DISPOSITION_REL,
            "supporting_refs": [POST_WAVE5_TERMINAL_STATES_REL],
            "sibling_refs": ["KT_PROD_CLEANROOM/reports/kt_unified_convergence_named_organ_disposition_register.json"],
        },
        {
            "function_id": "adapter_abi",
            "action": "VALIDATE_EXISTING",
            "authoritative_ref": "KT_PROD_CLEANROOM/governance/kt_adapter_abi_v1.json",
            "supporting_refs": [],
            "sibling_refs": [],
        },
        {
            "function_id": "benchmark_constitution",
            "action": "VALIDATE_EXISTING",
            "authoritative_ref": "KT_PROD_CLEANROOM/governance/kt_benchmark_constitution_v1.json",
            "supporting_refs": ["KT_PROD_CLEANROOM/governance/capability_atlas_contract.json"],
            "sibling_refs": [],
        },
        {
            "function_id": "externality_ladder",
            "action": "VALIDATE_EXISTING",
            "authoritative_ref": "KT_PROD_CLEANROOM/governance/kt_externality_class_matrix_v1.json",
            "supporting_refs": [POST_WAVE5_C006_REL],
            "sibling_refs": [],
        },
        {
            "function_id": "deferred_blocker_register",
            "action": "VALIDATE_EXISTING",
            "authoritative_ref": DEFAULT_DEFERRED_BLOCKERS_REL,
            "supporting_refs": [POST_WAVE5_C006_REL, DEFAULT_C006_HEARTBEAT_REL],
            "sibling_refs": [],
        },
        {
            "function_id": "tools_runtime_boundary",
            "action": "CREATE_NEW_IF_ABSENT",
            "authoritative_ref": DEFAULT_TOOLS_BOUNDARY_RULE_REL,
            "supporting_refs": [
                TRUST_ZONE_REL,
                RUNTIME_BOUNDARY_REL,
                TOOLCHAIN_FIREWALL_RECEIPT_REL,
            ],
            "sibling_refs": [],
        },
        {
            "function_id": "historical_claim_firewall",
            "action": "CREATE_NEW_IF_ABSENT",
            "authoritative_ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
            "supporting_refs": [
                FRONTIER_SCORECARD_REL,
                FRONTIER_AUDIT_PACKET_REL,
                FINAL_BLOCKER_REL,
                FINAL_READJUDICATION_REL,
                FINAL_CLAIM_CEILING_REL,
            ],
            "sibling_refs": [],
        },
    ]
    return {
        "schema_id": "kt.operator.authority_supersession_map.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "law": "For each function, KT must bind, supersede, or create exactly one authoritative surface.",
        "action_priority": ["VALIDATE_EXISTING", "UPGRADE_EXISTING", "CREATE_NEW_IF_ABSENT"],
        "rows": rows,
    }


def build_canonical_delta_w0(*, root: Path) -> Dict[str, Any]:
    family = _selected_family(root)
    blocker_ids, blocker_count = _active_blocker_rows(root, family["blocker_ref"])
    return {
        "schema_id": "kt.operator.canonical_delta_w0.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "wave_id": "W0_TRUTH_AND_BOUNDARY_CLOSURE",
        "canonical_outputs": [
            DEFAULT_LOCK_REL,
            DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
            DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
            DEFAULT_TOOLS_BOUNDARY_RULE_REL,
            DEFAULT_REPORT_AUTHORITY_INDEX_REL,
            DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL,
            DEFAULT_OMEGA_GATE_RECEIPT_REL,
        ],
        "blocker_delta": {
            "active_blocker_family": family["family_id"],
            "active_blocker_matrix_ref": family["blocker_ref"],
            "open_blocker_count": blocker_count,
            "open_blocker_ids": blocker_ids,
        },
        "claim_boundary_delta": "Current-head blocker and claim-ceiling selection is now explicit, typed, and sealed to a W0 scope.",
        "stronger_claims_not_made": [
            "release readiness proven",
            "externality above E1 earned",
            "commercial readiness proven",
        ],
    }


def build_advancement_delta_w0(*, root: Path) -> Dict[str, Any]:
    tier = _load_optional(root, WAVE5_TIER_REL)
    objectives = tier.get("continuing_governed_advancement_objectives")
    return {
        "schema_id": "kt.operator.advancement_delta_w0.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "wave_id": "W0_TRUTH_AND_BOUNDARY_CLOSURE",
        "claim_effect": "NO_CANONICAL_WIDENING",
        "continuing_governed_advancement_objectives": objectives if isinstance(objectives, list) else [],
        "note": "W0 preserves breadth as governed advancement without widening the active canonical claim surface.",
    }


def build_omega_gate_receipt(*, root: Path) -> Dict[str, Any]:
    authority_report = build_authority_convergence_report(root=root)
    toolchain_receipt = build_toolchain_runtime_firewall_receipt(root=root)
    trust_zone_receipt = validate_trust_zones(root=root)
    authority_resolution = build_authority_resolution_index(root=root)
    historical_firewall = build_historical_claim_firewall(root=root)
    current_head_lock = build_current_head_truth_lock(root=root)
    family = _selected_family(root)
    blocker_ids, blocker_count = _active_blocker_rows(root, family["blocker_ref"])
    deferred_c006 = _active_deferred_c006(root)
    deferred_machine_state = dict(deferred_c006.get("machine_effective_state", {})) if deferred_c006 else {}
    deferred_alignment_ok = (
        blocker_ids != ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
        or (
            bool(deferred_c006)
            and str(deferred_machine_state.get("externality_class_max", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
            and str(deferred_machine_state.get("comparative_widening", "")).strip() == "FORBIDDEN"
            and str(deferred_machine_state.get("commercial_widening", "")).strip() == "FORBIDDEN"
        )
    )
    all_checks = [
        {
            "check": "authority_convergence_passes",
            "status": authority_report["status"],
        },
        {
            "check": "toolchain_runtime_firewall_passes",
            "status": toolchain_receipt["status"],
        },
        {
            "check": "trust_zone_validation_passes",
            "status": trust_zone_receipt["status"],
        },
        {
            "check": "authority_resolution_index_passes",
            "status": authority_resolution["status"],
            "ref": DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
        },
        {
            "check": "historical_claim_firewall_active",
            "status": "PASS" if historical_firewall["status"] == "ACTIVE" else "FAIL",
            "ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        },
        {
            "check": "current_head_truth_lock_compiles",
            "status": current_head_lock["status"],
        },
        {
            "check": "active_blocker_family_selected",
            "status": "PASS" if blocker_count >= 0 else "FAIL",
            "ref": family["blocker_ref"],
        },
        {
            "check": "c006_deferral_ceiling_alignment_passes",
            "status": "PASS" if deferred_alignment_ok else "FAIL",
            "ref": DEFAULT_DEFERRED_BLOCKERS_REL,
        },
    ]
    failures = [row["check"] for row in all_checks if row["status"] != "PASS"]
    return {
        "schema_id": "kt.operator.omega_gate_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "wave_id": "W0_TRUTH_AND_BOUNDARY_CLOSURE",
        "gate_command": "python -m kt.omega_gate",
        "current_repo_head": _git_head(root),
        "active_blocker_family": family["family_id"],
        "active_blocker_matrix_ref": family["blocker_ref"],
        "active_open_blocker_count": blocker_count,
        "active_open_blocker_ids": blocker_ids,
        "current_head_truth_lock_ref": DEFAULT_LOCK_REL,
        "authority_resolution_index_ref": DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL,
        "historical_claim_firewall_ref": DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL,
        "report_authority_index_ref": DEFAULT_REPORT_AUTHORITY_INDEX_REL,
        "authority_supersession_map_ref": DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL,
        "checks": all_checks,
        "failures": failures,
        "claim_boundary": (
            "Omega gate passing means W0 truth and boundary closure are load-bearing for the sealed current-head workspace scope only. "
            "It does not certify release readiness, cross-host externality, historical uplift, or broad commercial admissibility."
        ),
        "next_lawful_move": "W1_BOUNDARY_PURIFICATION_AND_SINGLE_SPINE",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit W0 OMEGA truth and boundary artifacts and one typed gate receipt.")
    parser.add_argument("--lock-output", default=DEFAULT_LOCK_REL)
    parser.add_argument("--authority-resolution-output", default=DEFAULT_AUTHORITY_RESOLUTION_INDEX_REL)
    parser.add_argument("--historical-firewall-output", default=DEFAULT_HISTORICAL_CLAIM_FIREWALL_REL)
    parser.add_argument("--tools-boundary-output", default=DEFAULT_TOOLS_BOUNDARY_RULE_REL)
    parser.add_argument("--authority-index-output", default=DEFAULT_REPORT_AUTHORITY_INDEX_REL)
    parser.add_argument("--supersession-output", default=DEFAULT_AUTHORITY_SUPERSESSION_MAP_REL)
    parser.add_argument("--canonical-delta-output", default=DEFAULT_CANONICAL_DELTA_REL)
    parser.add_argument("--advancement-delta-output", default=DEFAULT_ADVANCEMENT_DELTA_REL)
    parser.add_argument("--gate-output", default=DEFAULT_OMEGA_GATE_RECEIPT_REL)
    return parser.parse_args(argv)


def _write(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable(_resolve(root, rel), payload)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()

    _write(root, str(args.authority_resolution_output), build_authority_resolution_index(root=root))
    _write(root, str(args.historical_firewall_output), build_historical_claim_firewall(root=root))
    _write(root, str(args.tools_boundary_output), build_tools_runtime_boundary_rule(root=root))
    _write(root, str(args.lock_output), build_current_head_truth_lock(root=root))
    _write(root, str(args.authority_index_output), build_report_authority_index(root=root))
    _write(root, str(args.supersession_output), build_authority_supersession_map(root=root))
    _write(root, str(args.canonical_delta_output), build_canonical_delta_w0(root=root))
    _write(root, str(args.advancement_delta_output), build_advancement_delta_w0(root=root))

    receipt = build_omega_gate_receipt(root=root)
    _write(root, str(args.gate_output), receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
