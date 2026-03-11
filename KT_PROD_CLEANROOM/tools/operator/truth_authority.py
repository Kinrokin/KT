from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List

from tools.operator.titanium_common import utc_now_iso_z


SETTLED_AUTHORITATIVE = "SETTLED_AUTHORITATIVE"
TRANSITIONAL_AUTHORITATIVE = "TRANSITIONAL_AUTHORITATIVE"
CURRENT_POINTER_REL = "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"
LEDGER_CURRENT_POINTER_REF = "kt_truth_ledger:ledger/current/current_pointer.json"
DOCUMENTARY_TRUTH_POLICY_REL = "KT_PROD_CLEANROOM/governance/documentary_truth_policy.json"


def path_ref(*, root: Path, path: Path) -> str:
    root_resolved = root.resolve()
    path_resolved = path.resolve()
    try:
        return path_resolved.relative_to(root_resolved).as_posix()
    except ValueError:
        return path_resolved.as_posix()


def is_branch_ref(ref: str) -> bool:
    value = str(ref).strip()
    return ":" in value and not value.startswith("/") and not value[1:3] == ":\\"


def load_json_ref(*, root: Path, ref: str) -> Dict[str, Any]:
    value = str(ref).strip()
    if not value:
        raise RuntimeError("FAIL_CLOSED: empty JSON ref")
    if is_branch_ref(value):
        branch, relpath = value.split(":", 1)
        try:
            content = subprocess.check_output(
                ["git", "-C", str(root), "show", f"{branch}:{relpath}"],
                text=True,
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001
            # Local bootstrap and unit-test fixtures may exercise ledger refs
            # before a real git branch exists. In that case, fall back to the
            # filesystem path encoded by the branch ref.
            fallback = (root / Path(relpath)).resolve()
            if not fallback.exists():
                raise RuntimeError(f"FAIL_CLOSED: unable to load branch ref {value}: {exc}") from exc
            return json.loads(fallback.read_text(encoding="utf-8"))
        return json.loads(content.lstrip("\ufeff"))
    path = (root / Path(value)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def active_truth_source_ref(*, root: Path) -> str:
    policy_path = root / DOCUMENTARY_TRUTH_POLICY_REL
    if not policy_path.exists():
        return CURRENT_POINTER_REL
    policy = json.loads(policy_path.read_text(encoding="utf-8-sig"))
    active = str(policy.get("active_current_head_truth_source", "")).strip()
    return active or CURRENT_POINTER_REL


def active_supporting_truth_surfaces(*, root: Path) -> List[str]:
    policy_path = root / DOCUMENTARY_TRUTH_POLICY_REL
    if not policy_path.exists():
        return []
    policy = json.loads(policy_path.read_text(encoding="utf-8-sig"))
    rows = policy.get("active_supporting_truth_surfaces") if isinstance(policy.get("active_supporting_truth_surfaces"), list) else []
    return [str(item).strip() for item in rows if str(item).strip()]


def index_check(index: Dict[str, Any], check_id: str) -> Dict[str, Any]:
    checks = index.get("checks") if isinstance(index.get("checks"), list) else []
    for row in checks:
        if not isinstance(row, dict):
            continue
        if str(row.get("check_id", "")).strip() == check_id:
            return row
    return {}


def authority_status(*, index: Dict[str, Any], enforcement: Dict[str, Any], conflicts: Dict[str, Any]) -> str:
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    clean_clone_status = str(index_check(index, "operator_clean_clone_smoke").get("status", "")).strip().upper()
    enforcement_status = str(enforcement.get("status", "")).strip().upper()
    conflicts_status = str(conflicts.get("status", "")).strip().upper()
    if bool(worktree.get("git_dirty")):
        return TRANSITIONAL_AUTHORITATIVE
    if clean_clone_status != "PASS":
        return TRANSITIONAL_AUTHORITATIVE
    if enforcement_status != "PASS":
        return TRANSITIONAL_AUTHORITATIVE
    if conflicts_status != "PASS":
        return TRANSITIONAL_AUTHORITATIVE
    return SETTLED_AUTHORITATIVE


def open_blockers(*, index: Dict[str, Any], enforcement: Dict[str, Any], conflicts: Dict[str, Any]) -> List[str]:
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    blockers: List[str] = []
    if bool(worktree.get("git_dirty")):
        blockers.append("WORKTREE_DIRTY")

    clean_clone_status = str(index_check(index, "operator_clean_clone_smoke").get("status", "")).strip().upper()
    if clean_clone_status == "SKIP":
        blockers.append("CLEAN_CLONE_NOT_RUN")
    elif clean_clone_status == "FAIL":
        blockers.append("CLEAN_CLONE_FAILED")
    elif clean_clone_status != "PASS":
        blockers.append("CLEAN_CLONE_UNVERIFIED")

    if str(enforcement.get("status", "")).strip().upper() != "PASS":
        blockers.append("TRACKED_TRUTH_NOT_RECONCILED")

    if str(conflicts.get("status", "")).strip().upper() != "PASS":
        rows = conflicts.get("conflicts") if isinstance(conflicts.get("conflicts"), list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            conflict_id = str(row.get("conflict_id", "")).strip()
            if conflict_id:
                blockers.append(conflict_id)
        if not rows:
            blockers.append("POSTURE_CONFLICTS_PRESENT")

    deduped: List[str] = []
    seen = set()
    for blocker in blockers:
        if blocker in seen:
            continue
        seen.add(blocker)
        deduped.append(blocker)
    return deduped


def _head_from(payload: Dict[str, Any]) -> str:
    if "validated_head_sha" in payload:
        return str(payload.get("validated_head_sha", "")).strip()
    worktree = payload.get("worktree")
    if isinstance(worktree, dict):
        return str(worktree.get("head_sha", "")).strip()
    return str(payload.get("head_sha", "")).strip()


def build_settled_truth_source_receipt(
    *,
    root: Path,
    live_validation_index_path: Path,
    report_root_rel: str,
    index: Dict[str, Any],
    current_state: Dict[str, Any],
    runtime_audit: Dict[str, Any],
    posture_consistency: Dict[str, Any],
    enforcement: Dict[str, Any],
    conflicts: Dict[str, Any],
) -> Dict[str, Any]:
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    live_head = str(worktree.get("head_sha", "")).strip()
    branch_ref = str(index.get("branch_ref", "")).strip()
    status = authority_status(index=index, enforcement=enforcement, conflicts=conflicts)
    blockers = open_blockers(index=index, enforcement=enforcement, conflicts=conflicts)
    generated_utc = str(index.get("generated_utc", "")).strip() or utc_now_iso_z()
    active_surfaces = [
        f"{report_root_rel}/current_state_receipt.json",
        f"{report_root_rel}/runtime_closure_audit.json",
        f"{report_root_rel}/posture_consistency_receipt.json",
        f"{report_root_rel}/posture_consistency_enforcement_receipt.json",
        f"{report_root_rel}/posture_conflict_receipt.json",
    ]
    return {
        "schema_id": "kt.operator.settled_truth_source_receipt.v1",
        "generated_utc": generated_utc,
        "status": status,
        "branch_ref": branch_ref,
        "pinned_head_sha": live_head,
        "authoritative_current_pointer_ref": CURRENT_POINTER_REL,
        "current_head_truth_source": path_ref(root=root, path=live_validation_index_path),
        "derived_posture_state": str(enforcement.get("derived_state", "")).strip(),
        "worktree_dirty": bool(worktree.get("git_dirty")),
        "operator_clean_clone_status": str(index_check(index, "operator_clean_clone_smoke").get("status", "")).strip().upper() or "UNKNOWN",
        "enforcement_status": str(enforcement.get("status", "")).strip().upper() or "UNKNOWN",
        "conflict_status": str(conflicts.get("status", "")).strip().upper() or "UNKNOWN",
        "active_tracked_truth_surfaces": active_surfaces,
        "open_blockers": blockers,
        "supersedes_if_current_head_changes": active_surfaces,
        "supporting_contracts": [
            "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json",
            "KT_PROD_CLEANROOM/governance/truth_supersession_rules.json",
            "KT_PROD_CLEANROOM/governance/truth_freshness_windows.json",
            "KT_PROD_CLEANROOM/governance/truth_invalidation_rules.json",
            "KT_PROD_CLEANROOM/governance/truth_publication_contract.json",
            "KT_PROD_CLEANROOM/governance/tracked_vs_generated_truth_boundary.json",
        ],
        "tracked_truth_heads": {
            "live_validation_index": _head_from(index),
            "current_state_receipt": _head_from(current_state),
            "runtime_closure_audit": _head_from(runtime_audit),
            "posture_consistency_receipt": _head_from(posture_consistency),
        },
    }


def build_truth_supersession_receipt(
    *,
    root: Path,
    live_validation_index_path: Path,
    report_root_rel: str,
    index: Dict[str, Any],
    current_state: Dict[str, Any],
    runtime_audit: Dict[str, Any],
    posture_consistency: Dict[str, Any],
    enforcement: Dict[str, Any],
    conflicts: Dict[str, Any],
) -> Dict[str, Any]:
    live_head = _head_from(index)
    active_truth_root = CURRENT_POINTER_REL
    generated_utc = str(index.get("generated_utc", "")).strip() or utc_now_iso_z()
    superseded: List[Dict[str, Any]] = []
    candidates = {
        f"{report_root_rel}/live_validation_index.json": index,
        f"{report_root_rel}/current_state_receipt.json": current_state,
        f"{report_root_rel}/runtime_closure_audit.json": runtime_audit,
        f"{report_root_rel}/posture_consistency_receipt.json": posture_consistency,
    }
    for rel_path, payload in candidates.items():
        observed_head = _head_from(payload)
        if observed_head and live_head and observed_head != live_head:
            superseded.append(
                {
                    "path": rel_path,
                    "reason": "HEAD_STALE",
                    "observed_head_sha": observed_head,
                    "authoritative_head_sha": live_head,
                }
            )
        if rel_path.endswith("posture_consistency_receipt.json"):
            status = str(payload.get("status", "")).strip().upper()
            if status and status != "PASS":
                superseded.append({"path": rel_path, "reason": "STATUS_NOT_PASS", "status": status})

    return {
        "schema_id": "kt.operator.truth_supersession_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "current_head_truth_source": path_ref(root=root, path=live_validation_index_path),
        "active_truth_root": active_truth_root,
        "supporting_tracked_truth_index": f"{report_root_rel}/settled_truth_source_receipt.json",
        "authority_status": authority_status(index=index, enforcement=enforcement, conflicts=conflicts),
        "derived_posture_state": str(enforcement.get("derived_state", "")).strip(),
        "superseded_surfaces": superseded,
        "open_blockers": open_blockers(index=index, enforcement=enforcement, conflicts=conflicts),
    }


def expected_readiness_excludes() -> List[str]:
    return ["ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "LAB", "QUARANTINED"]


def frozen_surface_coverage(*, frozen_surfaces: Iterable[str], protected_surfaces: Iterable[str]) -> List[str]:
    protected = [str(item).strip() for item in protected_surfaces if str(item).strip()]
    missing: List[str] = []
    for surface in frozen_surfaces:
        path = str(surface).strip()
        if not path:
            continue
        surface_path = Path(path.replace("\\", "/"))
        if not any(surface_path.match(item.replace("\\", "/")) for item in protected):
            missing.append(path)
    return missing
