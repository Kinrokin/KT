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
TRUTH_PUBLICATION_CLEANLINESS_RULES_REL = "KT_PROD_CLEANROOM/governance/truth_publication_cleanliness_rules.json"

DEFAULT_PUBLICATION_CARRIER_SURFACE_PATTERNS = [
    "KT_PROD_CLEANROOM/reports/**",
    "KT_PROD_CLEANROOM/exports/_truth/current/**",
    "KT_PROD_CLEANROOM/governance/execution_board.json",
    "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
    "KT_PROD_CLEANROOM/governance/h0_freeze_policy.json",
]


def path_ref(*, root: Path, path: Path) -> str:
    root_resolved = root.resolve()
    path_resolved = path.resolve()
    try:
        return path_resolved.relative_to(root_resolved).as_posix()
    except ValueError:
        return path_resolved.as_posix()


def _head_from_payload(payload: Dict[str, Any]) -> str:
    for key in ("truth_subject_commit", "validated_head_sha", "pinned_head_sha", "head_sha", "head"):
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    worktree = payload.get("worktree")
    if isinstance(worktree, dict):
        value = str(worktree.get("head_sha", "")).strip()
        if value:
            return value
    return ""


def _normalize_git_status_path(raw: str) -> str:
    value = str(raw).strip()
    if not value:
        return ""
    if len(value) > 3 and value[1] in {" ", "M", "A", "D", "R", "C", "U", "?"} and value[2] == " ":
        value = value[3:]
    if " -> " in value:
        value = value.split(" -> ", 1)[1]
    return value.replace("\\", "/").strip()


def _load_publication_carrier_surface_patterns(*, root: Path) -> List[str]:
    path = root / TRUTH_PUBLICATION_CLEANLINESS_RULES_REL
    if not path.exists():
        return list(DEFAULT_PUBLICATION_CARRIER_SURFACE_PATTERNS)
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    rows = payload.get("allowed_publication_carrier_surfaces")
    if not isinstance(rows, list) or not rows:
        return list(DEFAULT_PUBLICATION_CARRIER_SURFACE_PATTERNS)
    out = [str(item).replace("\\", "/").strip() for item in rows if str(item).strip()]
    return out or list(DEFAULT_PUBLICATION_CARRIER_SURFACE_PATTERNS)


def _matches_any_pattern(path: str, patterns: Iterable[str]) -> bool:
    normalized = str(path).replace("\\", "/").strip()
    if not normalized:
        return False
    path_obj = Path(normalized)
    for pattern in patterns:
        candidate = str(pattern).replace("\\", "/").strip()
        if not candidate:
            continue
        if path_obj.match(candidate):
            return True
    return False


def split_publication_carrier_dirty_paths(*, root: Path, dirty_lines: Iterable[str]) -> Dict[str, Any]:
    patterns = _load_publication_carrier_surface_patterns(root=root)
    normalized_paths = [
        _normalize_git_status_path(line)
        for line in dirty_lines
        if _normalize_git_status_path(line)
    ]
    carrier_dirty = [path for path in normalized_paths if _matches_any_pattern(path, patterns)]
    subject_dirty = [path for path in normalized_paths if path not in carrier_dirty]
    return {
        "all_dirty_paths": normalized_paths,
        "publication_carrier_surface_patterns": patterns,
        "publication_carrier_dirty_files": carrier_dirty,
        "subject_dirty_files": subject_dirty,
        "publication_carrier_only_dirty": bool(carrier_dirty) and not subject_dirty,
        "subject_git_dirty": bool(subject_dirty),
    }


def _git_changed_paths_between(*, root: Path, base_ref: str, head_ref: str) -> List[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "diff", "--name-only", str(base_ref).strip(), str(head_ref).strip()],
            text=True,
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()]


def resolve_truth_head_context(*, root: Path, live_head: str, dirty_lines: Iterable[str] = ()) -> Dict[str, Any]:
    live = str(live_head).strip()
    dirty_split = split_publication_carrier_dirty_paths(root=root, dirty_lines=dirty_lines)
    active_source = active_truth_source_ref(root=root)
    active_subject = ""
    try:
        active_payload = load_json_ref(root=root, ref=active_source)
        active_subject = _head_from_payload(active_payload)
    except Exception:  # noqa: BLE001
        active_subject = ""

    relation = "HEAD_IS_SUBJECT"
    validated_subject = live
    carrier_commit = ""
    carrier_delta_files: List[str] = []
    if active_subject and live and active_subject != live:
        candidate_delta_files = _git_changed_paths_between(root=root, base_ref=active_subject, head_ref=live)
        if candidate_delta_files and all(
            _matches_any_pattern(path, dirty_split["publication_carrier_surface_patterns"]) for path in candidate_delta_files
        ):
            validated_subject = active_subject
            carrier_commit = live
            carrier_delta_files = candidate_delta_files
            relation = "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT"
        else:
            relation = "HEAD_DIVERGED_FROM_ACTIVE_SUBJECT"

    if relation == "HEAD_IS_SUBJECT":
        carrier_commit = ""

    return {
        "validated_subject_head_sha": validated_subject,
        "publication_carrier_head_sha": carrier_commit,
        "head_relation": relation,
        "active_truth_source_ref": active_source,
        "active_truth_subject_head_sha": active_subject,
        "publication_carrier_delta_files": carrier_delta_files,
        **dirty_split,
    }


def is_branch_ref(ref: str) -> bool:
    value = str(ref).strip()
    return ":" in value and not value.startswith("/") and not value[1:3] == ":\\"


def _is_git_worktree(root: Path) -> bool:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            text=True,
            encoding="utf-8",
        ).strip()
    except Exception:  # noqa: BLE001
        return False
    return out.lower() == "true"


def _git_ref_exists(*, root: Path, ref: str) -> bool:
    try:
        subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", str(ref).strip()],
            text=True,
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        return False
    return True


def _git_remotes(root: Path) -> List[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "remote"],
            text=True,
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        return []
    remotes = [line.strip() for line in (out or "").splitlines() if line.strip()]
    if "origin" in remotes:
        remotes = ["origin"] + [remote for remote in remotes if remote != "origin"]
    return remotes


def _git_show_ref_path(*, root: Path, ref: str, relpath: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "show", f"{str(ref).strip()}:{str(relpath).strip()}"],
        text=True,
        encoding="utf-8",
    )


def load_json_ref(*, root: Path, ref: str) -> Dict[str, Any]:
    value = str(ref).strip()
    if not value:
        raise RuntimeError("FAIL_CLOSED: empty JSON ref")
    if is_branch_ref(value):
        branch, relpath = value.split(":", 1)
        if _is_git_worktree(root) and not _git_ref_exists(root=root, ref=branch):
            remotes = _git_remotes(root)
            if any(str(branch).strip().startswith(f"{remote}/") for remote in remotes):
                raise RuntimeError(f"FAIL_CLOSED: unable to load branch ref {value}: branch ref missing: {branch}")

            attempted: List[str] = [str(branch).strip()]
            for remote in remotes:
                candidate = f"{remote}/{str(branch).strip()}"
                attempted.append(candidate)
                if not _git_ref_exists(root=root, ref=candidate):
                    continue
                try:
                    candidate_content = _git_show_ref_path(root=root, ref=candidate, relpath=relpath)
                    return json.loads(candidate_content.lstrip("\ufeff"))
                except Exception:  # noqa: BLE001
                    continue
            attempted_s = ", ".join(attempted)
            raise RuntimeError(f"FAIL_CLOSED: unable to load branch ref {value} (attempted: {attempted_s}): branch ref missing: {branch}")
        try:
            content = _git_show_ref_path(root=root, ref=branch, relpath=relpath)
        except Exception as exc:  # noqa: BLE001
            # Fail closed for real repos: a branch ref must resolve through git.
            # Only unit-test fixtures (non-git worktrees) may fall back to a
            # filesystem path encoded by the branch ref.
            if _is_git_worktree(root):
                # If the ref doesn't exist locally (common in fresh clones), fall back to a
                # remote-tracking ref (e.g. origin/<branch>). If the ref exists locally,
                # do not mask missing-file errors by falling back elsewhere.
                raise RuntimeError(f"FAIL_CLOSED: unable to load branch ref {value}: {exc}") from exc

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
    if not active:
        raise RuntimeError("FAIL_CLOSED: documentary_truth_policy missing active_current_head_truth_source")
    return active


def active_supporting_truth_surfaces(*, root: Path) -> List[str]:
    policy_path = root / DOCUMENTARY_TRUTH_POLICY_REL
    if not policy_path.exists():
        return []
    policy = json.loads(policy_path.read_text(encoding="utf-8-sig"))
    rows = policy.get("active_supporting_truth_surfaces") if isinstance(policy.get("active_supporting_truth_surfaces"), list) else []
    return [str(item).strip() for item in rows if str(item).strip()]


def payload_documentary_only(payload: Dict[str, Any]) -> bool:
    if bool(payload.get("documentary_only")):
        return True
    if payload.get("live_authority") is False:
        return True
    if payload.get("ACTIVE_AUTHORITY") is False:
        return True
    if payload.get("LIVE_TRUTH_ALLOWED") is False:
        return True
    status = str(payload.get("status", "")).strip().upper()
    authority_level = str(payload.get("authority_level", "")).strip().upper()
    authority_role = str(payload.get("authority_role", "")).strip().upper()
    return (
        authority_level == "DOCUMENTARY_ONLY"
        or authority_role == "DOCUMENTARY_ONLY"
        or "DOCUMENTARY" in status
        or "SUPERSEDED" in status
    )


def compatibility_surface_is_non_authoritative(
    *,
    ref: str,
    active_source_ref: str,
    payload: Dict[str, Any],
    documentary_refs: Iterable[str] = (),
) -> bool:
    if payload_documentary_only(payload):
        return True
    ref_norm = str(ref).strip()
    active_norm = str(active_source_ref).strip()
    if not ref_norm or not active_norm or ref_norm == active_norm:
        return False
    documentary_set = {str(item).strip() for item in documentary_refs if str(item).strip()}
    return ref_norm in documentary_set


def truth_source_ref_is_active_or_compatibility_pointer(
    *,
    candidate_ref: str,
    active_source_ref: str,
    compatibility_payload: Dict[str, Any] | None = None,
) -> bool:
    candidate = str(candidate_ref).strip()
    active = str(active_source_ref).strip()
    if not candidate or not active:
        return False
    if candidate == active:
        return True
    if candidate == CURRENT_POINTER_REL and active != CURRENT_POINTER_REL:
        if compatibility_payload is None:
            return True
        return not payload_documentary_only(compatibility_payload)
    return False


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
    subject_dirty = bool(worktree.get("subject_git_dirty")) if "subject_git_dirty" in worktree else bool(worktree.get("git_dirty"))
    if subject_dirty:
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
    subject_dirty = bool(worktree.get("subject_git_dirty")) if "subject_git_dirty" in worktree else bool(worktree.get("git_dirty"))
    if subject_dirty:
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
    validated_subject_head = str(worktree.get("validated_subject_head_sha", "")).strip() or live_head
    publication_carrier_head = str(worktree.get("publication_carrier_head_sha", "")).strip()
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
    active_truth_ref = active_truth_source_ref(root=root)
    return {
        "schema_id": "kt.operator.settled_truth_source_receipt.v1",
        "generated_utc": generated_utc,
        "status": status,
        "branch_ref": branch_ref,
        "pinned_head_sha": validated_subject_head,
        "publication_carrier_head_sha": publication_carrier_head,
        "head_relation": str(worktree.get("head_relation", "")).strip() or "HEAD_IS_SUBJECT",
        "authoritative_current_pointer_ref": active_truth_ref,
        "current_head_truth_source": path_ref(root=root, path=live_validation_index_path),
        "derived_posture_state": str(enforcement.get("derived_state", "")).strip(),
        "worktree_dirty": bool(worktree.get("subject_git_dirty")) if "subject_git_dirty" in worktree else bool(worktree.get("git_dirty")),
        "publisher_worktree_dirty": bool(worktree.get("git_dirty")),
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
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    live_head = str(worktree.get("validated_subject_head_sha", "")).strip() or _head_from(index)
    active_truth_root = active_truth_source_ref(root=root)
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
    return ["ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "LAB", "QUARANTINED", "TOOLCHAIN_PROVING"]


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
