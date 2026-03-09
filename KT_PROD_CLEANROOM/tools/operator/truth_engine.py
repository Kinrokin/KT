from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z


TRUTH_DEFECTS_PRESENT = "TRUTH_DEFECTS_PRESENT"
CANONICAL_VALIDATED_DIRTY_WORKTREE = "CANONICAL_VALIDATED_DIRTY_WORKTREE"
CANONICAL_READY_FOR_REEARNED_GREEN = "CANONICAL_READY_FOR_REEARNED_GREEN"
TRUTHFUL_GREEN = "TRUTHFUL_GREEN"
DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"

GREEN_CLAIMS = {
    "P0_GREEN_FULL_CANDIDATE_ON_BRANCH",
    "P0_GREEN_FULL_BRANCH_CONFIRMED_PENDING_MAIN_PROMOTION",
    "P0_GREEN_FULL_ENGINEERING_COMPLETE_PENDING_PLATFORM_ENFORCEMENT",
    "P0_GREEN_FULL_MAINLINE",
    TRUTHFUL_GREEN,
}

STATE_RANK = {
    TRUTH_DEFECTS_PRESENT: 0,
    CANONICAL_VALIDATED_DIRTY_WORKTREE: 1,
    CANONICAL_READY_FOR_REEARNED_GREEN: 2,
    TRUTHFUL_GREEN: 3,
}


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _report_path(root: Path, report_root_rel: str, rel: str) -> Path:
    return (root / report_root_rel / rel).resolve()


def _critical_failures(index: Dict[str, Any]) -> List[Dict[str, Any]]:
    checks = index.get("checks") if isinstance(index.get("checks"), list) else []
    out: List[Dict[str, Any]] = []
    for row in checks:
        if not isinstance(row, dict):
            continue
        if not bool(row.get("critical")):
            continue
        status = str(row.get("status", "")).strip().upper()
        if status in {"PASS", "SKIP"}:
            continue
        out.append(row)
    return out


def normalize_claim_state(value: str) -> str:
    claim = str(value or "").strip()
    if claim in GREEN_CLAIMS:
        return TRUTHFUL_GREEN
    return claim


def state_rank(value: str) -> int:
    return int(STATE_RANK.get(normalize_claim_state(value), -1))


def derive_live_validation_state(index: Dict[str, Any]) -> str:
    failures = _critical_failures(index)
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    worktree_dirty = bool(worktree.get("git_dirty"))
    non_dirty_failures = [row for row in failures if not bool(row.get("dirty_sensitive"))]
    if non_dirty_failures:
        return TRUTH_DEFECTS_PRESENT
    if worktree_dirty:
        return CANONICAL_VALIDATED_DIRTY_WORKTREE
    return CANONICAL_READY_FOR_REEARNED_GREEN


def derive_authoritative_state(
    *,
    index: Dict[str, Any],
    current_state: Dict[str, Any],
    runtime_audit: Dict[str, Any],
    posture_consistency: Dict[str, Any],
) -> str:
    live_state = derive_live_validation_state(index)
    if live_state != CANONICAL_READY_FOR_REEARNED_GREEN:
        return live_state
    posture_ok = str(posture_consistency.get("status", "")).strip().upper() == "PASS"
    current_claim = normalize_claim_state(str(current_state.get("posture_state") or current_state.get("current_p0_state") or ""))
    audit_claim = normalize_claim_state(str(runtime_audit.get("posture_state") or runtime_audit.get("current_state") or ""))
    if posture_ok and current_claim == TRUTHFUL_GREEN and audit_claim == TRUTHFUL_GREEN:
        return TRUTHFUL_GREEN
    return CANONICAL_READY_FOR_REEARNED_GREEN


def _build_conflicts(
    *,
    index: Dict[str, Any],
    current_state: Dict[str, Any],
    runtime_audit: Dict[str, Any],
    posture_consistency: Dict[str, Any],
    derived_state: str,
) -> List[Dict[str, Any]]:
    conflicts: List[Dict[str, Any]] = []
    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    live_state = derive_live_validation_state(index)
    current_claim_raw = str(current_state.get("posture_state") or current_state.get("current_p0_state") or "").strip()
    audit_claim_raw = str(runtime_audit.get("posture_state") or runtime_audit.get("current_state") or "").strip()
    current_claim = normalize_claim_state(current_claim_raw)
    audit_claim = normalize_claim_state(audit_claim_raw)
    current_head = str(current_state.get("validated_head_sha", "")).strip()
    audit_head = str(runtime_audit.get("validated_head_sha", "")).strip()
    live_head = str(worktree.get("head_sha", "")).strip()
    live_branch = str(index.get("branch_ref", "")).strip()
    current_branch = str(current_state.get("branch_ref") or current_state.get("branch") or "").strip()
    audit_branch = str(runtime_audit.get("branch_ref") or runtime_audit.get("branch") or "").strip()

    for row in _critical_failures(index):
        if bool(row.get("dirty_sensitive")) and live_state != TRUTH_DEFECTS_PRESENT:
            continue
        conflicts.append(
            {
                "conflict_id": f"LIVE_VALIDATION_FAIL::{row.get('check_id')}",
                "severity": 9 if not bool(row.get("dirty_sensitive")) else 5,
                "message": str(row.get("summary", "critical live validation failed")).strip(),
                "dirty_sensitive": bool(row.get("dirty_sensitive")),
            }
        )

    if bool(worktree.get("git_dirty")):
        stronger_than_dirty = state_rank(current_claim) > state_rank(CANONICAL_VALIDATED_DIRTY_WORKTREE) or state_rank(audit_claim) > state_rank(
            CANONICAL_VALIDATED_DIRTY_WORKTREE
        )
        if stronger_than_dirty:
            conflicts.append(
                {
                    "conflict_id": "DIRTY_WORKTREE_BLOCKS_STRONGER_POSTURE",
                    "severity": 7,
                    "message": "active worktree is dirty; current-repo posture cannot exceed CANONICAL_VALIDATED_DIRTY_WORKTREE",
                    "dirty_sensitive": True,
                }
            )

    if current_head and live_head and current_head != live_head:
        conflicts.append(
            {
                "conflict_id": "CURRENT_STATE_HEAD_STALE",
                "severity": 8,
                "message": f"current_state_receipt validated_head_sha={current_head} differs from live head={live_head}",
                "dirty_sensitive": False,
            }
        )
    if audit_head and live_head and audit_head != live_head:
        conflicts.append(
            {
                "conflict_id": "RUNTIME_AUDIT_HEAD_STALE",
                "severity": 8,
                "message": f"runtime_closure_audit validated_head_sha={audit_head} differs from live head={live_head}",
                "dirty_sensitive": False,
            }
        )
    if current_branch and live_branch and current_branch != live_branch:
        conflicts.append(
            {
                "conflict_id": "CURRENT_STATE_BRANCH_STALE",
                "severity": 7,
                "message": f"current_state_receipt branch_ref={current_branch} differs from live branch={live_branch}",
                "dirty_sensitive": False,
            }
        )
    if audit_branch and live_branch and audit_branch != live_branch:
        conflicts.append(
            {
                "conflict_id": "RUNTIME_AUDIT_BRANCH_STALE",
                "severity": 7,
                "message": f"runtime_closure_audit branch_ref={audit_branch} differs from live branch={live_branch}",
                "dirty_sensitive": False,
            }
        )
    if current_claim and audit_claim and current_claim != audit_claim:
        conflicts.append(
            {
                "conflict_id": "POSTURE_RECEIPTS_DISAGREE",
                "severity": 9,
                "message": f"current_state_receipt posture={current_claim_raw} and runtime_closure_audit posture={audit_claim_raw} disagree",
                "dirty_sensitive": False,
            }
        )

    if current_claim and state_rank(current_claim) > state_rank(derived_state):
        conflicts.append(
            {
                "conflict_id": "CURRENT_STATE_OVERCLAIM",
                "severity": 9,
                "message": f"current_state_receipt claims {current_claim_raw} while derived_state={derived_state}",
                "dirty_sensitive": False,
            }
        )
    if audit_claim and state_rank(audit_claim) > state_rank(derived_state):
        conflicts.append(
            {
                "conflict_id": "RUNTIME_AUDIT_OVERCLAIM",
                "severity": 9,
                "message": f"runtime_closure_audit claims {audit_claim_raw} while derived_state={derived_state}",
                "dirty_sensitive": False,
            }
        )
    if str(posture_consistency.get("status", "")).strip().upper() != "PASS":
        conflicts.append(
            {
                "conflict_id": "POSTURE_CONSISTENCY_FAIL",
                "severity": 8,
                "message": str(posture_consistency.get("message", "posture_consistency_receipt is not PASS")).strip(),
                "dirty_sensitive": False,
            }
        )

    return conflicts


def build_truth_receipts(*, root: Path, live_validation_index_path: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Dict[str, Any]]:
    index = _load_required(live_validation_index_path)
    current_state = _load_required(_report_path(root, report_root_rel, "current_state_receipt.json"))
    runtime_audit = _load_required(_report_path(root, report_root_rel, "runtime_closure_audit.json"))
    posture_consistency = _load_required(_report_path(root, report_root_rel, "posture_consistency_receipt.json"))
    posture_contract = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "posture_contract.json")
    truth_contract = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "truth_engine_contract.json")

    derived_state = derive_authoritative_state(
        index=index,
        current_state=current_state,
        runtime_audit=runtime_audit,
        posture_consistency=posture_consistency,
    )
    conflicts = _build_conflicts(
        index=index,
        current_state=current_state,
        runtime_audit=runtime_audit,
        posture_consistency=posture_consistency,
        derived_state=derived_state,
    )
    conflict_status = "PASS" if not conflicts else "FAIL"

    worktree = index.get("worktree") if isinstance(index.get("worktree"), dict) else {}
    current_claim = str(current_state.get("posture_state") or current_state.get("current_p0_state") or "").strip()
    audit_claim = str(runtime_audit.get("posture_state") or runtime_audit.get("current_state") or "").strip()
    live_state = derive_live_validation_state(index)

    enforcement = {
        "schema_id": "kt.operator.posture_consistency_enforcement_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": conflict_status,
        "derived_state": derived_state,
        "live_validation_state": live_state,
        "claimed_state_current_receipt": current_claim,
        "claimed_state_runtime_audit": audit_claim,
        "worktree_dirty": bool(worktree.get("git_dirty")),
        "live_head_sha": str(worktree.get("head_sha", "")).strip(),
        "validation_index_ref": str(live_validation_index_path.relative_to(root).as_posix()),
        "posture_contract_id": str(posture_contract.get("contract_id", "")).strip(),
        "truth_engine_contract_id": str(truth_contract.get("contract_id", "")).strip(),
        "critical_failure_count": len(_critical_failures(index)),
        "non_dirty_critical_failure_count": len([row for row in _critical_failures(index) if not bool(row.get("dirty_sensitive"))]),
        "conflict_count": len(conflicts),
    }

    conflict_receipt = {
        "schema_id": "kt.operator.posture_conflict_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": conflict_status,
        "derived_state": derived_state,
        "live_validation_state": live_state,
        "claimed_state_current_receipt": current_claim,
        "claimed_state_runtime_audit": audit_claim,
        "conflicts": conflicts,
    }
    return {"enforcement": enforcement, "conflicts": conflict_receipt}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Derive truthful posture from live validation evidence.")
    ap.add_argument("--live-validation-index", default=f"{DEFAULT_REPORT_ROOT_REL}/live_validation_index.json")
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--out-dir", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    index_path = Path(str(args.live_validation_index)).expanduser()
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    out_dir_arg = str(args.out_dir).strip() or str(args.report_root).strip()
    out_dir = Path(out_dir_arg).expanduser()
    if not out_dir.is_absolute():
        out_dir = (root / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    receipts = build_truth_receipts(root=root, live_validation_index_path=index_path, report_root_rel=str(args.report_root))
    (out_dir / "posture_consistency_enforcement_receipt.json").write_text(
        json.dumps(receipts["enforcement"], indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "posture_conflict_receipt.json").write_text(
        json.dumps(receipts["conflicts"], indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(receipts["enforcement"], sort_keys=True, ensure_ascii=True))
    return 0 if receipts["enforcement"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
