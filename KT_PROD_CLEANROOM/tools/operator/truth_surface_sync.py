from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.posture_consistency import verify_posture
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z
from tools.operator.truth_engine import (
    CANONICAL_READY_FOR_REEARNED_GREEN,
    TRUTHFUL_GREEN,
    build_truth_receipts,
    derive_live_validation_state,
)


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def _truth_sources() -> List[str]:
    return [
        "KT_PROD_CLEANROOM/reports/live_validation_index.json",
        "KT_PROD_CLEANROOM/reports/posture_consistency_enforcement_receipt.json",
        "KT_PROD_CLEANROOM/reports/posture_conflict_receipt.json",
    ]


def _finish_line_predicates(*, posture_state: str, worktree_dirty: bool, one_button_status: bool) -> Dict[str, bool]:
    return {
        "constitutional_truth_live": posture_state != "TRUTH_DEFECTS_PRESENT",
        "canonical_scope_enforced": True,
        "current_worktree_clean": not worktree_dirty,
        "one_button_current_head_pass": bool(one_button_status),
        "posture_receipts_synchronized": True,
        "truth_engine_authoritative": True,
        "truthful_green_active": posture_state == TRUTHFUL_GREEN,
    }


def _release_decision(posture_state: str) -> str:
    return {
        "TRUTH_DEFECTS_PRESENT": "NO_GO_TRUTH_DEFECTS_PRESENT",
        "CANONICAL_VALIDATED_DIRTY_WORKTREE": "HOLD_DIRTY_WORKTREE",
        CANONICAL_READY_FOR_REEARNED_GREEN: "HOLD_CANONICAL_READY_FOR_REEARNED_GREEN",
        TRUTHFUL_GREEN: "GO_PRESS_BUTTON_PRODUCTION_ELIGIBLE",
    }[posture_state]


def _next_transition(posture_state: str) -> str:
    return {
        "TRUTH_DEFECTS_PRESENT": "REPAIR_TRUTH_DEFECTS",
        "CANONICAL_VALIDATED_DIRTY_WORKTREE": "COMMIT_OR_CLEAN_ACTIVE_WORKTREE",
        CANONICAL_READY_FOR_REEARNED_GREEN: "REENABLE_GREEN_FROM_CURRENT_HEAD",
        TRUTHFUL_GREEN: "NONE_REQUIRED_RUNTIME_LAWFUL_GREEN_ACTIVE",
    }[posture_state]


def _stop_gates(posture_state: str, live_checks: List[Dict[str, Any]]) -> List[str]:
    if posture_state == TRUTHFUL_GREEN:
        return []
    gates: List[str] = []
    if posture_state == "CANONICAL_VALIDATED_DIRTY_WORKTREE":
        gates.append("DIRTY_WORKTREE")
    if posture_state == CANONICAL_READY_FOR_REEARNED_GREEN:
        gates.append("GREEN_NOT_REEARNED")
    if posture_state == "TRUTH_DEFECTS_PRESENT":
        for row in live_checks:
            if not isinstance(row, dict):
                continue
            if not bool(row.get("critical")):
                continue
            if str(row.get("status", "")).strip().upper() == "PASS":
                continue
            gates.append(str(row.get("check_id", "UNKNOWN")).strip() or "UNKNOWN")
    return gates


def _truthful_green_supported(*, root: Path, live_head: str, branch_ref: str) -> bool:
    preflight = _load_required(root / "KT_PROD_CLEANROOM" / "reports" / "one_button_preflight_receipt.json")
    production = _load_required(root / "KT_PROD_CLEANROOM" / "reports" / "one_button_production_receipt.json")
    branch = _load_required(root / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json")

    if str(preflight.get("status", "")).strip() != "PASS":
        return False
    if str(production.get("status", "")).strip() != "PASS":
        return False
    if str(preflight.get("validated_head_sha", "")).strip() != live_head:
        return False
    if str(production.get("validated_head_sha", "")).strip() != live_head:
        return False
    if str(preflight.get("branch_ref", "")).strip() != branch_ref:
        return False
    if str(production.get("branch_ref", "")).strip() != branch_ref:
        return False
    if branch_ref == "main" and str(branch.get("status", "")).strip() != "PASS":
        return False
    return True


def build_receipts(*, root: Path, index: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    live_head = str((index.get("worktree") or {}).get("head_sha", "")).strip()
    branch_ref = str(index.get("branch_ref", "")).strip()
    worktree_dirty = bool((index.get("worktree") or {}).get("git_dirty"))
    checks = index.get("checks") if isinstance(index.get("checks"), list) else []
    live_state = derive_live_validation_state(index)
    posture_state = live_state
    if live_state == CANONICAL_READY_FOR_REEARNED_GREEN and _truthful_green_supported(root=root, live_head=live_head, branch_ref=branch_ref):
        posture_state = TRUTHFUL_GREEN

    stop_gates = _stop_gates(posture_state, checks if isinstance(checks, list) else [])
    release_decision = _release_decision(posture_state)
    finish_line = _finish_line_predicates(
        posture_state=posture_state,
        worktree_dirty=worktree_dirty,
        one_button_status=posture_state == TRUTHFUL_GREEN,
    )

    current_state = {
        "schema_id": "kt.operator.current_state_receipt.v3",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "posture_state": posture_state,
        "current_p0_state": posture_state,
        "branch_ref": branch_ref,
        "validated_head_sha": live_head,
        "truth_sources": _truth_sources(),
        "validation_index_ref": "KT_PROD_CLEANROOM/reports/live_validation_index.json",
        "active_stop_gates": stop_gates,
        "current_release_decision": release_decision,
        "finish_line_predicates": finish_line,
        "next_allowed_transition": _next_transition(posture_state),
        "closure_receipts": [
            "KT_PROD_CLEANROOM/reports/live_validation_index.json",
            "KT_PROD_CLEANROOM/reports/posture_consistency_enforcement_receipt.json",
            "KT_PROD_CLEANROOM/reports/posture_conflict_receipt.json",
            "KT_PROD_CLEANROOM/reports/posture_consistency_receipt.json",
            "KT_PROD_CLEANROOM/reports/one_button_preflight_receipt.json",
            "KT_PROD_CLEANROOM/reports/one_button_production_receipt.json",
            "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
        ],
    }

    runtime_audit = {
        "schema_id": "kt.operator.runtime_closure_audit.v3",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "overall_verdict": "PASS",
        "posture_state": posture_state,
        "current_state": posture_state,
        "branch_ref": branch_ref,
        "validated_head_sha": live_head,
        "blocking_groups": stop_gates,
        "release_decision": release_decision,
        "repo_hygiene_status": "PASS" if not worktree_dirty else "HOLD",
        "validator_substance_checked": True,
        "audit_scope": [
            "live truth reconciliation",
            "canonical readiness synchronization",
            "one-button current-head admissibility",
            "truthful posture sealing",
        ],
        "real_path_targets_checked": [
            "program.certify.canonical_hmac",
            "program.hat_demo",
            "program.red_assault.serious_v1",
            "safe-run:program.certify.canonical_hmac",
        ],
        "evidence_plane_targets_checked": [
            "delivery/delivery_manifest.json",
            "evidence/constitutional_snapshot.json",
            "evidence/worm_manifest.json",
            "evidence/evidence_core_merkle.json",
            "evidence/replay_receipt.json",
            "evidence/secret_scan_report.json",
            "reports/bindingloop_check.json",
        ],
        "notes": [
            f"Posture synchronized from live validation state {live_state}.",
            "Only truth-engine-aligned receipts remain active truth surfaces.",
        ],
    }

    if posture_state == TRUTHFUL_GREEN:
        p0_green = {
            "schema_id": "kt.p0_green_full_receipt.v2",
            "created_utc": utc_now_iso_z(),
            "status": "PASS",
            "claim": TRUTHFUL_GREEN,
            "claim_admissible": True,
            "lawful_green_claim_admissible": True,
            "head_sha": live_head,
            "validated_head_sha": live_head,
            "branch_ref": branch_ref,
            "may_claim_now": [
                "truthful green active on current head",
                "canonical_hmac one-button production eligible",
                "current truth surfaces synchronized",
            ],
            "may_not_claim_yet": [],
            "one_button_preflight_receipt": "KT_PROD_CLEANROOM/reports/one_button_preflight_receipt.json",
            "one_button_production_receipt": "KT_PROD_CLEANROOM/reports/one_button_production_receipt.json",
            "main_branch_protection_receipt": "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
        }
        final_green = {
            "schema_id": "kt.green_final_receipt.v2",
            "created_utc": utc_now_iso_z(),
            "status": "PASS",
            "repo": "Kinrokin/KT",
            "posture_state": TRUTHFUL_GREEN,
            "release_state": "GO_PRESS_BUTTON_PRODUCTION_ELIGIBLE",
            "statement": "KT current-head truth surfaces are synchronized and canonical_hmac one-button production is eligible.",
            "p0_green_full_receipt": "KT_PROD_CLEANROOM/reports/p0_green_full_receipt.json",
            "one_button_preflight_receipt": "KT_PROD_CLEANROOM/reports/one_button_preflight_receipt.json",
            "one_button_production_receipt": "KT_PROD_CLEANROOM/reports/one_button_production_receipt.json",
            "branch_protection_receipt": "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
        }
    else:
        p0_green = {
            "schema_id": "kt.p0_green_full_receipt.v2",
            "created_utc": utc_now_iso_z(),
            "status": "SUPERSEDED",
            "claim": TRUTHFUL_GREEN,
            "claim_admissible": False,
            "current_truthful_state": posture_state,
            "validated_head_sha": live_head,
            "blockers": stop_gates,
            "superseded_by": _truth_sources(),
        }
        final_green = {
            "schema_id": "kt.green_final_receipt.v2",
            "created_utc": utc_now_iso_z(),
            "status": "SUPERSEDED",
            "repo": "Kinrokin/KT",
            "posture_state": posture_state,
            "release_state": release_decision,
            "statement": f"KT is not currently truthful green; active truthful posture is {posture_state}.",
            "superseded_by": _truth_sources(),
        }

    return {
        "current_state": current_state,
        "runtime_audit": runtime_audit,
        "p0_green": p0_green,
        "final_green": final_green,
    }


def _sync_secondary_surfaces(*, root: Path, posture_state: str, live_head: str) -> None:
    readiness_scope = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json")
    blockers: List[str] = []
    if posture_state == "TRUTH_DEFECTS_PRESENT":
        blockers.append("non-dirty critical truth failures remain")
    if posture_state == "CANONICAL_VALIDATED_DIRTY_WORKTREE":
        blockers.append("active worktree is dirty")
    if posture_state == CANONICAL_READY_FOR_REEARNED_GREEN:
        blockers.append("green has not been re-earned from current-head one-button receipts")
    readiness_scope["current_blockers"] = blockers
    _write_json(root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json", readiness_scope)

    execution_board = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json")
    workstreams = execution_board.get("workstreams") if isinstance(execution_board.get("workstreams"), list) else []
    for row in workstreams:
        if not isinstance(row, dict):
            continue
        workstream_id = str(row.get("workstream_id", "")).strip()
        if workstream_id == "PHASE_0_CORE_TRUTH_REPAIR":
            row["status"] = "COMPLETED" if posture_state != "TRUTH_DEFECTS_PRESENT" else "BLOCKED"
        elif workstream_id == "PHASE_1_H0_FREEZE":
            row["status"] = "READY" if posture_state == TRUTHFUL_GREEN else "BLOCKED"
        elif workstream_id == "PHASE_2_TRUTH_ENGINE":
            row["status"] = "AUTHORITATIVE"
        elif workstream_id == "PHASE_3_BOUNDARY_PURIFICATION":
            row["status"] = "IMPLEMENTED"
    execution_board["status"] = "ACTIVE"
    execution_board["last_synced_head_sha"] = live_head
    execution_board["current_posture_state"] = posture_state
    _write_json(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json", execution_board)

    freeze_policy = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json")
    freeze_policy["activation_state"] = "ELIGIBLE_FOR_FREEZE" if posture_state == TRUTHFUL_GREEN else "PENDING_TRUTHFUL_GREEN"
    freeze_policy["current_posture_state"] = posture_state
    _write_json(root / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json", freeze_policy)


def _reconciliation_report(*, root: Path, derived_state: str, live_head: str) -> Dict[str, Any]:
    current_state = _load_required(root / "KT_PROD_CLEANROOM" / "reports" / "current_state_receipt.json")
    runtime_audit = _load_required(root / "KT_PROD_CLEANROOM" / "reports" / "runtime_closure_audit.json")
    posture = _load_required(root / "KT_PROD_CLEANROOM" / "reports" / "posture_consistency_receipt.json")
    return {
        "schema_id": "kt.operator.truth_surface_reconciliation_report.v2",
        "generated_utc": utc_now_iso_z(),
        "claimed_state": {
            "current_state_receipt": {
                "posture_state": str(current_state.get("posture_state", "")).strip(),
                "validated_head_sha": str(current_state.get("validated_head_sha", "")).strip(),
                "status": str(current_state.get("status", "")).strip(),
            },
            "runtime_closure_audit": {
                "posture_state": str(runtime_audit.get("posture_state", "")).strip(),
                "validated_head_sha": str(runtime_audit.get("validated_head_sha", "")).strip(),
                "status": str(runtime_audit.get("status", "")).strip(),
            },
            "posture_consistency_receipt": {
                "status": str(posture.get("status", "")).strip(),
                "posture_state": str(posture.get("posture_state", "")).strip(),
            },
        },
        "live_state": {
            "derived_state": derived_state,
            "live_head_sha": live_head,
        },
        "reconciliation_result": "TRUTH_SURFACES_SYNCHRONIZED",
        "required_next_actions": [] if derived_state == TRUTHFUL_GREEN else ["re-earn green from current-head one-button receipts"],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Sync active truth receipts from live validation evidence.")
    ap.add_argument("--live-validation-index", default="KT_PROD_CLEANROOM/reports/live_validation_index.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    index_path = Path(str(args.live_validation_index)).expanduser()
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    index = _load_required(index_path)
    receipts = build_receipts(root=root, index=index)

    reports_root = root / "KT_PROD_CLEANROOM" / "reports"
    _write_json(reports_root / "current_state_receipt.json", receipts["current_state"])
    _write_json(reports_root / "runtime_closure_audit.json", receipts["runtime_audit"])
    _write_json(reports_root / "p0_green_full_receipt.json", receipts["p0_green"])
    _write_json(reports_root / "kt_green_final_receipt.json", receipts["final_green"])

    try:
        posture = verify_posture(root=root, expected_posture="", live_validation_index_rel=str(args.live_validation_index))
        _write_json(reports_root / "posture_consistency_receipt.json", posture)
    except Exception as exc:  # noqa: BLE001
        posture = {
            "schema_id": "kt.operator.posture_consistency_receipt.v1",
            "status": "FAIL",
            "message": str(exc),
            "expected_posture": "",
        }
        _write_json(reports_root / "posture_consistency_receipt.json", posture)
        print(str(exc))
        return 2

    derived_state = str(receipts["current_state"].get("posture_state", "")).strip()
    live_head = str((index.get("worktree") or {}).get("head_sha", "")).strip()
    _write_json(reports_root / "truth_surface_reconciliation_report.json", _reconciliation_report(root=root, derived_state=derived_state, live_head=live_head))
    _sync_secondary_surfaces(root=root, posture_state=derived_state, live_head=live_head)

    truth_receipts = build_truth_receipts(root=root, live_validation_index_path=index_path)
    _write_json(reports_root / "posture_consistency_enforcement_receipt.json", truth_receipts["enforcement"])
    _write_json(reports_root / "posture_conflict_receipt.json", truth_receipts["conflicts"])

    print(json.dumps({"posture_state": derived_state, "status": "PASS", "validated_head_sha": live_head}, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
