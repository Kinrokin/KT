from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_pr15_fl3_phase_path_normalization_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_pr15_fl3_phase_path_normalization_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-pr15-fl3-remediation"
EXECUTION_STATUS = "PASS__POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_BOUND"
OUTCOME_DEFINED = "POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_DEFINED__PHASE_EXECUTORS_STILL_USE_WEAK_ROOT_SELECTION"
OUTCOME_CLEARED = "POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_RESOLVED__TRANCHE4_CLEARED"
NEXT_MOVE_DEFINED = "EXECUTE_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_REMEDIATION"
NEXT_MOVE_CLEARED = "AUTHOR_POST_F_PR15_FL3_FULL_RED_TO_GREEN_PACKET"

AUTHORITY_PACKET_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_packet.json"
AUTHORITY_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_receipt.json"
BLOCKER_LEDGER_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json"
T03_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json"

PHASE1C_EXECUTOR_REL = "KT_PROD_CLEANROOM/tools/verification/phase1c_execute.py"
PHASE2_EXECUTOR_REL = "KT_PROD_CLEANROOM/tools/verification/phase2_execute.py"
PHASE2_WORK_ORDER_REL = "KT_PROD_CLEANROOM/kt.phase2_work_order.v1.json"
PHASE1C_TEST_REL = "KT_PROD_CLEANROOM/tests/fl3/test_phase1c_execute_smoke.py"
PHASE2_TEST_REL = "KT_PROD_CLEANROOM/tests/fl3/test_phase2_execute_dry_run_smoke.py"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip() or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
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


def _path_exists(root: Path, rel_path: str) -> bool:
    return common.resolve_path(root, rel_path).exists()


def _source_uses_weak_root_selection(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return 'if (parent / "KT_PROD_CLEANROOM").exists()' in text or 'if (parent / "KT_PROD_CLEANROOM").is_dir()' in text


def _source_uses_strong_root_selection(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return '"04_PROD_TEMPLE_V2"' in text and "fl3_suite_registry_schema.py" in text


def _resolution_classes() -> List[Dict[str, str]]:
    return [
        {
            "class_id": "NORMALIZE_PHASE_EXECUTOR_REPO_ROOT_SELECTION",
            "summary": "Phase executors must select repo root using the cleanroom source-tree sentinel, not the first parent that happens to contain a KT_PROD_CLEANROOM subtree.",
        },
        {
            "class_id": "PRESERVE_PHASE_PATH_REFERENCES_UNDER_TRUE_REPO_ROOT",
            "summary": "Required refs like phase1c_executor and law_bundle_file must resolve under the true repo root without adding duplicate KT_PROD_CLEANROOM path segments.",
        },
    ]


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    authority_packet: Dict[str, Any],
    phase1c_executor_exists: bool,
    phase2_executor_exists: bool,
    phase2_work_order_exists: bool,
    phase1c_source_uses_weak_root_selection: bool,
    phase2_source_uses_weak_root_selection: bool,
    phase1c_source_uses_strong_root_selection: bool,
    phase2_source_uses_strong_root_selection: bool,
) -> Dict[str, Dict[str, Any] | str]:
    defined = (
        phase1c_executor_exists
        and phase2_executor_exists
        and phase2_work_order_exists
        and (phase1c_source_uses_weak_root_selection or phase2_source_uses_weak_root_selection)
    )
    cleared = (
        phase1c_executor_exists
        and phase2_executor_exists
        and phase2_work_order_exists
        and phase1c_source_uses_strong_root_selection
        and phase2_source_uses_strong_root_selection
        and not phase1c_source_uses_weak_root_selection
        and not phase2_source_uses_weak_root_selection
    )
    if defined == cleared:
        raise RuntimeError("FAIL_CLOSED: tranche T04 state is neither the frozen phase-path drift condition nor the cleared condition")

    lane_outcome = OUTCOME_CLEARED if cleared else OUTCOME_DEFINED
    next_move = NEXT_MOVE_CLEARED if cleared else NEXT_MOVE_DEFINED
    tranche_state = "cleared" if cleared else "defined"
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_phase_path_normalization_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": lane_outcome,
        "claim_boundary": (
            "This packet binds tranche T04 only. It does not widen package truth, does not change truth-engine law, "
            "and does not authorize archive promotion or main replay."
        ),
        "authority_header": {
            "authoritative_branch": branch_name,
            "authoritative_branch_head": branch_head,
            "package_promotion_still_deferred": bool(
                authority_packet.get("authority_header", {}).get("package_promotion_still_deferred", False)
            ),
            "truth_engine_law_unchanged": bool(
                authority_packet.get("authority_header", {}).get("truth_engine_law_unchanged", False)
            ),
            "replay_on_main_still_deferred_until_pr15_merge": bool(
                authority_packet.get("authority_header", {}).get("replay_on_main_still_deferred_until_pr15_merge", False)
            ),
        },
        "tranche_header": {
            "tranche_id": "T04",
            "tranche_name": "phase_path_normalization",
            "ordered_blocker_position": 4,
            "tranche_state": tranche_state,
            "phase_path_class": (
                "PHASE_EXECUTORS_STILL_SELECT_REPO_ROOT_TOO_EARLY"
                if not cleared
                else "PHASE_EXECUTOR_PATHS_NORMALIZED_TO_TRUE_REPO_ROOT"
            ),
        },
        "phase_truth": {
            "phase1c_executor_rel": PHASE1C_EXECUTOR_REL,
            "phase1c_executor_exists": phase1c_executor_exists,
            "phase2_executor_rel": PHASE2_EXECUTOR_REL,
            "phase2_executor_exists": phase2_executor_exists,
            "phase2_work_order_rel": PHASE2_WORK_ORDER_REL,
            "phase2_work_order_exists": phase2_work_order_exists,
        },
        "normalization_evidence": {
            "phase1c_source_uses_weak_root_selection": phase1c_source_uses_weak_root_selection,
            "phase2_source_uses_weak_root_selection": phase2_source_uses_weak_root_selection,
            "phase1c_source_uses_strong_root_selection": phase1c_source_uses_strong_root_selection,
            "phase2_source_uses_strong_root_selection": phase2_source_uses_strong_root_selection,
        },
        "precedence_rule": {
            "winning_source": "cleanroom_source_tree_sentinel",
            "winning_rule": (
                "Phase executor repo-root selection must use the same cleanroom source-tree sentinel as the already-normalized helper surfaces, "
                "so required refs resolve under the true repo root instead of under a nested cleanroom subtree."
            ),
            "resolution_decision_rule": (
                "Prefer normalizing phase executor root selection over moving phase executor files or widening path references."
            ),
        },
        "allowed_resolution_classes": _resolution_classes(),
        "live_resolution_read": {
            "genuine_missing_phase_executor": False,
            "phase_root_selection_drift_present": not cleared,
            "recommended_resolution_class": (
                "NORMALIZE_PHASE_EXECUTOR_REPO_ROOT_SELECTION"
                if not cleared
                else "ADVANCE_TO_T05_FULL_RED_TO_GREEN"
            ),
            "recommended_resolution_summary": (
                "Phase executors still use weak root selection that can resolve under KT_PROD_CLEANROOM/KT_PROD_CLEANROOM and duplicate canonical paths."
                if not cleared
                else "Phase executor root selection is normalized and tranche T04 is cleared."
            ),
        },
        "exact_scope": {
            "executor_scope": [
                PHASE1C_EXECUTOR_REL,
                PHASE2_EXECUTOR_REL,
            ],
            "test_scope": [
                PHASE1C_TEST_REL,
                PHASE2_TEST_REL,
            ],
            "reference_scope": [
                PHASE2_WORK_ORDER_REL,
                "KT_PROD_CLEANROOM/tools/verification/fl3_validators.py",
            ],
        },
        "do_not_widen_boundaries": authority_packet.get("do_not_widen_boundaries", []),
        "success_condition": {
            "phase_executor_paths_resolve_under_true_repo_root": True,
            "blocker_ledger_advances_to_tranche_5": True,
            "package_truth_unchanged": True,
            "truth_engine_law_unchanged": True,
        },
        "source_refs": common.output_ref_dict(
            remediation_authority_packet=common.resolve_path(repo_root(), AUTHORITY_PACKET_PATH),
            remediation_authority_receipt=common.resolve_path(repo_root(), AUTHORITY_RECEIPT_PATH),
            remediation_blocker_ledger=common.resolve_path(repo_root(), BLOCKER_LEDGER_PATH),
            tranche3_receipt=common.resolve_path(repo_root(), T03_RECEIPT_PATH),
            phase1c_executor=common.resolve_path(repo_root(), PHASE1C_EXECUTOR_REL),
            phase2_executor=common.resolve_path(repo_root(), PHASE2_EXECUTOR_REL),
            phase2_work_order=common.resolve_path(repo_root(), PHASE2_WORK_ORDER_REL),
        ),
        "next_lawful_move": next_move,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_phase_path_normalization_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": lane_outcome,
        "tranche_id": "T04",
        "tranche_state": tranche_state,
        "phase1c_source_uses_weak_root_selection": phase1c_source_uses_weak_root_selection,
        "phase2_source_uses_weak_root_selection": phase2_source_uses_weak_root_selection,
        "next_lawful_move": next_move,
    }
    report = common.report_lines(
        "Cohort0 Post-F PR15 FL3 Phase Path Normalization Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{lane_outcome}`",
            "- Tranche: `T04 phase_path_normalization`",
            f"- Tranche state: `{tranche_state}`",
            f"- Phase1C source still weak-roots: `{phase1c_source_uses_weak_root_selection}`",
            f"- Phase2 source still weak-roots: `{phase2_source_uses_weak_root_selection}`",
            f"- Recommended resolution class: `{packet['live_resolution_read']['recommended_resolution_class']}`",
            f"- Next lawful move: `{next_move}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    authority_receipt_path: Path,
    blocker_ledger_path: Path,
    tranche3_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: tranche T04 must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: tranche T04 requires a clean tracked worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="PR15 FL3 remediation authority packet")
    authority_receipt = common.load_json_required(root, authority_receipt_path, label="PR15 FL3 remediation authority receipt")
    blocker_ledger = common.load_json_required(root, blocker_ledger_path, label="PR15 FL3 remediation blocker ledger")
    tranche3_receipt = common.load_json_required(root, tranche3_receipt_path, label="tranche T03 receipt")
    common.ensure_pass(authority_packet, label="PR15 FL3 remediation authority packet")
    common.ensure_pass(authority_receipt, label="PR15 FL3 remediation authority receipt")
    common.ensure_pass(blocker_ledger, label="PR15 FL3 remediation blocker ledger")
    common.ensure_pass(tranche3_receipt, label="tranche T03 receipt")

    if str(tranche3_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_PACKET":
        raise RuntimeError("FAIL_CLOSED: tranche T03 receipt no longer authorizes tranche T04 packet")

    blockers = blocker_ledger.get("blockers")
    if not isinstance(blockers, list) or len(blockers) < 4 or blockers[3].get("tranche_id") != "T04":
        raise RuntimeError("FAIL_CLOSED: blocker ledger no longer binds tranche T04 as the fourth remediation blocker")

    phase1c_path = common.resolve_path(root, PHASE1C_EXECUTOR_REL)
    phase2_path = common.resolve_path(root, PHASE2_EXECUTOR_REL)
    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        authority_packet=authority_packet,
        phase1c_executor_exists=phase1c_path.exists(),
        phase2_executor_exists=phase2_path.exists(),
        phase2_work_order_exists=_path_exists(root, PHASE2_WORK_ORDER_REL),
        phase1c_source_uses_weak_root_selection=_source_uses_weak_root_selection(phase1c_path),
        phase2_source_uses_weak_root_selection=_source_uses_weak_root_selection(phase2_path),
        phase1c_source_uses_strong_root_selection=_source_uses_strong_root_selection(phase1c_path),
        phase2_source_uses_strong_root_selection=_source_uses_strong_root_selection(phase2_path),
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
        "lane_outcome": str(outputs["packet"]["lane_outcome"]),
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": str(outputs["receipt"]["next_lawful_move"]),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind tranche T04 for PR15 FL3 phase-path normalization.")
    parser.add_argument("--authority-packet", default=AUTHORITY_PACKET_PATH)
    parser.add_argument("--authority-receipt", default=AUTHORITY_RECEIPT_PATH)
    parser.add_argument("--blocker-ledger", default=BLOCKER_LEDGER_PATH)
    parser.add_argument("--tranche3-receipt", default=T03_RECEIPT_PATH)
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        blocker_ledger_path=common.resolve_path(root, args.blocker_ledger),
        tranche3_receipt_path=common.resolve_path(root, args.tranche3_receipt),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
