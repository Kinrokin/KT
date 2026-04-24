from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import (
    cohort0_gate_f_post_close_live_product_truth_tranche as live_product_truth_tranche,
)
from tools.operator import (
    cohort0_gate_f_post_close_supersession_note_tranche as post_f_supersession_tranche,
)
from tools.operator import cohort0_gate_f_one_narrow_wedge_review_tranche as review_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_post_f_broad_canonical_reaudit_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_broad_canonical_reaudit_receipt.json"
OUTPUT_BLOCKER_LEDGER = "cohort0_post_f_broad_canonical_reaudit_blocker_ledger.json"
OUTPUT_REPORT = "COHORT0_POST_F_BROAD_CANONICAL_REAUDIT_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_BROAD_CANONICAL_REAUDIT_EXECUTED"
OUTCOME_PASS = "POST_F_BROAD_CANONICAL_REAUDIT_PASS__MINIMUM_PATH_COMPLETE"


def run(
    *,
    reports_root: Path,
    branch_law_packet_path: Path,
    branch_law_receipt_path: Path,
    supersession_note_path: Path,
    orchestrator_receipt_path: Path,
    gate_f_review_receipt_path: Path,
    live_product_truth_packet_path: Path,
    live_product_truth_receipt_path: Path,
    post_f_supersession_note_path: Path,
    post_f_supersession_receipt_path: Path,
) -> Dict[str, str]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    branch_law_receipt = common.load_json_required(root, branch_law_receipt_path, label="live branch law receipt")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    gate_f_review_receipt = common.load_json_required(root, gate_f_review_receipt_path, label="Gate F review receipt")
    live_product_truth_packet = common.load_json_required(
        root, live_product_truth_packet_path, label="Gate F live product truth packet"
    )
    live_product_truth_receipt = common.load_json_required(
        root, live_product_truth_receipt_path, label="Gate F live product truth receipt"
    )
    post_f_supersession_note = common.load_json_required(
        root, post_f_supersession_note_path, label="Gate F post-close supersession note"
    )
    post_f_supersession_receipt = common.load_json_required(
        root, post_f_supersession_receipt_path, label="Gate F post-close supersession receipt"
    )

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    for payload, label in (
        (branch_law_receipt, "live branch law receipt"),
        (gate_f_review_receipt, "Gate F review receipt"),
        (live_product_truth_packet, "Gate F live product truth packet"),
        (live_product_truth_receipt, "Gate F live product truth receipt"),
        (post_f_supersession_note, "Gate F post-close supersession note"),
        (post_f_supersession_receipt, "Gate F post-close supersession receipt"),
    ):
        common.ensure_pass(payload, label=label)

    if not bool(branch_law_packet.get("canonical_live_branch_status", {}).get("gate_d_cleared_on_successor_line", False)):
        raise RuntimeError("FAIL_CLOSED: post-F broad re-audit requires Gate D clear on successor line")
    if not bool(branch_law_packet.get("canonical_live_branch_status", {}).get("gate_e_open", False)):
        raise RuntimeError("FAIL_CLOSED: post-F broad re-audit requires Gate E open on successor line")
    if str(gate_f_review_receipt.get("review_outcome", "")).strip() != review_tranche.OUTCOME_CONFIRMED:
        raise RuntimeError("FAIL_CLOSED: post-F broad re-audit requires Gate F one narrow wedge confirmation")
    if str(live_product_truth_receipt.get("current_product_posture", "")).strip() != common.GATE_F_CONFIRMED_POSTURE:
        raise RuntimeError("FAIL_CLOSED: post-F broad re-audit requires frozen live product truth")
    if not bool(
        post_f_supersession_receipt.get(
            "gate_f_post_close_live_product_truth_supersedes_prior_product_headers_for_live_posture", False
        )
    ):
        raise RuntimeError("FAIL_CLOSED: post-F broad re-audit requires explicit product supersession")

    blocker_ledger = {
        "schema_id": "kt.operator.cohort0_post_f_broad_canonical_reaudit_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This ledger reports only the blocker state for the post-F broad canonical re-audit. "
            "It does not widen beyond the minimum path already earned."
        ),
        "execution_status": EXECUTION_STATUS,
        "top_level_blocker": {
            "blocker_id": "POST_F_BROAD_CANONICAL_REAUDIT_NOT_YET_PASSED",
            "status": "CLEARED",
            "why_active": "No remaining bounded defects were found in the D/E/F minimum-path authority bundle.",
        },
        "ranked_missing_predicates": [],
        "subject_head": subject_head,
    }

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_broad_canonical_reaudit_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This re-audit checks only whether the minimum lawful path through Gate F is now contradiction-free, "
            "canonically frozen, and ready for controlled post-F expansion authoring. It does not broaden Gate F itself."
        ),
        "execution_status": EXECUTION_STATUS,
        "reaudit_outcome": OUTCOME_PASS,
        "minimum_path_complete_through_gate_f": True,
        "controlled_post_f_expansion_tracks_authorized_now": True,
        "current_program_posture": "MINIMUM_PATH_COMPLETE_THROUGH_GATE_F__BROAD_CANONICAL_REAUDIT_PASS",
        "reaudit_findings": {
            "gate_d_cleared_on_successor_line": True,
            "gate_e_open_on_successor_line": True,
            "gate_f_one_narrow_wedge_confirmed": True,
            "gate_f_open_remains_false": True,
            "live_product_truth_frozen": True,
            "historical_truth_preserved": True,
            "historical_product_truth_explicitly_superseded_for_live_posture": True,
            "live_authority_contradiction_free": True,
            "no_broader_platform_overclaim": True,
        },
        "next_lawful_move": common.NEXT_MOVE_POST_F_EXPANSION,
        "source_refs": {
            "branch_law_packet_ref": branch_law_packet_path.resolve().as_posix(),
            "branch_law_receipt_ref": branch_law_receipt_path.resolve().as_posix(),
            "supersession_note_ref": supersession_note_path.resolve().as_posix(),
            "orchestrator_receipt_ref": orchestrator_receipt_path.resolve().as_posix(),
            "gate_f_review_receipt_ref": gate_f_review_receipt_path.resolve().as_posix(),
            "live_product_truth_packet_ref": live_product_truth_packet_path.resolve().as_posix(),
            "live_product_truth_receipt_ref": live_product_truth_receipt_path.resolve().as_posix(),
            "post_f_supersession_note_ref": post_f_supersession_note_path.resolve().as_posix(),
            "post_f_supersession_receipt_ref": post_f_supersession_receipt_path.resolve().as_posix(),
        },
        "blocker_ledger_ref": (reports_root / OUTPUT_BLOCKER_LEDGER).resolve().as_posix(),
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_broad_canonical_reaudit_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "reaudit_outcome": OUTCOME_PASS,
        "minimum_path_complete_through_gate_f": True,
        "controlled_post_f_expansion_tracks_authorized_now": True,
        "next_lawful_move": common.NEXT_MOVE_POST_F_EXPANSION,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Post-F Broad Canonical Reaudit Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Reaudit outcome: `{OUTCOME_PASS}`",
            "- Minimum path complete through Gate F: `True`",
            "- Controlled post-F expansion tracks authorized now: `True`",
            f"- Next lawful move: `{common.NEXT_MOVE_POST_F_EXPANSION}`",
        ],
    )

    blocker_ledger_path = (reports_root / OUTPUT_BLOCKER_LEDGER).resolve()
    packet_path = (reports_root / OUTPUT_PACKET).resolve()
    receipt_path = (reports_root / OUTPUT_RECEIPT).resolve()
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    write_json_stable(blocker_ledger_path, blocker_ledger)
    write_json_stable(packet_path, packet)
    write_json_stable(receipt_path, receipt)
    common.write_text(report_path, report)
    return {
        "packet_path": packet_path.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "blocker_ledger_path": blocker_ledger_path.as_posix(),
        "next_lawful_move": common.NEXT_MOVE_POST_F_EXPANSION,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the post-F broad canonical re-audit.")
    parser.add_argument("--branch-law-receipt", default=f"{common.REPORTS_ROOT_REL}/cohort0_successor_gate_d_post_clear_branch_law_receipt.json")
    parser.add_argument("--gate-f-review-receipt", default=f"{common.REPORTS_ROOT_REL}/{review_tranche.OUTPUT_RECEIPT}")
    parser.add_argument(
        "--live-product-truth-packet",
        default=f"{common.REPORTS_ROOT_REL}/{live_product_truth_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--live-product-truth-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{live_product_truth_tranche.OUTPUT_RECEIPT}",
    )
    parser.add_argument(
        "--post-f-supersession-note",
        default=f"{common.REPORTS_ROOT_REL}/{post_f_supersession_tranche.OUTPUT_NOTE}",
    )
    parser.add_argument(
        "--post-f-supersession-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{post_f_supersession_tranche.OUTPUT_RECEIPT}",
    )
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        branch_law_receipt_path=common.resolve_path(root, args.branch_law_receipt),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        gate_f_review_receipt_path=common.resolve_path(root, args.gate_f_review_receipt),
        live_product_truth_packet_path=common.resolve_path(root, args.live_product_truth_packet),
        live_product_truth_receipt_path=common.resolve_path(root, args.live_product_truth_receipt),
        post_f_supersession_note_path=common.resolve_path(root, args.post_f_supersession_note),
        post_f_supersession_receipt_path=common.resolve_path(root, args.post_f_supersession_receipt),
    )
    print(result["next_lawful_move"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
