from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_product_wedge_admissibility_screen_tranche as screen_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_gate_f_one_narrow_wedge_review_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_one_narrow_wedge_review_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_ONE_NARROW_WEDGE_REVIEW_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_ONE_NARROW_WEDGE_REVIEW_CONVENED"
OUTCOME_CONFIRMED = "GATE_F_ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY"
OUTCOME_NOT_CONFIRMED = "GATE_F_ONE_NARROW_WEDGE_NOT_CONFIRMED__BOUNDED_DEFECT_IDENTIFIED"


def build_outputs(*, subject_head: str, authorized: bool) -> Dict[str, Dict[str, object]]:
    outcome = OUTCOME_CONFIRMED if authorized else OUTCOME_NOT_CONFIRMED
    next_move = common.NEXT_MOVE_MAINTAIN if authorized else "AUTHOR_GATE_F_WEDGE_DEFECT_CLOSURE_PACKET"
    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_one_narrow_wedge_review_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This review decides only whether one Gate F narrow wedge is confirmed. "
            "It does not broaden that confirmation into a larger platform claim."
        ),
        "execution_status": EXECUTION_STATUS,
        "review_outcome": outcome,
        "current_gate_f_posture": (
            "GATE_F_ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY"
            if authorized
            else "GATE_F_NARROW_WEDGE_STILL_NOT_CONFIRMED"
        ),
        "gate_f_narrow_wedge_confirmed": authorized,
        "gate_f_open": False,
        "wedge_id": common.GATE_F_WEDGE_ID,
        "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
        "next_lawful_move": next_move,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_one_narrow_wedge_review_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "review_outcome": outcome,
        "gate_f_narrow_wedge_confirmed": authorized,
        "gate_f_open": False,
        "next_lawful_move": next_move,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F One Narrow Wedge Review Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Review outcome: `{outcome}`",
            f"- Gate F narrow wedge confirmed: `{authorized}`",
            f"- Active profile: `{common.ACTIVE_WEDGE_PROFILE_ID}`",
            f"- Next lawful move: `{next_move}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    branch_law_packet_path: Path,
    supersession_note_path: Path,
    orchestrator_receipt_path: Path,
    screen_receipt_path: Path,
) -> Dict[str, str]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    screen_receipt = common.load_json_required(root, screen_receipt_path, label="Gate F admissibility screen receipt")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    authorized = str(screen_receipt.get("screen_outcome", "")).strip() == screen_tranche.OUTCOME_AUTHORIZED
    outputs = build_outputs(subject_head=subject_head, authorized=authorized)

    packet_path = (reports_root / OUTPUT_PACKET).resolve()
    receipt_path = (reports_root / OUTPUT_RECEIPT).resolve()
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    common.write_text(report_path, outputs["report"])
    return {
        "packet_path": packet_path.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "report_path": report_path.as_posix(),
        "review_outcome": str(outputs["receipt"]["review_outcome"]),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Convene the Gate F one narrow wedge review.")
    parser.add_argument("--screen-receipt", default=f"{common.REPORTS_ROOT_REL}/{screen_tranche.OUTPUT_RECEIPT}")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        screen_receipt_path=common.resolve_path(root, args.screen_receipt),
    )
    print(result["review_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
