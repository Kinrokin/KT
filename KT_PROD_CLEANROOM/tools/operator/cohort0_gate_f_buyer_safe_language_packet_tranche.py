from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_external_workload_pilot_tranche as pilot_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_gate_f_buyer_safe_language_and_support_boundary_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_buyer_safe_language_and_support_boundary_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_BUYER_SAFE_LANGUAGE_AND_SUPPORT_BOUNDARY_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_BUYER_SAFE_LANGUAGE_AND_SUPPORT_BOUNDARY_BOUND"
PACKET_OUTCOME = "GATE_F_BUYER_SAFE_LANGUAGE_BOUND__LOCAL_VERIFIER_MODE_ONLY"


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    support_boundary: Dict[str, object],
    commercial_truth_packet: Dict[str, object],
) -> Dict[str, Dict[str, object]]:
    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_buyer_safe_language_and_support_boundary_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet binds only the buyer-safe Gate F language for one local verifier wedge. "
            "It does not widen the product story beyond that wedge."
        ),
        "execution_status": EXECUTION_STATUS,
        "packet_outcome": PACKET_OUTCOME,
        "one_page_audience_sheet": {
            "audience": "bounded_operator_needing_same_host_verifier_execution_and_receipts",
            "what_this_is": [
                "one local single-tenant verifier-backed execution surface",
                "clear PASS/FAIL receipt retrieval",
                "bounded audit packet and replay-kit handoff",
            ],
            "what_this_is_not": [
                "multi-tenant platform",
                "cross-host proof",
                "enterprise deployment promise",
                "training or mutation support",
            ],
        },
        "narrow_roi_packet": {
            "operator_value": "bounded install-to-pass/fail and audit-packet retrieval without repo archaeology",
            "time_budget_minutes": 15,
            "support_tier": str(support_boundary.get("support_tier", "")).strip(),
        },
        "support_boundary_sheet": {
            "supported_surfaces": list(support_boundary.get("supported_surfaces", [])),
            "unsupported_surfaces": list(support_boundary.get("unsupported_surfaces", [])),
            "runtime_cutover_allowed": bool(support_boundary.get("runtime_cutover_allowed", False)),
            "no_training_default": bool(support_boundary.get("no_training_default", False)),
        },
        "non_claims": [
            "No Gate F claim beyond local_verifier_mode.",
            "No claim of team-wide or regulated workflow entitlement from this packet alone.",
            "No F-to-G leap, no enterprise posture, no platform autonomy claim.",
        ],
        "source_refs": common.output_ref_dict(
            one_page_truth=common.resolve_path(root, common.ONE_PAGE_TRUTH_SURFACE_REL),
            support_boundary=common.resolve_path(root, common.SUPPORT_BOUNDARY_REL),
            commercial_truth_packet=common.resolve_path(root, common.COMMERCIAL_TRUTH_PACKET_REL),
            e1_wedge_doc=common.resolve_path(root, common.E1_WEDGE_DOC_REL),
            e1_demo_doc=common.resolve_path(root, common.E1_DEMO_DOC_REL),
        ),
        "subject_head": subject_head,
        "next_lawful_move": common.NEXT_MOVE_LANGUAGE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_buyer_safe_language_and_support_boundary_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "packet_outcome": PACKET_OUTCOME,
        "buyer_safe_language_bound": True,
        "gate_f_open": False,
        "next_lawful_move": common.NEXT_MOVE_LANGUAGE,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F Buyer Safe Language And Support Boundary Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Packet outcome: `{PACKET_OUTCOME}`",
            f"- Offer surface ceiling: `{commercial_truth_packet.get('externality_class_max', '')}`",
            f"- Support tier: `{support_boundary.get('support_tier', '')}`",
            f"- Next lawful move: `{common.NEXT_MOVE_LANGUAGE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    branch_law_packet_path: Path,
    supersession_note_path: Path,
    orchestrator_receipt_path: Path,
    pilot_receipt_path: Path,
) -> Dict[str, str]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    pilot_receipt = common.load_json_required(root, pilot_receipt_path, label="Gate F workload pilot receipt")
    support_boundary = common.load_json_required(root, common.SUPPORT_BOUNDARY_REL, label="support boundary")
    commercial_truth_packet = common.load_json_required(root, common.COMMERCIAL_TRUTH_PACKET_REL, label="commercial truth packet")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    common.ensure_pass(pilot_receipt, label="Gate F workload pilot receipt")
    if str(pilot_receipt.get("pilot_outcome", "")).strip() != pilot_tranche.PILOT_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Gate F buyer-safe packet requires a passing workload pilot")

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        support_boundary=support_boundary,
        commercial_truth_packet=commercial_truth_packet,
    )
    packet_path = (reports_root / OUTPUT_PACKET).resolve()
    receipt_path = (reports_root / OUTPUT_RECEIPT).resolve()
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    common.write_outputs(
        packet_path=packet_path,
        receipt_path=receipt_path,
        report_path=report_path,
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=outputs["report"],
    )
    return {
        "packet_path": packet_path.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "report_path": report_path.as_posix(),
        "packet_outcome": PACKET_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the Gate F buyer-safe language and support-boundary packet.")
    parser.add_argument("--pilot-receipt", default=f"{common.REPORTS_ROOT_REL}/{pilot_tranche.OUTPUT_RECEIPT}")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        pilot_receipt_path=common.resolve_path(root, args.pilot_receipt),
    )
    print(result["packet_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
