from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_buyer_safe_language_packet_tranche as language_tranche
from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_deployment_smoke_and_tenant_isolation_tranche as deploy_tranche
from tools.operator import cohort0_gate_f_external_workload_pilot_tranche as pilot_tranche
from tools.operator import cohort0_gate_f_fresh_operator_bootstrap_and_greenline_tranche as bootstrap_tranche
from tools.operator import cohort0_gate_f_narrow_wedge_scope_packet_tranche as scope_tranche
from tools.operator import cohort0_gate_f_product_truth_and_governance_contract_tranche as governance_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_gate_f_product_wedge_admissibility_screen_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_product_wedge_admissibility_screen_receipt.json"
OUTPUT_LEDGER = "cohort0_gate_f_product_wedge_admissibility_blocker_ledger.json"
OUTPUT_REPORT = "COHORT0_GATE_F_PRODUCT_WEDGE_ADMISSIBILITY_SCREEN_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_PRODUCT_WEDGE_ADMISSIBILITY_SCREEN_EXECUTED"
OUTCOME_AUTHORIZED = "GATE_F_ADMISSIBILITY_SCREEN_AUTHORIZED__ONE_NARROW_WEDGE_ONLY"
OUTCOME_BLOCKED = "GATE_F_NOT_ADMISSIBLE__BOUNDED_DEFECT_IDENTIFIED"
OUTCOME_DEFERRED = "DEFERRED__SPECIFIC_GATE_F_PREDICATE_MISSING"


def build_outputs(
    *,
    subject_head: str,
    findings: Dict[str, bool],
) -> Dict[str, Dict[str, object]]:
    missing = [key for key, ok in findings.items() if not ok]
    if not missing:
        outcome = OUTCOME_AUTHORIZED
        next_move = common.NEXT_MOVE_SCREEN
        blocker = "NONE"
    elif len(missing) == len(findings):
        outcome = OUTCOME_DEFERRED
        next_move = "MAINTAIN_GATE_F_PRE_ADMISSIBILITY_POSTURE"
        blocker = "ALL_GATE_F_PREDICATES_MISSING"
    else:
        outcome = OUTCOME_BLOCKED
        next_move = "AUTHOR_GATE_F_BOUNDED_DEFECT_CLOSURE_PACKET"
        blocker = missing[0]

    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_product_wedge_admissibility_screen_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This screen decides only whether one Gate F narrow wedge may proceed to review. "
            "It does not by itself open Gate F or widen the product plane."
        ),
        "execution_status": EXECUTION_STATUS,
        "screen_outcome": outcome,
        "predicate_findings": findings,
        "gate_f_narrow_wedge_review_authorized_now": outcome == OUTCOME_AUTHORIZED,
        "gate_f_open": False,
        "next_lawful_move": next_move,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_product_wedge_admissibility_screen_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "screen_outcome": outcome,
        "gate_f_narrow_wedge_review_authorized_now": outcome == OUTCOME_AUTHORIZED,
        "gate_f_open": False,
        "next_lawful_move": next_move,
        "subject_head": subject_head,
    }
    ledger = {
        "schema_id": "kt.operator.cohort0_gate_f_product_wedge_admissibility_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "current_authority_scope": "GATE_F_NARROW_WEDGE_PROGRAM",
        "screen_outcome": outcome,
        "ranked_missing_predicates": missing,
        "primary_blocker": blocker,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F Product Wedge Admissibility Screen Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Screen outcome: `{outcome}`",
            f"- Review authorized now: `{outcome == OUTCOME_AUTHORIZED}`",
            f"- Primary blocker: `{blocker}`",
            f"- Next lawful move: `{next_move}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "ledger": ledger, "report": report}


def run(
    *,
    reports_root: Path,
    branch_law_packet_path: Path,
    supersession_note_path: Path,
    orchestrator_receipt_path: Path,
    scope_packet_path: Path,
    governance_contract_path: Path,
    deployment_wave_receipt_path: Path,
    bootstrap_wave_receipt_path: Path,
    pilot_receipt_path: Path,
    language_receipt_path: Path,
) -> Dict[str, str]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    scope_packet = common.load_json_required(root, scope_packet_path, label="Gate F scope packet")
    governance_contract = common.load_json_required(root, governance_contract_path, label="Gate F governance contract")
    deployment_wave_receipt = common.load_json_required(root, deployment_wave_receipt_path, label="Gate F deployment smoke receipt")
    bootstrap_wave_receipt = common.load_json_required(root, bootstrap_wave_receipt_path, label="Gate F bootstrap receipt")
    pilot_receipt = common.load_json_required(root, pilot_receipt_path, label="Gate F workload pilot receipt")
    language_receipt = common.load_json_required(root, language_receipt_path, label="Gate F buyer-safe language receipt")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    findings = {
        "scope_bound": str(scope_packet.get("scope_outcome", "")).strip() == scope_tranche.SCOPE_OUTCOME,
        "governance_bound": str(governance_contract.get("contract_outcome", "")).strip() == governance_tranche.CONTRACT_OUTCOME,
        "deployment_smoke_pass": str(deployment_wave_receipt.get("wave_outcome", "")).strip() == deploy_tranche.WAVE_OUTCOME,
        "bootstrap_greenline_pass": str(bootstrap_wave_receipt.get("wave_outcome", "")).strip() == bootstrap_tranche.WAVE_OUTCOME,
        "external_workload_pilot_pass": str(pilot_receipt.get("pilot_outcome", "")).strip() == pilot_tranche.PILOT_OUTCOME,
        "buyer_safe_language_bound": str(language_receipt.get("packet_outcome", "")).strip() == language_tranche.PACKET_OUTCOME,
    }

    outputs = build_outputs(subject_head=subject_head, findings=findings)
    packet_path = (reports_root / OUTPUT_PACKET).resolve()
    receipt_path = (reports_root / OUTPUT_RECEIPT).resolve()
    ledger_path = (reports_root / OUTPUT_LEDGER).resolve()
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    write_json_stable(ledger_path, outputs["ledger"])
    common.write_text(report_path, outputs["report"])
    return {
        "packet_path": packet_path.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "ledger_path": ledger_path.as_posix(),
        "report_path": report_path.as_posix(),
        "screen_outcome": str(outputs["receipt"]["screen_outcome"]),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the Gate F product wedge admissibility screen.")
    parser.add_argument("--scope-packet", default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}")
    parser.add_argument("--governance-contract", default=f"{common.REPORTS_ROOT_REL}/{governance_tranche.OUTPUT_PACKET}")
    parser.add_argument("--deployment-wave-receipt", default=f"{common.REPORTS_ROOT_REL}/{deploy_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--bootstrap-wave-receipt", default=f"{common.REPORTS_ROOT_REL}/{bootstrap_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--pilot-receipt", default=f"{common.REPORTS_ROOT_REL}/{pilot_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--language-receipt", default=f"{common.REPORTS_ROOT_REL}/{language_tranche.OUTPUT_RECEIPT}")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        scope_packet_path=common.resolve_path(root, args.scope_packet),
        governance_contract_path=common.resolve_path(root, args.governance_contract),
        deployment_wave_receipt_path=common.resolve_path(root, args.deployment_wave_receipt),
        bootstrap_wave_receipt_path=common.resolve_path(root, args.bootstrap_wave_receipt),
        pilot_receipt_path=common.resolve_path(root, args.pilot_receipt),
        language_receipt_path=common.resolve_path(root, args.language_receipt),
    )
    print(result["screen_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
