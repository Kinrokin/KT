from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_deployment_smoke_and_tenant_isolation_tranche as deploy_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_gate_f_fresh_operator_bootstrap_and_greenline_wave_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_fresh_operator_bootstrap_and_greenline_wave_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_FRESH_OPERATOR_BOOTSTRAP_AND_GREENLINE_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_FRESH_OPERATOR_BOOTSTRAP_AND_GREENLINE_BOUND"
WAVE_OUTCOME = "GATE_F_FRESH_OPERATOR_BOOTSTRAP_AND_GREENLINE_PASS__RUNBOOK_ONLY_PATH_BOUND"


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    greenline_receipt: Dict[str, Any],
    product_install_receipt: Dict[str, Any],
    operator_handoff_receipt: Dict[str, Any],
    live_validation_index: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    clean_clone_row = common.find_check(live_validation_index, check_id="operator_clean_clone_smoke")
    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_fresh_operator_bootstrap_and_greenline_wave_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This wave proves only that the Gate F wedge inherits a bounded runbook/bootstrap/greenline path without repo archaeology. "
            "It does not prove enterprise support or multi-operator rollout."
        ),
        "execution_status": EXECUTION_STATUS,
        "wave_outcome": WAVE_OUTCOME,
        "bootstrap_findings": {
            "product_install_receipt_status": str(product_install_receipt.get("status", "")).strip(),
            "operator_handoff_receipt_status": str(operator_handoff_receipt.get("status", "")).strip(),
            "greenline_receipt_status": str(greenline_receipt.get("status", "")).strip(),
            "clean_clone_smoke_status": str(clean_clone_row.get("status", "")).strip(),
            "independent_operator_target_minutes": int(operator_handoff_receipt.get("independent_operator_target_minutes", 0) or 0),
        },
        "runbook_bundle_refs": list(operator_handoff_receipt.get("handoff_bundle_refs", [])),
        "greenline_refs": {
            "greenline_receipt_ref": common.resolve_path(root, common.GREENLINE_RECEIPT_REL).as_posix(),
            "live_validation_index_ref": common.resolve_path(root, common.LIVE_VALIDATION_INDEX_REL).as_posix(),
        },
        "explicit_non_claims": [
            "No claim of cross-host bootstrap independence.",
            "No claim of multi-tenant support readiness.",
            "No claim of support staffing or enterprise SLOs.",
        ],
        "subject_head": subject_head,
        "next_lawful_move": common.NEXT_MOVE_BOOTSTRAP,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_fresh_operator_bootstrap_and_greenline_wave_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "wave_outcome": WAVE_OUTCOME,
        "runbook_only_bootstrap_ready": True,
        "greenline_ready": True,
        "gate_f_open": False,
        "next_lawful_move": common.NEXT_MOVE_BOOTSTRAP,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F Fresh Operator Bootstrap And Greenline Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Wave outcome: `{WAVE_OUTCOME}`",
            f"- Product install status: `{product_install_receipt.get('status', '')}`",
            f"- Operator handoff status: `{operator_handoff_receipt.get('status', '')}`",
            f"- Greenline status: `{greenline_receipt.get('status', '')}`",
            f"- Clean clone smoke status: `{clean_clone_row.get('status', '')}`",
            f"- Next lawful move: `{common.NEXT_MOVE_BOOTSTRAP}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    branch_law_packet_path: Path,
    supersession_note_path: Path,
    orchestrator_receipt_path: Path,
    deployment_wave_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    deployment_wave_receipt = common.load_json_required(root, deployment_wave_receipt_path, label="Gate F deployment smoke receipt")
    greenline_receipt = common.load_json_required(root, common.GREENLINE_RECEIPT_REL, label="operator greenline receipt")
    product_install_receipt = common.load_json_required(root, common.PRODUCT_INSTALL_RECEIPT_REL, label="product install receipt")
    operator_handoff_receipt = common.load_json_required(root, common.OPERATOR_HANDOFF_RECEIPT_REL, label="operator handoff receipt")
    live_validation_index = common.load_json_required(root, common.LIVE_VALIDATION_INDEX_REL, label="live validation index")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    common.ensure_pass(deployment_wave_receipt, label="Gate F deployment smoke receipt")
    if str(deployment_wave_receipt.get("wave_outcome", "")).strip() != deploy_tranche.WAVE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Gate F bootstrap wave requires deployment smoke to pass first")
    common.ensure_pass(greenline_receipt, label="operator greenline receipt")
    common.ensure_pass(product_install_receipt, label="product install receipt")
    common.ensure_pass(operator_handoff_receipt, label="operator handoff receipt")
    if str(common.find_check(live_validation_index, check_id="operator_clean_clone_smoke").get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Gate F bootstrap requires a passing clean-clone operator smoke row")

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        greenline_receipt=greenline_receipt,
        product_install_receipt=product_install_receipt,
        operator_handoff_receipt=operator_handoff_receipt,
        live_validation_index=live_validation_index,
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
        "wave_outcome": WAVE_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the Gate F fresh operator bootstrap and greenline wave.")
    parser.add_argument(
        "--deployment-wave-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{deploy_tranche.OUTPUT_RECEIPT}",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        deployment_wave_receipt_path=common.resolve_path(root, args.deployment_wave_receipt),
    )
    print(result["wave_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
