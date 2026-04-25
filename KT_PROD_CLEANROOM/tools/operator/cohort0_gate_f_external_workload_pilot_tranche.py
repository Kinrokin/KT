from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_deployment_smoke_and_tenant_isolation_tranche as deploy_tranche
from tools.operator import cohort0_gate_f_fresh_operator_bootstrap_and_greenline_tranche as bootstrap_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_gate_f_external_workload_pilot_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_external_workload_pilot_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_EXTERNAL_WORKLOAD_PILOT_REPORT.md"
OUTPUT_PILOT_VERIFIER = "cohort0_gate_f_external_workload_pilot_public_verifier_report.json"

EXECUTION_STATUS = "PASS__GATE_F_EXTERNAL_WORKLOAD_PILOT_EXECUTED"
PILOT_OUTCOME = "GATE_F_EXTERNAL_WORKLOAD_PILOT_PASS__LOCAL_VERIFIER_MODE_ONLY"


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    pilot_report_path: Path,
    pilot_report: Dict[str, Any],
    detached_verifier_receipt: Dict[str, Any],
    external_audit_packet: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_external_workload_pilot_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet records one bounded Gate F workload pilot through the local verifier mode only. "
            "It does not prove a customer rollout, multi-tenant operation, or broader product usage."
        ),
        "execution_status": EXECUTION_STATUS,
        "pilot_outcome": PILOT_OUTCOME,
        "pilot_definition": {
            "pilot_id": "LOCAL_VERIFIER_MODE_CURRENT_HEAD_SMOKE_PILOT_V1",
            "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
            "pilot_command": common.ACTIVE_WEDGE_COMMAND,
            "single_tenant_only": True,
            "current_head_report_ref": pilot_report_path.as_posix(),
            "receipt_retrieval_refs": list(common.ACTIVE_WEDGE_RECEIPT_REFS),
        },
        "pilot_results": {
            "live_report_status": str(pilot_report.get("status", "")).strip(),
            "live_head_claim_verdict": str(pilot_report.get("head_claim_verdict", "")).strip(),
            "live_workflow_governance_status": str(pilot_report.get("workflow_governance_status", "")).strip(),
            "detached_receipt_status": str(detached_verifier_receipt.get("status", "")).strip(),
            "external_audit_packet_status": str(external_audit_packet.get("status", "")).strip(),
        },
        "explicit_non_claims": [
            "This is not a customer pilot or public launch.",
            "This is not multi-tenant usage.",
            "This is not a cross-host or outsider-capability claim.",
        ],
        "subject_head": subject_head,
        "next_lawful_move": common.NEXT_MOVE_PILOT,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_external_workload_pilot_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "pilot_outcome": PILOT_OUTCOME,
        "gate_f_external_workload_pilot_pass": True,
        "gate_f_open": False,
        "next_lawful_move": common.NEXT_MOVE_PILOT,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F External Workload Pilot Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Pilot outcome: `{PILOT_OUTCOME}`",
            f"- Pilot command: `{common.ACTIVE_WEDGE_COMMAND}`",
            f"- Pilot report: `{pilot_report_path.as_posix()}`",
            f"- Detached verifier receipt status: `{detached_verifier_receipt.get('status', '')}`",
            f"- Next lawful move: `{common.NEXT_MOVE_PILOT}`",
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
    bootstrap_wave_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    deployment_wave_receipt = common.load_json_required(root, deployment_wave_receipt_path, label="Gate F deployment smoke receipt")
    bootstrap_wave_receipt = common.load_json_required(root, bootstrap_wave_receipt_path, label="Gate F bootstrap receipt")
    detached_verifier_receipt = common.load_json_required(root, common.DETACHED_VERIFIER_RECEIPT_REL, label="detached verifier receipt")
    external_audit_packet = common.load_json_required(root, common.EXTERNAL_AUDIT_PACKET_REL, label="external audit packet")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    common.ensure_pass(deployment_wave_receipt, label="Gate F deployment smoke receipt")
    common.ensure_pass(bootstrap_wave_receipt, label="Gate F bootstrap receipt")
    if str(deployment_wave_receipt.get("wave_outcome", "")).strip() != deploy_tranche.WAVE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Gate F workload pilot requires the deployment smoke wave")
    if str(bootstrap_wave_receipt.get("wave_outcome", "")).strip() != bootstrap_tranche.WAVE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Gate F workload pilot requires the bootstrap wave")
    common.ensure_pass(detached_verifier_receipt, label="detached verifier receipt")
    common.ensure_pass(external_audit_packet, label="external audit packet")

    pilot_report_path = (reports_root / OUTPUT_PILOT_VERIFIER).resolve()
    pilot_report = common.run_public_verifier_smoke(root=root, output_path=pilot_report_path)

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        pilot_report_path=pilot_report_path,
        pilot_report=pilot_report,
        detached_verifier_receipt=detached_verifier_receipt,
        external_audit_packet=external_audit_packet,
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
        "pilot_report_path": pilot_report_path.as_posix(),
        "pilot_outcome": PILOT_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the Gate F external workload pilot.")
    parser.add_argument("--deployment-wave-receipt", default=f"{common.REPORTS_ROOT_REL}/{deploy_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--bootstrap-wave-receipt", default=f"{common.REPORTS_ROOT_REL}/{bootstrap_tranche.OUTPUT_RECEIPT}")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        deployment_wave_receipt_path=common.resolve_path(root, args.deployment_wave_receipt),
        bootstrap_wave_receipt_path=common.resolve_path(root, args.bootstrap_wave_receipt),
    )
    print(result["pilot_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
