from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_narrow_wedge_scope_packet_tranche as scope_tranche
from tools.operator import cohort0_gate_f_product_truth_and_governance_contract_tranche as governance_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_gate_f_deployment_smoke_and_tenant_isolation_wave_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_deployment_smoke_and_tenant_isolation_wave_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_DEPLOYMENT_SMOKE_AND_TENANT_ISOLATION_REPORT.md"
OUTPUT_LIVE_VERIFIER = "cohort0_gate_f_live_public_verifier_report.json"

EXECUTION_STATUS = "PASS__GATE_F_DEPLOYMENT_SMOKE_AND_TENANT_ISOLATION_BOUND"
WAVE_OUTCOME = "GATE_F_DEPLOYMENT_SMOKE_AND_TENANT_ISOLATION_PASS__SINGLE_TENANT_ONLY"


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    live_verifier_report_path: Path,
    live_verifier_report: Dict[str, Any],
    deployment_profiles: Dict[str, Any],
    final_truth_boundary: Dict[str, Any],
    product_install_receipt: Dict[str, Any],
    public_verifier_kit: Dict[str, Any],
    detached_verifier_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    local_profile = common.first_profile(deployment_profiles, profile_id=common.ACTIVE_WEDGE_PROFILE_ID)
    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_deployment_smoke_and_tenant_isolation_wave_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This wave proves only that the Gate F local verifier wedge can be smoked on the current head and that the "
            "allowed tenant posture is single-tenant only. It does not prove multi-tenant isolation or broader product scale."
        ),
        "execution_status": EXECUTION_STATUS,
        "wave_outcome": WAVE_OUTCOME,
        "tenant_posture": {
            "posture": common.TENANT_POSTURE_SINGLE_ONLY,
            "multi_tenant_isolation_proven": False,
            "bounded_single_tenant_declaration": True,
            "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
        },
        "deployment_smoke": {
            "command": common.ACTIVE_WEDGE_COMMAND,
            "live_verifier_report_ref": live_verifier_report_path.as_posix(),
            "live_verifier_status": str(live_verifier_report.get("status", "")).strip(),
            "live_verifier_head_claim_verdict": str(live_verifier_report.get("head_claim_verdict", "")).strip(),
            "pass_fail_surface_refs": list(common.ACTIVE_WEDGE_RECEIPT_REFS),
        },
        "bounded_supporting_receipts": {
            "final_product_truth_boundary_ref": common.resolve_path(root, common.FINAL_PRODUCT_TRUTH_BOUNDARY_REL).as_posix(),
            "product_install_receipt_ref": common.resolve_path(root, common.PRODUCT_INSTALL_RECEIPT_REL).as_posix(),
            "public_verifier_kit_ref": common.resolve_path(root, common.PUBLIC_VERIFIER_KIT_REL).as_posix(),
            "detached_verifier_receipt_ref": common.resolve_path(root, common.DETACHED_VERIFIER_RECEIPT_REL).as_posix(),
        },
        "supporting_findings": {
            "local_profile_install_budget_minutes": int(local_profile.get("install_to_pass_fail_minutes", 0) or 0),
            "product_truth_boundary_status": str(final_truth_boundary.get("status", "")).strip(),
            "product_install_status": str(product_install_receipt.get("status", "")).strip(),
            "public_verifier_kit_status": str(public_verifier_kit.get("status", "")).strip(),
            "detached_verifier_receipt_status": str(detached_verifier_receipt.get("status", "")).strip(),
        },
        "explicit_non_claims": [
            "No multi-tenant isolation proof is claimed.",
            "No cross-host execution proof is claimed.",
            "No enterprise deployment claim is made.",
            "No autonomous queueing or broad platform orchestration claim is made.",
        ],
        "subject_head": subject_head,
        "next_lawful_move": common.NEXT_MOVE_DEPLOY,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_deployment_smoke_and_tenant_isolation_wave_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "wave_outcome": WAVE_OUTCOME,
        "tenant_posture": common.TENANT_POSTURE_SINGLE_ONLY,
        "live_verifier_smoke_pass": True,
        "gate_f_open": False,
        "next_lawful_move": common.NEXT_MOVE_DEPLOY,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F Deployment Smoke And Tenant Isolation Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Wave outcome: `{WAVE_OUTCOME}`",
            f"- Tenant posture: `{common.TENANT_POSTURE_SINGLE_ONLY}`",
            f"- Live verifier report: `{live_verifier_report_path.as_posix()}`",
            f"- Live verifier status: `{live_verifier_report.get('status', '')}`",
            f"- Next lawful move: `{common.NEXT_MOVE_DEPLOY}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    branch_law_packet_path: Path,
    supersession_note_path: Path,
    orchestrator_receipt_path: Path,
    scope_packet_path: Path,
    governance_contract_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    scope_packet = common.load_json_required(root, scope_packet_path, label="Gate F scope packet")
    governance_contract = common.load_json_required(root, governance_contract_path, label="Gate F governance contract")
    deployment_profiles = common.load_json_required(root, common.DEPLOYMENT_PROFILES_REL, label="deployment profiles")
    final_truth_boundary = common.load_json_required(root, common.FINAL_PRODUCT_TRUTH_BOUNDARY_REL, label="final product truth boundary")
    product_install_receipt = common.load_json_required(root, common.PRODUCT_INSTALL_RECEIPT_REL, label="product install receipt")
    public_verifier_kit = common.load_json_required(root, common.PUBLIC_VERIFIER_KIT_REL, label="public verifier kit")
    detached_verifier_receipt = common.load_json_required(root, common.DETACHED_VERIFIER_RECEIPT_REL, label="detached verifier receipt")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    common.ensure_pass(scope_packet, label="Gate F scope packet")
    common.ensure_pass(governance_contract, label="Gate F governance contract")
    if str(scope_packet.get("scope_outcome", "")).strip() != scope_tranche.SCOPE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Gate F deployment smoke requires the narrow scope packet")
    if str(governance_contract.get("contract_outcome", "")).strip() != governance_tranche.CONTRACT_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Gate F deployment smoke requires the product truth/governance contract")

    live_verifier_report_path = (reports_root / OUTPUT_LIVE_VERIFIER).resolve()
    live_verifier_report = common.run_public_verifier_smoke(root=root, output_path=live_verifier_report_path)

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        live_verifier_report_path=live_verifier_report_path,
        live_verifier_report=live_verifier_report,
        deployment_profiles=deployment_profiles,
        final_truth_boundary=final_truth_boundary,
        product_install_receipt=product_install_receipt,
        public_verifier_kit=public_verifier_kit,
        detached_verifier_receipt=detached_verifier_receipt,
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
        "live_verifier_report_path": live_verifier_report_path.as_posix(),
        "wave_outcome": WAVE_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the Gate F deployment smoke and tenant isolation wave.")
    parser.add_argument("--scope-packet", default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}")
    parser.add_argument("--governance-contract", default=f"{common.REPORTS_ROOT_REL}/{governance_tranche.OUTPUT_PACKET}")
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
    )
    print(result["wave_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
