from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_narrow_wedge_scope_packet_tranche as scope_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_gate_f_product_truth_and_governance_contract.json"
OUTPUT_RECEIPT = "cohort0_gate_f_product_truth_and_governance_contract_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_PRODUCT_TRUTH_AND_GOVERNANCE_CONTRACT_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_PRODUCT_TRUTH_AND_GOVERNANCE_BOUND"
CONTRACT_OUTCOME = "GATE_F_PRODUCT_TRUTH_AND_GOVERNANCE_CONTRACT_BOUND__LOCAL_VERIFIER_MODE_ONLY"


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    scope_packet: Dict[str, Any],
    branch_law_packet: Dict[str, Any],
    deployment_profiles: Dict[str, Any],
    support_boundary: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    local_profile = common.first_profile(deployment_profiles, profile_id=common.ACTIVE_WEDGE_PROFILE_ID)
    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_product_truth_and_governance_contract.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This contract binds the exact product-truth comparator and governance obligations for the Gate F narrow wedge only. "
            "It does not open Gate F or widen beyond the local verifier mode."
        ),
        "execution_status": EXECUTION_STATUS,
        "contract_outcome": CONTRACT_OUTCOME,
        "boundary_header": {
            "gate_d_cleared_on_successor_line": True,
            "gate_e_open_on_successor_line": True,
            "gate_f_open": False,
            "binding_only": True,
        },
        "gate_f_comparator_definition": {
            "comparator_id": "GATE_F_LOCAL_VERIFIER_TRUTH_COMPARATOR_V1",
            "bounded_surface_under_review": common.GATE_F_WEDGE_ID,
            "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
            "lawful_comparator_win_definition": (
                "A Gate F narrow wedge claim is lawful only when the local verifier mode can be run from the governed wrapper, "
                "returns the declared receipt/proof surfaces, and stays inside the explicit single-tenant support boundary."
            ),
            "comparison_not_allowed_against": [
                "cross_host_or_hostile_verification",
                "multi_tenant_orchestration",
                "enterprise_platform_readiness",
                "broad_autonomy_or_multi_surface_runtime_claims",
            ],
            "local_profile_install_budget_minutes": int(local_profile.get("install_to_pass_fail_minutes", 0) or 0),
        },
        "gate_f_governance_bundle": {
            "tenant_posture_required": common.TENANT_POSTURE_SINGLE_ONLY,
            "bounded_operator_authority_required": True,
            "runbook_only_bootstrap_required": True,
            "receipt_retrieval_required": True,
            "buyer_safe_language_required": True,
            "rollback_rule": (
                "Any contradiction, governance drift, or support-boundary violation demotes the wedge back below admissibility."
            ),
            "unsupported_surfaces": list(support_boundary.get("unsupported_surfaces", [])),
        },
        "predicate_to_evidence_map": [
            {
                "predicate_id": "gate_f_live_header_open_state",
                "source_ref": common.resolve_path(root, common.LIVE_BRANCH_LAW_PACKET_REL).as_posix(),
                "satisfaction_rule": "Gate D cleared and Gate E open are both true on the successor line.",
                "failure_rule": "If either D clear or E open is false, Gate F is fail-closed.",
            },
            {
                "predicate_id": "gate_f_active_wedge_profile_local_verifier_only",
                "source_ref": common.resolve_path(root, common.DEPLOYMENT_PROFILES_REL).as_posix(),
                "satisfaction_rule": "local_verifier_mode exists and remains bounded to E1-style same-host use.",
                "failure_rule": "If local_verifier_mode is missing or widened, the wedge contract is invalid.",
            },
            {
                "predicate_id": "gate_f_support_boundary_no_training_single_tenant",
                "source_ref": common.resolve_path(root, common.SUPPORT_BOUNDARY_REL).as_posix(),
                "satisfaction_rule": "No training, no runtime cutover, single-tenant-only posture.",
                "failure_rule": "Any training, runtime cutover, or multi-tenant claim invalidates the contract.",
            },
            {
                "predicate_id": "gate_f_receipt_surface_declared",
                "source_ref": common.resolve_path(root, common.CLIENT_WRAPPER_SPEC_REL).as_posix(),
                "satisfaction_rule": "The wrapper declares verify and detached PASS/FAIL entrypoints and receipt refs.",
                "failure_rule": "Missing wrapper command or receipt refs blocks Gate F admissibility.",
            },
        ],
        "explicit_non_claims": [
            "This contract does not open Gate F.",
            "This contract does not imply Gate G, re-audit, or enterprise rollout.",
            "This contract does not treat Gate D/E success as automatic product entitlement.",
            "This contract does not widen beyond local_verifier_mode.",
        ],
        "allowed_next_outcomes": [
            "GATE_F_DEPLOYMENT_SMOKE_AND_TENANT_ISOLATION_PASS",
            "GATE_F_DEPLOYMENT_SMOKE_AND_TENANT_ISOLATION_FAIL__BOUNDED_DEFECT",
            "DEFERRED__MISSING_GATE_F_PRODUCT_GOVERNANCE_PREDICATE",
        ],
        "source_refs": common.output_ref_dict(
            scope_packet=common.resolve_path(root, common.REPORTS_ROOT_REL) / scope_tranche.OUTPUT_PACKET,
            branch_law_packet=common.resolve_path(root, common.LIVE_BRANCH_LAW_PACKET_REL),
            deployment_profiles=common.resolve_path(root, common.DEPLOYMENT_PROFILES_REL),
            support_boundary=common.resolve_path(root, common.SUPPORT_BOUNDARY_REL),
        ),
        "subject_head": subject_head,
        "next_lawful_move": common.NEXT_MOVE_GOVERNANCE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_product_truth_and_governance_contract_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "contract_outcome": CONTRACT_OUTCOME,
        "gate_f_comparator_governance_bundle_bound": True,
        "gate_f_open": False,
        "next_lawful_move": common.NEXT_MOVE_GOVERNANCE,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F Product Truth And Governance Contract Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Contract outcome: `{CONTRACT_OUTCOME}`",
            f"- Comparator id: `GATE_F_LOCAL_VERIFIER_TRUTH_COMPARATOR_V1`",
            f"- Active wedge profile: `{common.ACTIVE_WEDGE_PROFILE_ID}`",
            f"- Tenant posture required: `{common.TENANT_POSTURE_SINGLE_ONLY}`",
            f"- Next lawful move: `{common.NEXT_MOVE_GOVERNANCE}`",
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
) -> Dict[str, Any]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    scope_packet = common.load_json_required(root, scope_packet_path, label="Gate F scope packet")
    deployment_profiles = common.load_json_required(root, common.DEPLOYMENT_PROFILES_REL, label="deployment profiles")
    support_boundary = common.load_json_required(root, common.SUPPORT_BOUNDARY_REL, label="support boundary")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    common.ensure_pass(scope_packet, label="Gate F scope packet")
    if str(scope_packet.get("scope_outcome", "")).strip() != scope_tranche.SCOPE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Gate F governance contract requires the narrow scope packet to be bound first")

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        scope_packet=scope_packet,
        branch_law_packet=branch_law_packet,
        deployment_profiles=deployment_profiles,
        support_boundary=support_boundary,
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
        "contract_outcome": CONTRACT_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the Gate F product-truth and governance contract.")
    parser.add_argument(
        "--scope-packet",
        default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        scope_packet_path=common.resolve_path(root, args.scope_packet),
    )
    print(result["contract_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
