from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_gate_f_narrow_wedge_scope_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_narrow_wedge_scope_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_NARROW_WEDGE_SCOPE_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_NARROW_WEDGE_SCOPE_BOUND"
SCOPE_OUTCOME = "GATE_F_NARROW_WEDGE_SCOPE_DEFINED__LOCAL_VERIFIER_MODE_ONLY"


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    branch_law_packet: Dict[str, Any],
    deployment_profiles: Dict[str, Any],
    wrapper_spec: Dict[str, Any],
    support_boundary: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    local_profile = common.first_profile(deployment_profiles, profile_id=common.ACTIVE_WEDGE_PROFILE_ID)
    verify_entrypoint = common.first_entrypoint(wrapper_spec, entrypoint_id="verify_packet")
    detached_entrypoint = common.first_entrypoint(wrapper_spec, entrypoint_id="detached_pass_fail")

    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_narrow_wedge_scope_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet freezes the smallest Gate F surface now truthfully supportable by the live system: "
            "one local single-tenant verifier-backed execute/receipt wedge. It does not open broader product planes."
        ),
        "execution_status": EXECUTION_STATUS,
        "scope_outcome": SCOPE_OUTCOME,
        "authority_header": {
            "gate_d_cleared_on_successor_line": True,
            "gate_e_open_on_successor_line": True,
            "gate_f_open": False,
            "scope_setting_only": True,
        },
        "wedge_surface": {
            "wedge_id": common.GATE_F_WEDGE_ID,
            "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
            "surface_summary": (
                "Single-tenant same-host verifier-backed execution request, receipt retrieval, and replay-kit handoff."
            ),
            "for_operator_type": "bounded_local_operator",
            "successful_use_definition": [
                "run the bounded verifier entrypoint",
                "obtain the detached PASS/FAIL receipt surface",
                "retrieve the bounded audit packet and verifier kit without repo archaeology",
            ],
            "supported_actions": [
                "submit_bounded_verification_request",
                "retrieve_pass_fail_receipt",
                "retrieve_bounded_audit_packet",
                "retrieve_replay_kit_refs",
            ],
            "receipt_must_return": list(common.ACTIVE_WEDGE_RECEIPT_REFS),
            "deployment_modes_allowed": [common.ACTIVE_WEDGE_PROFILE_ID],
        },
        "wedge_mechanics": {
            "verify_entrypoint_id": "verify_packet",
            "verify_command": str(verify_entrypoint.get("command", "")).strip(),
            "detached_entrypoint_id": "detached_pass_fail",
            "detached_command": str(detached_entrypoint.get("command", "")).strip(),
            "pass_fail_surface_refs": list(wrapper_spec.get("pass_fail_surface_refs", [])),
            "support_boundary_ref": common.resolve_path(root, common.SUPPORT_BOUNDARY_REL).as_posix(),
        },
        "support_boundary": {
            "support_tier": str(support_boundary.get("support_tier", "")).strip(),
            "supported_surfaces": list(support_boundary.get("supported_surfaces", [])),
            "unsupported_surfaces": list(support_boundary.get("unsupported_surfaces", [])),
            "runtime_cutover_allowed": bool(support_boundary.get("runtime_cutover_allowed", False)),
            "no_training_default": bool(support_boundary.get("no_training_default", False)),
        },
        "explicit_non_claims": [
            "No multi-tenant execution claim.",
            "No cross-host proof claim.",
            "No enterprise readiness claim.",
            "No training, mutation, or runtime cutover claim.",
            "No autonomous multi-surface platform claim.",
        ],
        "source_refs": common.output_ref_dict(
            branch_law_packet=common.resolve_path(root, common.LIVE_BRANCH_LAW_PACKET_REL),
            deployment_profiles=common.resolve_path(root, common.DEPLOYMENT_PROFILES_REL),
            wrapper_spec=common.resolve_path(root, common.CLIENT_WRAPPER_SPEC_REL),
            support_boundary=common.resolve_path(root, common.SUPPORT_BOUNDARY_REL),
        ),
        "subject_head": subject_head,
        "next_lawful_move": common.NEXT_MOVE_SCOPE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_narrow_wedge_scope_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "scope_outcome": SCOPE_OUTCOME,
        "wedge_id": common.GATE_F_WEDGE_ID,
        "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
        "gate_f_open": False,
        "next_lawful_move": common.NEXT_MOVE_SCOPE,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F Narrow Wedge Scope Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Scope outcome: `{SCOPE_OUTCOME}`",
            f"- Active wedge id: `{common.GATE_F_WEDGE_ID}`",
            f"- Active profile: `{common.ACTIVE_WEDGE_PROFILE_ID}`",
            f"- Verify command: `{verify_entrypoint.get('command', '')}`",
            f"- Detached command: `{detached_entrypoint.get('command', '')}`",
            f"- Next lawful move: `{common.NEXT_MOVE_SCOPE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    branch_law_packet_path: Path,
    supersession_note_path: Path,
    orchestrator_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    deployment_profiles = common.load_json_required(root, common.DEPLOYMENT_PROFILES_REL, label="deployment profiles")
    wrapper_spec = common.load_json_required(root, common.CLIENT_WRAPPER_SPEC_REL, label="client wrapper spec")
    support_boundary = common.load_json_required(root, common.SUPPORT_BOUNDARY_REL, label="support boundary")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        branch_law_packet=branch_law_packet,
        deployment_profiles=deployment_profiles,
        wrapper_spec=wrapper_spec,
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
        "scope_outcome": SCOPE_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the Gate F narrow wedge scope packet.")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
    )
    print(result["scope_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
