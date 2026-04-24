from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_buyer_safe_language_packet_tranche as language_tranche
from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_gate_f_deployment_smoke_and_tenant_isolation_tranche as deploy_tranche
from tools.operator import cohort0_gate_f_external_workload_pilot_tranche as pilot_tranche
from tools.operator import cohort0_gate_f_fresh_operator_bootstrap_and_greenline_tranche as bootstrap_tranche
from tools.operator import cohort0_gate_f_one_narrow_wedge_review_tranche as review_tranche
from tools.operator import cohort0_gate_f_product_truth_and_governance_contract_tranche as governance_tranche
from tools.operator import cohort0_gate_f_product_wedge_admissibility_screen_tranche as screen_tranche
from tools.operator import cohort0_gate_f_narrow_wedge_scope_packet_tranche as scope_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_gate_f_post_close_live_product_truth_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_f_post_close_live_product_truth_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_POST_CLOSE_LIVE_PRODUCT_TRUTH_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_POST_CLOSE_LIVE_PRODUCT_TRUTH_BOUND"


def _tenant_posture(deployment_receipt: Dict[str, Any]) -> str:
    return str(deployment_receipt.get("tenant_posture", "")).strip() or common.TENANT_POSTURE_SINGLE_ONLY


def build_outputs(
    *,
    subject_head: str,
    branch_law_packet: Dict[str, Any],
    scope_packet: Dict[str, Any],
    governance_contract: Dict[str, Any],
    deployment_receipt: Dict[str, Any],
    bootstrap_receipt: Dict[str, Any],
    pilot_receipt: Dict[str, Any],
    language_receipt: Dict[str, Any],
    screen_receipt: Dict[str, Any],
    review_packet: Dict[str, Any],
    review_receipt: Dict[str, Any],
    source_refs: Dict[str, str],
) -> Dict[str, Any]:
    branch_status = dict(branch_law_packet.get("canonical_live_branch_status", {}))
    canonical_status = {
        "gate_d_cleared_on_successor_line": bool(branch_status.get("gate_d_cleared_on_successor_line", False)),
        "gate_e_open_on_successor_line": bool(branch_status.get("gate_e_open", False)),
        "same_head_counted_reentry_admissible_now": bool(
            branch_status.get("same_head_counted_reentry_admissible_now", False)
        ),
        "gate_f_narrow_wedge_confirmed": True,
        "gate_f_open": False,
        "current_product_posture": common.GATE_F_CONFIRMED_POSTURE,
        "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
        "wedge_id": common.GATE_F_WEDGE_ID,
        "tenant_posture": _tenant_posture(deployment_receipt),
        "support_tier": str(scope_packet.get("support_boundary", {}).get("support_tier", "")).strip(),
    }
    packet = {
        "schema_id": "kt.operator.cohort0_gate_f_post_close_live_product_truth_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet freezes the canonical live product truth after Gate F one narrow wedge confirmation. "
            "It does not open Gate F into a broader platform, enterprise surface, or multi-tenant claim."
        ),
        "execution_status": EXECUTION_STATUS,
        "canonical_live_product_status": canonical_status,
        "governing_post_f_rule": (
            "Gate D cleared on the successor line, Gate E open on that line, and Gate F confirmed only as one "
            "single-tenant local verifier wedge. All product claims must stay narrower than that live stack."
        ),
        "what_changed": [
            "Gate F one narrow wedge is now frozen as canonical live product truth.",
            "The canonical product posture is now local verifier mode only.",
            "Live product posture is now anchored to the bounded current-head verifier-backed execute/receipt surface.",
        ],
        "what_did_not_change": [
            "Gate F did not open as a broad platform.",
            "No multi-tenant, enterprise, or cross-host claim was earned.",
            "Detached standalone package rerun was not upgraded into fresh current-head proof.",
            "Historical product surfaces remain preserved as historical lineage only.",
        ],
        "selected_wedge_summary": {
            "wedge_id": common.GATE_F_WEDGE_ID,
            "active_profile_id": common.ACTIVE_WEDGE_PROFILE_ID,
            "surface_summary": str(scope_packet.get("wedge_surface", {}).get("surface_summary", "")).strip(),
            "supported_actions": list(scope_packet.get("wedge_surface", {}).get("supported_actions", [])),
            "receipt_must_return": list(scope_packet.get("wedge_surface", {}).get("receipt_must_return", [])),
            "verify_command": str(scope_packet.get("wedge_mechanics", {}).get("verify_command", "")).strip(),
            "detached_command": str(scope_packet.get("wedge_mechanics", {}).get("detached_command", "")).strip(),
        },
        "validation_summary": {
            "scope_defined": str(scope_packet.get("scope_outcome", "")).strip(),
            "governance_bound": str(governance_contract.get("contract_outcome", "")).strip(),
            "deployment_smoke_status": str(deployment_receipt.get("wave_outcome", "")).strip(),
            "fresh_operator_bootstrap_status": str(bootstrap_receipt.get("wave_outcome", "")).strip(),
            "external_workload_pilot_status": str(pilot_receipt.get("pilot_outcome", "")).strip(),
            "buyer_safe_language_bound": str(language_receipt.get("language_outcome", "")).strip(),
            "wedge_screen_status": str(screen_receipt.get("screen_outcome", "")).strip(),
            "wedge_review_status": str(review_receipt.get("review_outcome", "")).strip(),
        },
        "authoritative_live_product_surfaces": source_refs,
        "next_lawful_move": common.NEXT_MOVE_POST_F_REAUDIT,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_post_close_live_product_truth_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "current_product_posture": common.GATE_F_CONFIRMED_POSTURE,
        "gate_f_narrow_wedge_confirmed": True,
        "gate_f_open": False,
        "next_lawful_move": common.NEXT_MOVE_POST_F_REAUDIT,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Gate F Post-Close Live Product Truth Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Current product posture: `{common.GATE_F_CONFIRMED_POSTURE}`",
            f"- Gate F narrow wedge confirmed: `True`",
            f"- Gate F open: `False`",
            f"- Active profile: `{common.ACTIVE_WEDGE_PROFILE_ID}`",
            f"- Tenant posture: `{canonical_status['tenant_posture']}`",
            f"- Next lawful move: `{common.NEXT_MOVE_POST_F_REAUDIT}`",
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
    deployment_receipt_path: Path,
    bootstrap_receipt_path: Path,
    pilot_receipt_path: Path,
    language_receipt_path: Path,
    screen_receipt_path: Path,
    review_packet_path: Path,
    review_receipt_path: Path,
) -> Dict[str, str]:
    root = repo_root()
    branch_law_packet = common.load_json_required(root, branch_law_packet_path, label="live branch law packet")
    supersession_note = common.load_json_required(root, supersession_note_path, label="live supersession note")
    orchestrator_receipt = common.load_json_required(root, orchestrator_receipt_path, label="live orchestrator receipt")
    scope_packet = common.load_json_required(root, scope_packet_path, label="Gate F scope packet")
    governance_contract = common.load_json_required(root, governance_contract_path, label="Gate F governance contract")
    deployment_receipt = common.load_json_required(root, deployment_receipt_path, label="Gate F deployment receipt")
    bootstrap_receipt = common.load_json_required(root, bootstrap_receipt_path, label="Gate F bootstrap receipt")
    pilot_receipt = common.load_json_required(root, pilot_receipt_path, label="Gate F pilot receipt")
    language_receipt = common.load_json_required(root, language_receipt_path, label="Gate F language receipt")
    screen_receipt = common.load_json_required(root, screen_receipt_path, label="Gate F screen receipt")
    review_packet = common.load_json_required(root, review_packet_path, label="Gate F review packet")
    review_receipt = common.load_json_required(root, review_receipt_path, label="Gate F review receipt")

    subject_head = common.ensure_live_post_e_state(
        branch_law_packet=branch_law_packet,
        supersession_note=supersession_note,
        orchestrator_receipt=orchestrator_receipt,
    )
    for payload, label in (
        (scope_packet, "Gate F scope packet"),
        (governance_contract, "Gate F governance contract"),
        (deployment_receipt, "Gate F deployment receipt"),
        (bootstrap_receipt, "Gate F bootstrap receipt"),
        (pilot_receipt, "Gate F pilot receipt"),
        (language_receipt, "Gate F language receipt"),
        (screen_receipt, "Gate F screen receipt"),
        (review_packet, "Gate F review packet"),
        (review_receipt, "Gate F review receipt"),
    ):
        common.ensure_pass(payload, label=label)

    if str(review_receipt.get("review_outcome", "")).strip() != review_tranche.OUTCOME_CONFIRMED:
        raise RuntimeError("FAIL_CLOSED: post-close live product truth requires a confirmed Gate F wedge review")
    if not bool(review_receipt.get("gate_f_narrow_wedge_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: post-close live product truth requires gate_f_narrow_wedge_confirmed=true")
    if bool(review_receipt.get("gate_f_open", True)):
        raise RuntimeError("FAIL_CLOSED: post-close live product truth must keep gate_f_open=false")
    if str(screen_receipt.get("screen_outcome", "")).strip() != screen_tranche.OUTCOME_AUTHORIZED:
        raise RuntimeError("FAIL_CLOSED: post-close live product truth requires wedge admissibility authorization")
    if _tenant_posture(deployment_receipt) != common.TENANT_POSTURE_SINGLE_ONLY:
        raise RuntimeError("FAIL_CLOSED: post-close live product truth requires single-tenant-only posture")

    source_refs = common.output_ref_dict(
        branch_law_packet=branch_law_packet_path,
        supersession_note=supersession_note_path,
        orchestrator_receipt=orchestrator_receipt_path,
        gate_f_scope_packet=scope_packet_path,
        gate_f_governance_contract=governance_contract_path,
        gate_f_deployment_receipt=deployment_receipt_path,
        gate_f_bootstrap_receipt=bootstrap_receipt_path,
        gate_f_pilot_receipt=pilot_receipt_path,
        gate_f_language_receipt=language_receipt_path,
        gate_f_screen_receipt=screen_receipt_path,
        gate_f_review_packet=review_packet_path,
        gate_f_review_receipt=review_receipt_path,
    )
    outputs = build_outputs(
        subject_head=subject_head,
        branch_law_packet=branch_law_packet,
        scope_packet=scope_packet,
        governance_contract=governance_contract,
        deployment_receipt=deployment_receipt,
        bootstrap_receipt=bootstrap_receipt,
        pilot_receipt=pilot_receipt,
        language_receipt=language_receipt,
        screen_receipt=screen_receipt,
        review_packet=review_packet,
        review_receipt=review_receipt,
        source_refs=source_refs,
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
        "current_product_posture": common.GATE_F_CONFIRMED_POSTURE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Freeze Gate F one narrow wedge as canonical live product truth.")
    parser.add_argument("--scope-packet", default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}")
    parser.add_argument("--governance-contract", default=f"{common.REPORTS_ROOT_REL}/{governance_tranche.OUTPUT_PACKET}")
    parser.add_argument("--deployment-receipt", default=f"{common.REPORTS_ROOT_REL}/{deploy_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--bootstrap-receipt", default=f"{common.REPORTS_ROOT_REL}/{bootstrap_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--pilot-receipt", default=f"{common.REPORTS_ROOT_REL}/{pilot_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--language-receipt", default=f"{common.REPORTS_ROOT_REL}/{language_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--screen-receipt", default=f"{common.REPORTS_ROOT_REL}/{screen_tranche.OUTPUT_RECEIPT}")
    parser.add_argument("--review-packet", default=f"{common.REPORTS_ROOT_REL}/{review_tranche.OUTPUT_PACKET}")
    parser.add_argument("--review-receipt", default=f"{common.REPORTS_ROOT_REL}/{review_tranche.OUTPUT_RECEIPT}")
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        branch_law_packet_path=common.resolve_path(root, args.branch_law_packet),
        supersession_note_path=common.resolve_path(root, args.supersession_note),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
        scope_packet_path=common.resolve_path(root, args.scope_packet),
        governance_contract_path=common.resolve_path(root, args.governance_contract),
        deployment_receipt_path=common.resolve_path(root, args.deployment_receipt),
        bootstrap_receipt_path=common.resolve_path(root, args.bootstrap_receipt),
        pilot_receipt_path=common.resolve_path(root, args.pilot_receipt),
        language_receipt_path=common.resolve_path(root, args.language_receipt),
        screen_receipt_path=common.resolve_path(root, args.screen_receipt),
        review_packet_path=common.resolve_path(root, args.review_packet),
        review_receipt_path=common.resolve_path(root, args.review_receipt),
    )
    print(result["current_product_posture"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
