from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_01_comparative_scope_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_01_comparative_scope_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_01_COMPARATIVE_SCOPE_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_TRACK_01_COMPARATIVE_SCOPE_BOUND"
SCOPE_OUTCOME = "POST_F_TRACK_01_COMPARATIVE_SCOPE_DEFINED__CANONICAL_WEDGE_ONLY"
TRACK_ID = "POST_F_TRACK_01_CANONICAL_COMPARATIVE_PROOF"
NEXT_MOVE = "AUTHOR_POST_F_TRACK_01_COMPARATOR_MATRIX_PACKET"


def _require_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _current_branch_name(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception:
        return "UNKNOWN_BRANCH"
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    branch_name: str,
    live_product_truth_packet: Dict[str, Any],
    post_f_reaudit_receipt: Dict[str, Any],
    post_merge_closeout_receipt: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    canonical_live_status = dict(live_product_truth_packet.get("canonical_live_product_status", {}))
    selected_surface = dict(live_product_truth_packet.get("selected_wedge_summary", {}))
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_comparative_scope_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet defines only the first post-F comparative-proof scope for the confirmed canonical "
            "local_verifier_mode wedge. It does not widen canonical product truth, does not promote broad model "
            "superiority claims, and remains non-authoritative until the protected canonical merge path lands."
        ),
        "execution_status": EXECUTION_STATUS,
        "scope_outcome": SCOPE_OUTCOME,
        "track_identity": {
            "track_id": TRACK_ID,
            "track_name": "Canonical Comparative Proof",
            "scope_first_track": True,
            "branch_type": "post_f_expansion_scope_only",
        },
        "authority_header": {
            "canonical_authority_branch": "main",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
            "gate_d_cleared_on_successor_line": bool(canonical_live_status.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(canonical_live_status.get("gate_e_open_on_successor_line", False)),
            "gate_f_open": bool(canonical_live_status.get("gate_f_open", False)),
            "gate_f_narrow_wedge_confirmed": bool(canonical_live_status.get("gate_f_narrow_wedge_confirmed", False)),
            "post_f_reaudit_passed": bool(post_f_reaudit_receipt.get("minimum_path_complete_through_gate_f", False)),
            "cleanup_closeout_merged_locally": str(post_merge_closeout_receipt.get("status", "")).strip()
            == "PASS__CANONICAL_CLEAN_CLOSEOUT_MERGED_TO_MAIN",
        },
        "confirmed_canonical_surface": {
            "wedge_id": str(selected_surface.get("wedge_id", "")).strip(),
            "active_profile_id": str(selected_surface.get("active_profile_id", "")).strip(),
            "surface_summary": str(selected_surface.get("surface_summary", "")).strip(),
            "verify_command": str(selected_surface.get("verify_command", "")).strip(),
            "receipt_must_return": list(selected_surface.get("receipt_must_return", [])),
            "supported_actions": list(selected_surface.get("supported_actions", [])),
            "support_tier": str(canonical_live_status.get("support_tier", "")).strip(),
            "tenant_posture": str(canonical_live_status.get("tenant_posture", "")).strip(),
        },
        "comparison_category": {
            "category_id": "GOVERNED_RECEIPT_BACKED_FAIL_CLOSED_EXECUTION_UNDER_LAW",
            "category_summary": (
                "Compare only within the bounded category already supported by the confirmed wedge: governed execution, "
                "receipt retrieval, replayability, and fail-closed operator trust."
            ),
            "proof_axes": [
                "receipt_quality",
                "replayability",
                "fail_closed_behavior",
                "operator_trust_boundary",
                "governed_execution_control",
            ],
        },
        "comparator_classes": [
            {
                "class_id": "INTERNAL_STATIC_BASELINE",
                "label": "strongest static internal baseline",
                "category_fair": True,
                "named_systems_allowed": False,
            },
            {
                "class_id": "INTERNAL_BEST_STATIC_ADAPTER",
                "label": "best static adapter baseline",
                "category_fair": True,
                "named_systems_allowed": False,
            },
            {
                "class_id": "EXTERNAL_MONOLITH_WORKFLOW",
                "label": "one simple external monolith workflow",
                "category_fair": True,
                "named_systems_allowed": True,
                "naming_rule": "Only name an external system when the workflow comparison is category-fair for the confirmed wedge.",
            },
        ],
        "first_wave_harness": {
            "participants": [
                "kt_canonical_local_verifier_wedge",
                "internal_static_baseline",
                "best_static_adapter_baseline",
                "one_external_monolith_workflow",
            ],
            "required_harness_components": [
                "route_proof_receipt_comparison_matrix",
                "bounded_operator_run_script",
                "receipt_quality_scorecard",
                "fail_closed_event_register",
            ],
            "fairness_guardrails": [
                "Compare only on the confirmed local_verifier_mode surface.",
                "Do not benchmark broad autonomy, creativity, or general intelligence.",
                "Do not import Kaggle or broader lobe-ratification workloads into Track 01.",
                "Do not let buyer language outrun the confirmed wedge boundary.",
            ],
        },
        "allowed_claims": [
            "control",
            "proof",
            "receipt_quality",
            "replayability",
            "fail_closed_behavior",
            "operator_trust",
        ],
        "forbidden_claims": [
            "best_ai_overall",
            "broad_model_superiority",
            "broad_creativity_superiority",
            "full_brain_or_civilization_superiority",
            "broad_platform_open",
        ],
        "non_claim_boundary": [
            "This packet does not widen Gate F beyond one narrow wedge.",
            "This packet does not alter the live Gate D/E/F truth spine.",
            "This packet does not authorize Kaggle, broader lobe ratification, or broad commercialization claims.",
        ],
        "source_refs": common.output_ref_dict(
            live_product_truth_packet=common.resolve_path(root, common.REPORTS_ROOT_REL + "/cohort0_gate_f_post_close_live_product_truth_packet.json"),
            post_f_reaudit_receipt=common.resolve_path(root, common.REPORTS_ROOT_REL + "/cohort0_post_f_broad_canonical_reaudit_receipt.json"),
            post_merge_closeout_receipt=common.resolve_path(root, common.REPORTS_ROOT_REL + "/cohort0_post_merge_closeout_receipt.json"),
            orchestrator_receipt=common.resolve_path(root, common.LIVE_ORCHESTRATOR_RECEIPT_REL),
        ),
        "subject_head": subject_head,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_01_comparative_scope_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "scope_outcome": SCOPE_OUTCOME,
        "track_id": TRACK_ID,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "confirmed_surface_wedge_id": packet["confirmed_canonical_surface"]["wedge_id"],
        "next_lawful_move": NEXT_MOVE,
        "subject_head": subject_head,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 01 Comparative Scope Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Scope outcome: `{SCOPE_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Confirmed wedge id: `{packet['confirmed_canonical_surface']['wedge_id']}`",
            f"- Comparison category: `{packet['comparison_category']['category_id']}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    live_product_truth_packet_path: Path,
    post_f_reaudit_receipt_path: Path,
    post_merge_closeout_receipt_path: Path,
    orchestrator_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    live_product_truth_packet = common.load_json_required(
        root,
        live_product_truth_packet_path,
        label="post-F live product truth packet",
    )
    post_f_reaudit_receipt = common.load_json_required(
        root,
        post_f_reaudit_receipt_path,
        label="post-F broad canonical re-audit receipt",
    )
    post_merge_closeout_receipt = common.load_json_required(
        root,
        post_merge_closeout_receipt_path,
        label="post-merge closeout receipt",
    )
    orchestrator_receipt = common.load_json_required(
        root,
        orchestrator_receipt_path,
        label="live orchestrator receipt",
    )

    _require_pass(live_product_truth_packet, label="post-F live product truth packet")
    _require_pass(post_f_reaudit_receipt, label="post-F broad canonical re-audit receipt")
    _require_pass(orchestrator_receipt, label="live orchestrator receipt")
    if str(post_merge_closeout_receipt.get("status", "")).strip() != "PASS__CANONICAL_CLEAN_CLOSEOUT_MERGED_TO_MAIN":
        raise RuntimeError("FAIL_CLOSED: post-merge closeout receipt must reflect the merged clean closeout state")

    canonical_live_status = dict(live_product_truth_packet.get("canonical_live_product_status", {}))
    if str(canonical_live_status.get("current_product_posture", "")).strip() != common.GATE_F_CONFIRMED_POSTURE:
        raise RuntimeError("FAIL_CLOSED: Track 01 requires the confirmed Gate F narrow wedge posture")
    if not bool(canonical_live_status.get("gate_f_narrow_wedge_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 requires the confirmed Gate F wedge")
    if bool(canonical_live_status.get("gate_f_open", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 assumes Gate F is still a narrow wedge, not broadly open")
    if not bool(post_f_reaudit_receipt.get("controlled_post_f_expansion_tracks_authorized_now", False)):
        raise RuntimeError("FAIL_CLOSED: Track 01 requires controlled post-F expansion authorization")
    if str(orchestrator_receipt.get("current_product_posture", "")).strip() != common.GATE_F_CONFIRMED_POSTURE:
        raise RuntimeError("FAIL_CLOSED: Track 01 requires the live orchestrator to reflect the confirmed wedge posture")

    subject_head = str(live_product_truth_packet.get("subject_head", "")).strip() or str(orchestrator_receipt.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 01 requires a subject head")

    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        branch_name=_current_branch_name(root),
        live_product_truth_packet=live_product_truth_packet,
        post_f_reaudit_receipt=post_f_reaudit_receipt,
        post_merge_closeout_receipt=post_merge_closeout_receipt,
        orchestrator_receipt=orchestrator_receipt,
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
        report_text=str(outputs["report"]),
    )
    return {
        "packet_path": packet_path.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "report_path": report_path.as_posix(),
        "scope_outcome": SCOPE_OUTCOME,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the post-F Track 01 comparative scope packet.")
    parser.add_argument(
        "--live-product-truth-packet",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json",
    )
    parser.add_argument(
        "--post-f-reaudit-receipt",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_broad_canonical_reaudit_receipt.json",
    )
    parser.add_argument(
        "--post-merge-closeout-receipt",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_merge_closeout_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        live_product_truth_packet_path=common.resolve_path(root, args.live_product_truth_packet),
        post_f_reaudit_receipt_path=common.resolve_path(root, args.post_f_reaudit_receipt),
        post_merge_closeout_receipt_path=common.resolve_path(root, args.post_merge_closeout_receipt),
        orchestrator_receipt_path=common.resolve_path(root, args.orchestrator_receipt),
    )
    print(result["scope_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
