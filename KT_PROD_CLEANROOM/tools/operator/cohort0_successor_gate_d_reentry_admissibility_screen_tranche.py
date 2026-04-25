from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_gate_d_successor_execution_charter_tranche as successor_charter
from tools.operator import cohort0_successor_reentry_prep_packet_tranche as prep_packet_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_SUCCESSOR_REENTRY_CONTRACT_REL = (
    f"KT_PROD_CLEANROOM/reports/{successor_charter.OUTPUT_SUCCESSOR_REENTRY_CONTRACT}"
)
DEFAULT_SUCCESSOR_READJUDICATION_MANIFEST_REL = (
    f"KT_PROD_CLEANROOM/reports/{successor_charter.OUTPUT_READJUDICATION_MANIFEST}"
)
DEFAULT_PREP_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{prep_packet_tranche.OUTPUT_PACKET}"
DEFAULT_PREP_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{prep_packet_tranche.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_gate_d_reentry_admissibility_screen_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_gate_d_reentry_admissibility_screen_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_GATE_D_REENTRY_ADMISSIBILITY_SCREEN_REPORT.md"

NEXT_LAWFUL_MOVE = "CONVENE_SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW__STILL_PRE_GATE_D"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object: {path.as_posix()}")
    return payload


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _require_same_subject_head(packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: successor admissibility screen requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    successor_reentry_contract: Dict[str, Any],
    successor_readjudication_manifest: Dict[str, Any],
    prep_packet: Dict[str, Any],
    prep_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (successor_reentry_contract, "successor gate d reentry contract"),
        (successor_readjudication_manifest, "successor gate d readjudication manifest"),
        (prep_packet, "successor reentry-prep packet"),
        (prep_receipt, "successor reentry-prep receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain blocked")
    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block must remain active")

    if str(successor_reentry_contract.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: successor reentry contract must remain authorized-only")
    if str(successor_readjudication_manifest.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: successor readjudication manifest must remain authorized-only")

    if str(prep_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_REENTRY_PREP_PACKET_AUTHORED":
        raise RuntimeError("FAIL_CLOSED: successor reentry-prep receipt must exist")
    if not bool(prep_receipt.get("successor_reentry_prep_packet_authored", False)):
        raise RuntimeError("FAIL_CLOSED: successor reentry-prep packet must be authored before admissibility screen")
    if str(prep_receipt.get("next_lawful_move", "")).strip() != prep_packet_tranche.NEXT_LAWFUL_MOVE:
        raise RuntimeError("FAIL_CLOSED: successor reentry-prep next move mismatch")

    for receipt in (prep_receipt,):
        if bool(receipt.get("same_head_counted_reentry_admissible_now", True)):
            raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering admissibility screen")
        if bool(receipt.get("gate_d_reopened", True)):
            raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering admissibility screen")
        if bool(receipt.get("gate_e_open", True)):
            raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering admissibility screen")

    boundary = dict(prep_packet.get("authority_and_boundary_header", {}))
    if not bool(boundary.get("no_counted_claim_earned_yet", False)):
        raise RuntimeError("FAIL_CLOSED: prep packet must explicitly remain non-counted")
    if str(boundary.get("packet_status", "")).strip() != "STRICTLY_PRE_GATE_D_ONLY":
        raise RuntimeError("FAIL_CLOSED: prep packet must remain strictly pre-Gate-D only")


def _build_outputs(
    *,
    subject_head: str,
    prep_packet: Dict[str, Any],
    source_refs: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    selected_core = dict(prep_packet.get("selected_successor_core", {}))
    lane_a = dict(prep_packet.get("lane_a_evidence_spine", {}))
    lane_b = dict(prep_packet.get("lane_b_evidence_spine", {}))
    compare = dict(prep_packet.get("cross_lane_comparative_verdict_section", {}))
    reserve = dict(prep_packet.get("reserve_challenge_closure_section", {}))
    harness_totals = dict(selected_core.get("fixed_harness_global_totals", {}))

    fixed_harness_stable = (
        float(harness_totals.get("forced_wrong_route_total_cost", 0.0)) > 0.0
        and float(harness_totals.get("witness_ablation_total_cost", 0.0)) > 0.0
        and float(harness_totals.get("static_hold_control_total_cost", 1.0)) == 0.0
    )

    narrow_review_authorized = (
        float(lane_a.get("full_panel_metrics", {}).get("selected_bridge_reason_exact_accuracy", 0.0)) >= 1.0
        and float(lane_a.get("full_panel_metrics", {}).get("selected_bridge_reason_admissible_accuracy", 0.0)) >= 1.0
        and float(lane_b.get("overall_metrics", {}).get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
        and float(lane_b.get("overall_metrics", {}).get("bridge_reason_admissible_accuracy", 0.0)) >= 1.0
        and float(lane_b.get("route_consequence_visibility_summary", {}).get("overall_rate", 0.0)) >= 1.0
        and bool(compare.get("lane_b_counts_as_materially_distinct_executed_theorem_strengthening_evidence", False))
        and bool(compare.get("dominance_broadening_visible", False))
        and bool(reserve.get("reserve_challenges_pass", False))
        and fixed_harness_stable
    )

    packet = {
        "schema_id": "kt.operator.cohort0_successor_gate_d_reentry_admissibility_screen_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This screen decides only whether the successor pre-Gate-D packet is strong enough to authorize a narrow successor "
            "Gate D admissibility review. It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": "PASS__SUCCESSOR_GATE_D_REENTRY_ADMISSIBILITY_SCREEN_EXECUTED",
        "screen_findings": {
            "selected_bridge_cross_lane_hold": (
                float(lane_a.get("full_panel_metrics", {}).get("selected_bridge_reason_exact_accuracy", 0.0)) >= 1.0
                and float(lane_b.get("overall_metrics", {}).get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
            ),
            "route_consequence_cross_lane_nonzero": (
                float(lane_b.get("route_consequence_visibility_summary", {}).get("overall_rate", 0.0)) >= 1.0
                and fixed_harness_stable
            ),
            "dominance_broadening_visible": bool(compare.get("dominance_broadening_visible", False)),
            "materially_distinct_family_lane_executed": bool(
                compare.get("lane_b_counts_as_materially_distinct_executed_theorem_strengthening_evidence", False)
            ),
            "reserve_challenges_pass": bool(reserve.get("reserve_challenges_pass", False)),
            "fixed_harness_stable": fixed_harness_stable,
        },
        "narrow_successor_gate_d_admissibility_review_authorized": narrow_review_authorized,
        "broad_same_head_counted_reentry_block_remains": True,
        "full_successor_gate_d_readjudication_authorized_now": False,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": (
            NEXT_LAWFUL_MOVE
            if narrow_review_authorized
            else "RUN_ADDITIONAL_STRENGTHENING_WAVE_BEFORE_NARROW_ADMISSIBILITY_REVIEW"
        ),
        "source_refs": source_refs,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_successor_gate_d_reentry_admissibility_screen_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": packet["execution_status"],
        "narrow_successor_gate_d_admissibility_review_authorized": narrow_review_authorized,
        "broad_same_head_counted_reentry_block_remains": True,
        "full_successor_gate_d_readjudication_authorized_now": False,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": packet["next_lawful_move"],
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    findings = dict(packet.get("screen_findings", {}))
    return (
        "# Cohort0 Successor Gate D Reentry Admissibility Screen Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Narrow admissibility review authorized: `{receipt.get('narrow_successor_gate_d_admissibility_review_authorized', False)}`\n"
        f"- Broad counted reentry block remains: `{receipt.get('broad_same_head_counted_reentry_block_remains', False)}`\n"
        f"- Full Gate D readjudication authorized now: `{receipt.get('full_successor_gate_d_readjudication_authorized_now', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', True)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', True)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', True)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Screen Findings\n"
        f"- Selected bridge cross-lane hold: `{findings.get('selected_bridge_cross_lane_hold', False)}`\n"
        f"- Route consequence cross-lane nonzero: `{findings.get('route_consequence_cross_lane_nonzero', False)}`\n"
        f"- Dominance broadening visible: `{findings.get('dominance_broadening_visible', False)}`\n"
        f"- Materially distinct family lane executed: `{findings.get('materially_distinct_family_lane_executed', False)}`\n"
        f"- Reserve challenges pass: `{findings.get('reserve_challenges_pass', False)}`\n"
        f"- Fixed harness stable: `{findings.get('fixed_harness_stable', False)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    successor_reentry_contract_path: Path,
    successor_readjudication_manifest_path: Path,
    prep_packet_path: Path,
    prep_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    successor_reentry_contract = _load_json_required(
        successor_reentry_contract_path, label="successor gate d reentry contract"
    )
    successor_readjudication_manifest = _load_json_required(
        successor_readjudication_manifest_path, label="successor gate d readjudication manifest"
    )
    prep_packet = _load_json_required(prep_packet_path, label="successor reentry-prep packet")
    prep_receipt = _load_json_required(prep_receipt_path, label="successor reentry-prep receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        successor_reentry_contract=successor_reentry_contract,
        successor_readjudication_manifest=successor_readjudication_manifest,
        prep_packet=prep_packet,
        prep_receipt=prep_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            successor_reentry_contract,
            successor_readjudication_manifest,
            prep_packet,
            prep_receipt,
        )
    )

    source_refs = {
        "verdict_packet_ref": verdict_packet_path.as_posix(),
        "reentry_block_ref": reentry_block_path.as_posix(),
        "successor_reentry_contract_ref": successor_reentry_contract_path.as_posix(),
        "successor_readjudication_manifest_ref": successor_readjudication_manifest_path.as_posix(),
        "successor_reentry_prep_packet_ref": prep_packet_path.as_posix(),
        "successor_reentry_prep_receipt_ref": prep_receipt_path.as_posix(),
    }
    outputs = _build_outputs(subject_head=subject_head, prep_packet=prep_packet, source_refs=source_refs)

    reports_root.mkdir(parents=True, exist_ok=True)
    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(packet=outputs["packet"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": outputs["receipt"]["execution_status"],
        "narrow_successor_gate_d_admissibility_review_authorized": outputs["receipt"][
            "narrow_successor_gate_d_admissibility_review_authorized"
        ],
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute the successor Gate D reentry admissibility screen on the authored pre-Gate-D prep packet."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--successor-reentry-contract", default=DEFAULT_SUCCESSOR_REENTRY_CONTRACT_REL)
    parser.add_argument("--successor-readjudication-manifest", default=DEFAULT_SUCCESSOR_READJUDICATION_MANIFEST_REL)
    parser.add_argument("--prep-packet", default=DEFAULT_PREP_PACKET_REL)
    parser.add_argument("--prep-receipt", default=DEFAULT_PREP_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        successor_reentry_contract_path=_resolve(root, args.successor_reentry_contract),
        successor_readjudication_manifest_path=_resolve(root, args.successor_readjudication_manifest),
        prep_packet_path=_resolve(root, args.prep_packet),
        prep_receipt_path=_resolve(root, args.prep_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "narrow_successor_gate_d_admissibility_review_authorized",
        "next_lawful_move",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
