from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_successor_anti_selection_stress_wave_tranche as anti_selection_wave
from tools.operator import (
    cohort0_successor_family_side_anti_selection_closure_wave_tranche as family_side_closure_wave,
)
from tools.operator import cohort0_successor_gate_d_narrow_admissibility_review_tranche as narrow_review
from tools.operator import cohort0_successor_route_consequence_severity_escalation_wave_tranche as severity_wave
from tools.operator import cohort0_successor_third_surface_breadth_witness_wave_tranche as third_surface_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_NARROW_REVIEW_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_PACKET}"
DEFAULT_NARROW_REVIEW_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_RECEIPT}"
DEFAULT_SEVERITY_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{severity_wave.OUTPUT_PACKET}"
DEFAULT_SEVERITY_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{severity_wave.OUTPUT_RECEIPT}"
DEFAULT_ANTI_SELECTION_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{anti_selection_wave.OUTPUT_PACKET}"
DEFAULT_ANTI_SELECTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{anti_selection_wave.OUTPUT_RECEIPT}"
DEFAULT_FAMILY_SIDE_CLOSURE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{family_side_closure_wave.OUTPUT_PACKET}"
DEFAULT_FAMILY_SIDE_CLOSURE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{family_side_closure_wave.OUTPUT_RECEIPT}"
DEFAULT_THIRD_SURFACE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{third_surface_wave.OUTPUT_PACKET}"
DEFAULT_THIRD_SURFACE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{third_surface_wave.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_full_gate_d_readjudication_authorization_screen_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_full_gate_d_readjudication_authorization_screen_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_FULL_GATE_D_READJUDICATION_AUTHORIZATION_SCREEN_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_FULL_GATE_D_READJUDICATION_AUTHORIZATION_SCREEN_EXECUTED"
STATUS_DEFERRED_ANTI_SELECTION = "DEFERRED__ANTI_SELECTION_BOUNDED_DEFECT_REMAINS"
STATUS_DEFERRED_GENERIC = "DEFERRED__SUCCESSOR_AUTHORIZATION_PREDICATES_NOT_YET_CLOSED"
STATUS_AUTHORIZED = "AUTHORIZED__FULL_SUCCESSOR_GATE_D_READJUDICATION_REVIEW_MAY_BE_CONVENED"
NEXT_MOVE_DEFERRED_ANTI_SELECTION = (
    "MAINTAIN_NARROW_SUCCESSOR_GATE_D_ADMISSIBILITY_POSTURE__ANTI_SELECTION_DEFECT_REMAINS"
)
NEXT_MOVE_DEFERRED_GENERIC = "MAINTAIN_NARROW_SUCCESSOR_GATE_D_ADMISSIBILITY_POSTURE__STILL_PRE_GATE_D"
NEXT_MOVE_AUTHORIZED = "AUTHORIZE_FULL_SUCCESSOR_GATE_D_READJUDICATION__STILL_NOT_GATE_D_REOPENED"


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


def _load_json_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: optional JSON must be an object when present: {path.as_posix()}")
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: optional JSON must have PASS status when present: {path.as_posix()}")
    return payload


def _require_same_subject_head(packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: full authorization screen requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    narrow_review_packet: Dict[str, Any],
    narrow_review_receipt: Dict[str, Any],
    severity_packet: Dict[str, Any],
    severity_receipt: Dict[str, Any],
    anti_selection_packet: Dict[str, Any],
    anti_selection_receipt: Dict[str, Any],
    family_side_closure_receipt: Optional[Dict[str, Any]],
    third_surface_packet: Dict[str, Any],
    third_surface_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (narrow_review_packet, "narrow review packet"),
        (narrow_review_receipt, "narrow review receipt"),
        (severity_packet, "severity wave packet"),
        (severity_receipt, "severity wave receipt"),
        (anti_selection_packet, "anti-selection wave packet"),
        (anti_selection_receipt, "anti-selection wave receipt"),
        (third_surface_packet, "third-surface wave packet"),
        (third_surface_receipt, "third-surface wave receipt"),
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

    if str(narrow_review_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED":
        raise RuntimeError("FAIL_CLOSED: narrow review must exist before full authorization screen")
    if not bool(narrow_review_receipt.get("narrow_successor_gate_d_admissibility_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: narrow admissibility must remain confirmed")
    if str(narrow_review_packet.get("review_outcome", "")).strip() != narrow_review.OUTCOME_CONFIRMED:
        raise RuntimeError("FAIL_CLOSED: narrow review outcome mismatch")

    if str(severity_receipt.get("execution_status", "")).strip() != severity_wave.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: severity wave receipt missing")
    if str(anti_selection_receipt.get("execution_status", "")).strip() != anti_selection_wave.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: anti-selection wave receipt missing")
    if isinstance(family_side_closure_receipt, dict) and str(
        family_side_closure_receipt.get("execution_status", "")
    ).strip() != family_side_closure_wave.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: family-side closure receipt execution status mismatch")
    if str(third_surface_receipt.get("execution_status", "")).strip() != third_surface_wave.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: third-surface wave receipt missing")


def _build_outputs(
    *,
    narrow_review_packet: Dict[str, Any],
    severity_packet: Dict[str, Any],
    severity_receipt: Dict[str, Any],
    anti_selection_packet: Dict[str, Any],
    anti_selection_receipt: Dict[str, Any],
    family_side_closure_packet: Optional[Dict[str, Any]],
    family_side_closure_receipt: Optional[Dict[str, Any]],
    third_surface_packet: Dict[str, Any],
    third_surface_receipt: Dict[str, Any],
    subject_head: str,
    source_refs: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    severity_closed = bool(severity_receipt.get("severity_escalation_route_consequence_wave_closed", False))
    anti_selection_closed = bool(anti_selection_receipt.get("anti_selection_wave_beyond_reserve_closed", False))
    if isinstance(family_side_closure_receipt, dict):
        anti_selection_closed = anti_selection_closed or bool(
            family_side_closure_receipt.get("anti_selection_wave_beyond_reserve_closed", False)
        )
    third_surface_closed = bool(third_surface_receipt.get("third_surface_breadth_witness_closed", False))
    if isinstance(family_side_closure_receipt, dict):
        remaining_bounded_defects = list(family_side_closure_receipt.get("bounded_defects_remaining", []))
    elif isinstance(family_side_closure_packet, dict):
        remaining_bounded_defects = list(family_side_closure_packet.get("bounded_defects_remaining", []))
    else:
        remaining_bounded_defects = list(anti_selection_packet.get("bounded_defects_remaining", []))

    full_authorized = severity_closed and anti_selection_closed and third_surface_closed
    if full_authorized:
        screen_status = STATUS_AUTHORIZED
        next_lawful_move = NEXT_MOVE_AUTHORIZED
        remaining_predicates: list[str] = []
    elif remaining_bounded_defects:
        screen_status = STATUS_DEFERRED_ANTI_SELECTION
        next_lawful_move = NEXT_MOVE_DEFERRED_ANTI_SELECTION
        remaining_predicates = (
            ["family_side_anti_selection_defect_closed"]
            if isinstance(family_side_closure_receipt, dict) or isinstance(family_side_closure_packet, dict)
            else ["anti_selection_wave_beyond_reserve_closed"]
        )
    else:
        screen_status = STATUS_DEFERRED_GENERIC
        next_lawful_move = NEXT_MOVE_DEFERRED_GENERIC
        remaining_predicates = [
            name
            for name, flag in (
                ("severity_escalation_route_consequence_wave_closed", severity_closed),
                ("anti_selection_wave_beyond_reserve_closed", anti_selection_closed),
                ("third_surface_breadth_witness_closed", third_surface_closed),
            )
            if not flag
        ]

    packet = {
        "schema_id": "kt.operator.cohort0_successor_full_gate_d_readjudication_authorization_screen_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This screen decides only whether the successor line has earned full Gate D readjudication authorization. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "full_successor_gate_d_readjudication_authorization_screen_status": screen_status,
        "authorization_findings": {
            "narrow_successor_gate_d_admissibility_confirmed": bool(
                narrow_review_packet.get("narrow_successor_gate_d_admissibility_confirmed", False)
            ),
            "severity_escalation_route_consequence_wave_closed": severity_closed,
            "anti_selection_wave_beyond_reserve_closed": anti_selection_closed,
            "family_side_anti_selection_defect_closed": (
                bool(family_side_closure_receipt.get("family_side_anti_selection_defect_closed", False))
                if isinstance(family_side_closure_receipt, dict)
                else False
            ),
            "third_surface_breadth_witness_closed": third_surface_closed,
            "selected_bridge_locked": bool(
                narrow_review_packet.get("review_basis", {}).get("selected_successor_core", {}).get("lead_bridge_candidate_id", "")
                == "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1"
            ),
            "fixed_harness_locked": True,
            "same_head_comparator_locked": bool(
                narrow_review_packet.get("review_basis", {}).get("selected_successor_core", {}).get("same_head_comparator_mode", "")
                == "LOCKED__STATIC_ALPHA_COMPARATOR"
            ),
        },
        "remaining_authorization_predicates": remaining_predicates,
        "remaining_bounded_defects": remaining_bounded_defects,
        "full_successor_gate_d_readjudication_authorized_now": full_authorized,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": next_lawful_move,
        "source_refs": source_refs,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_successor_full_gate_d_readjudication_authorization_screen_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "full_successor_gate_d_readjudication_authorization_screen_status": screen_status,
        "full_successor_gate_d_readjudication_authorization_screen_executed": True,
        "full_successor_gate_d_readjudication_authorized_now": full_authorized,
        "remaining_authorization_predicates": remaining_predicates,
        "remaining_bounded_defects": remaining_bounded_defects,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": next_lawful_move,
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    findings = dict(packet.get("authorization_findings", {}))
    return (
        "# Cohort0 Successor Full Gate D Readjudication Authorization Screen Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Screen status: `{receipt.get('full_successor_gate_d_readjudication_authorization_screen_status', '')}`\n"
        f"- Full successor Gate D readjudication authorized now: `{receipt.get('full_successor_gate_d_readjudication_authorized_now', False)}`\n"
        f"- Remaining authorization predicates: `{receipt.get('remaining_authorization_predicates', [])}`\n"
        f"- Remaining bounded defects: `{receipt.get('remaining_bounded_defects', [])}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', False)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Authorization Findings\n"
        f"- Narrow admissibility confirmed: `{findings.get('narrow_successor_gate_d_admissibility_confirmed', False)}`\n"
        f"- Severity wave closed: `{findings.get('severity_escalation_route_consequence_wave_closed', False)}`\n"
        f"- Anti-selection closed beyond reserve: `{findings.get('anti_selection_wave_beyond_reserve_closed', False)}`\n"
        f"- Third-surface breadth witness closed: `{findings.get('third_surface_breadth_witness_closed', False)}`\n"
        f"- Selected bridge locked: `{findings.get('selected_bridge_locked', False)}`\n"
        f"- Fixed harness locked: `{findings.get('fixed_harness_locked', False)}`\n"
        f"- Same-head comparator locked: `{findings.get('same_head_comparator_locked', False)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    narrow_review_packet_path: Path,
    narrow_review_receipt_path: Path,
    severity_packet_path: Path,
    severity_receipt_path: Path,
    anti_selection_packet_path: Path,
    anti_selection_receipt_path: Path,
    family_side_closure_packet_path: Optional[Path] = None,
    family_side_closure_receipt_path: Optional[Path] = None,
    third_surface_packet_path: Path,
    third_surface_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    narrow_review_packet = _load_json_required(narrow_review_packet_path, label="narrow review packet")
    narrow_review_receipt = _load_json_required(narrow_review_receipt_path, label="narrow review receipt")
    severity_packet = _load_json_required(severity_packet_path, label="severity packet")
    severity_receipt = _load_json_required(severity_receipt_path, label="severity receipt")
    anti_selection_packet = _load_json_required(anti_selection_packet_path, label="anti-selection packet")
    anti_selection_receipt = _load_json_required(anti_selection_receipt_path, label="anti-selection receipt")
    family_side_closure_packet = _load_json_optional(family_side_closure_packet_path) if family_side_closure_packet_path else None
    family_side_closure_receipt = _load_json_optional(family_side_closure_receipt_path) if family_side_closure_receipt_path else None
    third_surface_packet = _load_json_required(third_surface_packet_path, label="third-surface packet")
    third_surface_receipt = _load_json_required(third_surface_receipt_path, label="third-surface receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        narrow_review_packet=narrow_review_packet,
        narrow_review_receipt=narrow_review_receipt,
        severity_packet=severity_packet,
        severity_receipt=severity_receipt,
        anti_selection_packet=anti_selection_packet,
        anti_selection_receipt=anti_selection_receipt,
        family_side_closure_receipt=family_side_closure_receipt,
        third_surface_packet=third_surface_packet,
        third_surface_receipt=third_surface_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            narrow_review_packet,
            narrow_review_receipt,
            severity_packet,
            severity_receipt,
            anti_selection_packet,
            anti_selection_receipt,
            family_side_closure_packet,
            family_side_closure_receipt,
            third_surface_packet,
            third_surface_receipt,
        )
    )

    source_refs = {
        "verdict_packet_ref": verdict_packet_path.as_posix(),
        "reentry_block_ref": reentry_block_path.as_posix(),
        "narrow_review_packet_ref": narrow_review_packet_path.as_posix(),
        "narrow_review_receipt_ref": narrow_review_receipt_path.as_posix(),
        "severity_packet_ref": severity_packet_path.as_posix(),
        "severity_receipt_ref": severity_receipt_path.as_posix(),
        "anti_selection_packet_ref": anti_selection_packet_path.as_posix(),
        "anti_selection_receipt_ref": anti_selection_receipt_path.as_posix(),
        "third_surface_packet_ref": third_surface_packet_path.as_posix(),
        "third_surface_receipt_ref": third_surface_receipt_path.as_posix(),
    }
    if family_side_closure_packet_path and isinstance(family_side_closure_packet, dict):
        source_refs["family_side_closure_packet_ref"] = family_side_closure_packet_path.as_posix()
    if family_side_closure_receipt_path and isinstance(family_side_closure_receipt, dict):
        source_refs["family_side_closure_receipt_ref"] = family_side_closure_receipt_path.as_posix()

    outputs = _build_outputs(
        narrow_review_packet=narrow_review_packet,
        severity_packet=severity_packet,
        severity_receipt=severity_receipt,
        anti_selection_packet=anti_selection_packet,
        anti_selection_receipt=anti_selection_receipt,
        family_side_closure_packet=family_side_closure_packet,
        family_side_closure_receipt=family_side_closure_receipt,
        third_surface_packet=third_surface_packet,
        third_surface_receipt=third_surface_receipt,
        subject_head=subject_head,
        source_refs=source_refs,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(packet=outputs["packet"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "full_successor_gate_d_readjudication_authorized_now": outputs["receipt"][
            "full_successor_gate_d_readjudication_authorized_now"
        ],
        "screen_status": outputs["receipt"]["full_successor_gate_d_readjudication_authorization_screen_status"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the successor full Gate D readjudication authorization screen on the post-limited-review wave bundle."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--narrow-review-packet", default=DEFAULT_NARROW_REVIEW_PACKET_REL)
    parser.add_argument("--narrow-review-receipt", default=DEFAULT_NARROW_REVIEW_RECEIPT_REL)
    parser.add_argument("--severity-packet", default=DEFAULT_SEVERITY_PACKET_REL)
    parser.add_argument("--severity-receipt", default=DEFAULT_SEVERITY_RECEIPT_REL)
    parser.add_argument("--anti-selection-packet", default=DEFAULT_ANTI_SELECTION_PACKET_REL)
    parser.add_argument("--anti-selection-receipt", default=DEFAULT_ANTI_SELECTION_RECEIPT_REL)
    parser.add_argument("--family-side-closure-packet", default=DEFAULT_FAMILY_SIDE_CLOSURE_PACKET_REL)
    parser.add_argument("--family-side-closure-receipt", default=DEFAULT_FAMILY_SIDE_CLOSURE_RECEIPT_REL)
    parser.add_argument("--third-surface-packet", default=DEFAULT_THIRD_SURFACE_PACKET_REL)
    parser.add_argument("--third-surface-receipt", default=DEFAULT_THIRD_SURFACE_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        narrow_review_packet_path=_resolve(root, args.narrow_review_packet),
        narrow_review_receipt_path=_resolve(root, args.narrow_review_receipt),
        severity_packet_path=_resolve(root, args.severity_packet),
        severity_receipt_path=_resolve(root, args.severity_receipt),
        anti_selection_packet_path=_resolve(root, args.anti_selection_packet),
        anti_selection_receipt_path=_resolve(root, args.anti_selection_receipt),
        family_side_closure_packet_path=_resolve(root, args.family_side_closure_packet),
        family_side_closure_receipt_path=_resolve(root, args.family_side_closure_receipt),
        third_surface_packet_path=_resolve(root, args.third_surface_packet),
        third_surface_receipt_path=_resolve(root, args.third_surface_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "full_successor_gate_d_readjudication_authorized_now",
        "screen_status",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
