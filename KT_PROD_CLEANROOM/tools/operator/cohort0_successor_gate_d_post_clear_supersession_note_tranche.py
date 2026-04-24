from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator import cohort0_successor_gate_d_post_clear_branch_law_tranche as post_clear_branch_law
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_POST_CLEAR_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_PACKET}"
DEFAULT_POST_CLEAR_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_RECEIPT}"
DEFAULT_FULL_READJUDICATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_readjudication.OUTPUT_RECEIPT}"
DEFAULT_ORCHESTRATOR_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json"
DEFAULT_GATE_E_SCREEN_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_e_admissibility_screen_receipt.json"
DEFAULT_HISTORICAL_STATUS_SECTION_REL = "KT_PROD_CLEANROOM/reports/cohort0_v11_current_status_section.json"
DEFAULT_HISTORICAL_BLOCKER_BOARD_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_parallel_blocker_board.json"
DEFAULT_HISTORICAL_STATUS_AUDIT_REL = "KT_PROD_CLEANROOM/reports/cohort0_v11_gate_d_status_audit_packet.json"
DEFAULT_HISTORICAL_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_REPORTS_ROOT_REL = post_clear_branch_law.DEFAULT_REPORTS_ROOT_REL

OUTPUT_NOTE = "cohort0_successor_gate_d_post_clear_supersession_note.json"
OUTPUT_RECEIPT = "cohort0_successor_gate_d_post_clear_supersession_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_GATE_D_POST_CLEAR_SUPERSESSION_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_GATE_D_POST_CLEAR_SUPERSESSION_BOUND"
GATE_E_OPEN_OUTCOME = "GATE_E_OPENED__SUCCESSOR_LINE"
GATE_E_OPEN_NEXT_MOVE = "MAINTAIN_GATE_E_OPEN_POSTURE__POST_SUCCESSOR_LINE_CLEAR"


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
        raise RuntimeError("FAIL_CLOSED: post-clear supersession note requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    post_clear_packet: Dict[str, Any],
    post_clear_receipt: Dict[str, Any],
    full_readjudication_receipt: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
    gate_e_screen_receipt: Optional[Dict[str, Any]],
    historical_status_section: Dict[str, Any],
    historical_blocker_board: Dict[str, Any],
    historical_status_audit: Dict[str, Any],
    historical_overlay: Dict[str, Any],
) -> None:
    for payload, label in (
        (post_clear_packet, "post-clear branch law packet"),
        (post_clear_receipt, "post-clear branch law receipt"),
        (full_readjudication_receipt, "full successor Gate D readjudication receipt"),
        (orchestrator_receipt, "successor master orchestrator receipt"),
        (historical_status_section, "historical v11 status section"),
        (historical_blocker_board, "historical blocker board"),
        (historical_status_audit, "historical status audit"),
    ):
        _ensure_pass(payload, label=label)
    if not str(historical_overlay.get("schema_id", "")).strip():
        raise RuntimeError("FAIL_CLOSED: historical current campaign overlay must remain a JSON carrier surface")

    if not bool(post_clear_receipt.get("gate_d_cleared_on_successor_line", False)):
        raise RuntimeError("FAIL_CLOSED: post-clear branch law must already record the Gate D clear")
    if str(full_readjudication_receipt.get("readjudication_outcome", "")).strip() != full_readjudication.OUTCOME_CLEARED:
        raise RuntimeError("FAIL_CLOSED: supersession note requires successor Gate D clear")
    if bool(isinstance(gate_e_screen_receipt, dict) and gate_e_screen_receipt.get("gate_e_open", False)):
        if str(gate_e_screen_receipt.get("screen_outcome", "")).strip() != GATE_E_OPEN_OUTCOME:
            raise RuntimeError("FAIL_CLOSED: open-state supersession note requires an open Gate E screen receipt")
        if str(orchestrator_receipt.get("current_branch_posture", "")).strip() != post_clear_branch_law.OPEN_POSTURE:
            raise RuntimeError("FAIL_CLOSED: open-state supersession note requires open-state orchestrator posture")


def _build_outputs(
    *,
    subject_head: str,
    source_refs: Dict[str, str],
    orchestrator_receipt: Dict[str, Any],
    gate_e_screen_receipt: Optional[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    gate_e_open_now = bool(isinstance(gate_e_screen_receipt, dict) and gate_e_screen_receipt.get("gate_e_open", False))
    next_lawful_move = str(orchestrator_receipt.get("next_lawful_move", "")).strip() or (
        GATE_E_OPEN_NEXT_MOVE if gate_e_open_now else full_readjudication.NEXT_MOVE_CLEARED
    )
    note = {
        "schema_id": "kt.operator.cohort0_successor_gate_d_post_clear_supersession_note.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This note binds the historical supersession rule after successor Gate D clear "
            "and any later lawful Gate E movement. It preserves the older hardened-ceiling truth as history "
            "while freezing the new live authority stack."
        ),
        "execution_status": EXECUTION_STATUS,
        "historical_failure_not_erased": True,
        "prior_same_head_lane_closure_historically_valid": True,
        "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture": True,
        "supersession_rule": (
            "The earlier same-head failure remains historically true. "
            "For live branch posture only, it is superseded by the successor Gate D clear receipt, the recomputed orchestrator, "
            "and any later lawful Gate E receipt."
        ),
        "authoritative_live_surfaces_now": [
            source_refs["full_readjudication_receipt_ref"],
            source_refs["orchestrator_receipt_ref"],
            source_refs["post_clear_packet_ref"],
            source_refs["post_clear_receipt_ref"],
            *(
                [source_refs["gate_e_screen_receipt_ref"]]
                if gate_e_open_now and "gate_e_screen_receipt_ref" in source_refs
                else []
            ),
        ],
        "historically_valid_but_live_superseded_surfaces": [
            source_refs["historical_status_section_ref"],
            source_refs["historical_blocker_board_ref"],
            source_refs["historical_status_audit_ref"],
            source_refs["historical_overlay_ref"],
        ],
        "next_lawful_move": next_lawful_move,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_successor_gate_d_post_clear_supersession_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": note["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "historical_failure_not_erased": True,
        "prior_same_head_lane_closure_historically_valid": True,
        "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture": True,
        "next_lawful_move": note["next_lawful_move"],
        "subject_head": subject_head,
    }
    return {"note": note, "receipt": receipt}


def _build_report(*, note: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    live_lines = "\n".join(f"- `{item}`" for item in note.get("authoritative_live_surfaces_now", []))
    historical_lines = "\n".join(
        f"- `{item}`" for item in note.get("historically_valid_but_live_superseded_surfaces", [])
    )
    return (
        "# Cohort0 Successor Gate D Post-Clear Supersession Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Historical failure not erased: `{receipt.get('historical_failure_not_erased', False)}`\n"
        f"- Prior same-head lane closure historically valid: `{receipt.get('prior_same_head_lane_closure_historically_valid', False)}`\n"
        f"- Successor line supersedes prior failure for live posture: `{receipt.get('successor_line_supersedes_prior_same_head_failure_for_live_branch_posture', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Authoritative Live Surfaces Now\n"
        f"{live_lines}\n\n"
        "## Historically Valid But Live-Superseded Surfaces\n"
        f"{historical_lines}\n"
    )


def run(
    *,
    post_clear_packet_path: Path,
    post_clear_receipt_path: Path,
    full_readjudication_receipt_path: Path,
    orchestrator_receipt_path: Path,
    gate_e_screen_receipt_path: Optional[Path] = None,
    historical_status_section_path: Path,
    historical_blocker_board_path: Path,
    historical_status_audit_path: Path,
    historical_overlay_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    post_clear_packet = _load_json_required(post_clear_packet_path, label="post-clear branch law packet")
    post_clear_receipt = _load_json_required(post_clear_receipt_path, label="post-clear branch law receipt")
    full_readjudication_receipt = _load_json_required(
        full_readjudication_receipt_path, label="full successor Gate D readjudication receipt"
    )
    orchestrator_receipt = _load_json_required(orchestrator_receipt_path, label="successor master orchestrator receipt")
    gate_e_screen_receipt = _load_json_required(
        gate_e_screen_receipt_path, label="Gate E admissibility screen receipt"
    ) if gate_e_screen_receipt_path and gate_e_screen_receipt_path.is_file() else None
    historical_status_section = _load_json_required(
        historical_status_section_path, label="historical v11 status section"
    )
    historical_blocker_board = _load_json_required(
        historical_blocker_board_path, label="historical blocker board"
    )
    historical_status_audit = _load_json_required(
        historical_status_audit_path, label="historical status audit"
    )
    historical_overlay = _load_json_required(historical_overlay_path, label="historical current campaign overlay")

    _validate_inputs(
        post_clear_packet=post_clear_packet,
        post_clear_receipt=post_clear_receipt,
        full_readjudication_receipt=full_readjudication_receipt,
        orchestrator_receipt=orchestrator_receipt,
        gate_e_screen_receipt=gate_e_screen_receipt,
        historical_status_section=historical_status_section,
        historical_blocker_board=historical_blocker_board,
        historical_status_audit=historical_status_audit,
        historical_overlay=historical_overlay,
    )
    subject_head = _require_same_subject_head(
        (
            post_clear_packet,
            post_clear_receipt,
            full_readjudication_receipt,
            orchestrator_receipt,
            historical_status_section,
            historical_blocker_board,
            historical_status_audit,
            historical_overlay,
        )
    )
    source_refs = {
        "post_clear_packet_ref": post_clear_packet_path.as_posix(),
        "post_clear_receipt_ref": post_clear_receipt_path.as_posix(),
        "full_readjudication_receipt_ref": full_readjudication_receipt_path.as_posix(),
        "orchestrator_receipt_ref": orchestrator_receipt_path.as_posix(),
        **(
            {"gate_e_screen_receipt_ref": gate_e_screen_receipt_path.as_posix()}
            if gate_e_screen_receipt_path and isinstance(gate_e_screen_receipt, dict)
            else {}
        ),
        "historical_status_section_ref": historical_status_section_path.as_posix(),
        "historical_blocker_board_ref": historical_blocker_board_path.as_posix(),
        "historical_status_audit_ref": historical_status_audit_path.as_posix(),
        "historical_overlay_ref": historical_overlay_path.as_posix(),
    }
    outputs = _build_outputs(
        subject_head=subject_head,
        source_refs=source_refs,
        orchestrator_receipt=orchestrator_receipt,
        gate_e_screen_receipt=gate_e_screen_receipt,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    note_path = reports_root / OUTPUT_NOTE
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(note_path, outputs["note"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(note=outputs["note"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "historical_failure_not_erased": True,
        "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture": True,
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bind the post-clear supersession note after successor Gate D clear.")
    parser.add_argument("--post-clear-packet", default=DEFAULT_POST_CLEAR_PACKET_REL)
    parser.add_argument("--post-clear-receipt", default=DEFAULT_POST_CLEAR_RECEIPT_REL)
    parser.add_argument("--full-readjudication-receipt", default=DEFAULT_FULL_READJUDICATION_RECEIPT_REL)
    parser.add_argument("--orchestrator-receipt", default=DEFAULT_ORCHESTRATOR_RECEIPT_REL)
    parser.add_argument("--gate-e-screen-receipt", default=DEFAULT_GATE_E_SCREEN_RECEIPT_REL)
    parser.add_argument("--historical-status-section", default=DEFAULT_HISTORICAL_STATUS_SECTION_REL)
    parser.add_argument("--historical-blocker-board", default=DEFAULT_HISTORICAL_BLOCKER_BOARD_REL)
    parser.add_argument("--historical-status-audit", default=DEFAULT_HISTORICAL_STATUS_AUDIT_REL)
    parser.add_argument("--historical-overlay", default=DEFAULT_HISTORICAL_OVERLAY_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        post_clear_packet_path=_resolve(root, args.post_clear_packet),
        post_clear_receipt_path=_resolve(root, args.post_clear_receipt),
        full_readjudication_receipt_path=_resolve(root, args.full_readjudication_receipt),
        orchestrator_receipt_path=_resolve(root, args.orchestrator_receipt),
        gate_e_screen_receipt_path=_resolve(root, args.gate_e_screen_receipt),
        historical_status_section_path=_resolve(root, args.historical_status_section),
        historical_blocker_board_path=_resolve(root, args.historical_blocker_board),
        historical_status_audit_path=_resolve(root, args.historical_status_audit),
        historical_overlay_path=_resolve(root, args.historical_overlay),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "historical_failure_not_erased",
        "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture",
        "next_lawful_move",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
