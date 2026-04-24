from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator import cohort0_successor_gate_d_post_clear_branch_law_tranche as post_clear_branch_law
from tools.operator import cohort0_successor_gate_d_post_clear_supersession_note_tranche as supersession_note
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_FULL_READJUDICATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_readjudication.OUTPUT_RECEIPT}"
DEFAULT_POST_CLEAR_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_PACKET}"
DEFAULT_POST_CLEAR_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_RECEIPT}"
DEFAULT_SUPERSESSION_NOTE_REL = f"KT_PROD_CLEANROOM/reports/{supersession_note.OUTPUT_NOTE}"
DEFAULT_SUPERSESSION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{supersession_note.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = post_clear_branch_law.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_gate_e_precondition_monitor_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_e_precondition_monitor_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_E_PRECONDITION_MONITOR_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_E_PRECONDITION_MONITOR_CONVENED"
MONITOR_OUTCOME = "GATE_E_CONSIDERATION_AUTHORIZED__POST_SUCCESSOR_GATE_D_CLEAR__STILL_CLOSED"
NEXT_LAWFUL_MOVE = "AUTHOR_GATE_E_ADMISSIBILITY_SCOPE_PACKET__STILL_NOT_GATE_E_OPEN"


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
        raise RuntimeError("FAIL_CLOSED: Gate E precondition monitor requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    full_readjudication_receipt: Dict[str, Any],
    post_clear_packet: Dict[str, Any],
    post_clear_receipt: Dict[str, Any],
    supersession_note_payload: Dict[str, Any],
    supersession_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (full_readjudication_receipt, "full successor Gate D readjudication receipt"),
        (post_clear_packet, "post-clear branch law packet"),
        (post_clear_receipt, "post-clear branch law receipt"),
        (supersession_note_payload, "post-clear supersession note"),
        (supersession_receipt, "post-clear supersession receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(full_readjudication_receipt.get("readjudication_outcome", "")).strip() != full_readjudication.OUTCOME_CLEARED:
        raise RuntimeError("FAIL_CLOSED: Gate E monitor requires successor Gate D clear")
    if not bool(full_readjudication_receipt.get("gate_d_reopened", False)):
        raise RuntimeError("FAIL_CLOSED: Gate E monitor requires Gate D reopened on successor line")
    if bool(full_readjudication_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must still be closed when monitor is convened")
    if not bool(post_clear_receipt.get("gate_d_cleared_on_successor_line", False)):
        raise RuntimeError("FAIL_CLOSED: post-clear branch law must already be bound")
    if not bool(
        supersession_receipt.get("successor_line_supersedes_prior_same_head_failure_for_live_branch_posture", False)
    ):
        raise RuntimeError("FAIL_CLOSED: explicit supersession must be bound before Gate E monitor")


def _build_outputs(
    *,
    subject_head: str,
    source_refs: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    packet = {
        "schema_id": "kt.operator.cohort0_gate_e_precondition_monitor_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This monitor decides only whether lawful Gate E consideration may begin after successor Gate D clear. "
            "It does not open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "monitor_scope": "POST_SUCCESSOR_GATE_D_CLEAR__GATE_E_PRECONDITION_ONLY",
        "monitor_findings": {
            "successor_gate_d_cleared": True,
            "same_head_counted_reentry_admissible_on_successor_line": True,
            "post_clear_branch_law_bound": True,
            "historical_supersession_explicit": True,
            "d_before_e_order_satisfied": True,
            "gate_e_still_closed": True,
            "no_automatic_gate_e_opening": True,
        },
        "monitor_outcome": MONITOR_OUTCOME,
        "gate_e_lawful_consideration_authorized_now": True,
        "gate_e_open": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "source_refs": source_refs,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_e_precondition_monitor_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "monitor_scope": packet["monitor_scope"],
        "monitor_outcome": packet["monitor_outcome"],
        "gate_e_lawful_consideration_authorized_now": True,
        "gate_e_open": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    findings = dict(packet.get("monitor_findings", {}))
    finding_lines = "\n".join(f"- {key}: `{value}`" for key, value in findings.items())
    return (
        "# Cohort0 Gate E Precondition Monitor Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Monitor scope: `{receipt.get('monitor_scope', '')}`\n"
        f"- Monitor outcome: `{receipt.get('monitor_outcome', '')}`\n"
        f"- Gate E lawful consideration authorized now: `{receipt.get('gate_e_lawful_consideration_authorized_now', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Monitor Findings\n"
        f"{finding_lines}\n"
    )


def run(
    *,
    full_readjudication_receipt_path: Path,
    post_clear_packet_path: Path,
    post_clear_receipt_path: Path,
    supersession_note_path: Path,
    supersession_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    full_readjudication_receipt = _load_json_required(
        full_readjudication_receipt_path, label="full successor Gate D readjudication receipt"
    )
    post_clear_packet = _load_json_required(post_clear_packet_path, label="post-clear branch law packet")
    post_clear_receipt = _load_json_required(post_clear_receipt_path, label="post-clear branch law receipt")
    supersession_note_payload = _load_json_required(supersession_note_path, label="post-clear supersession note")
    supersession_receipt = _load_json_required(supersession_receipt_path, label="post-clear supersession receipt")

    _validate_inputs(
        full_readjudication_receipt=full_readjudication_receipt,
        post_clear_packet=post_clear_packet,
        post_clear_receipt=post_clear_receipt,
        supersession_note_payload=supersession_note_payload,
        supersession_receipt=supersession_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            full_readjudication_receipt,
            post_clear_packet,
            post_clear_receipt,
            supersession_note_payload,
            supersession_receipt,
        )
    )
    source_refs = {
        "full_readjudication_receipt_ref": full_readjudication_receipt_path.as_posix(),
        "post_clear_packet_ref": post_clear_packet_path.as_posix(),
        "post_clear_receipt_ref": post_clear_receipt_path.as_posix(),
        "supersession_note_ref": supersession_note_path.as_posix(),
        "supersession_receipt_ref": supersession_receipt_path.as_posix(),
    }
    outputs = _build_outputs(subject_head=subject_head, source_refs=source_refs)

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
        "monitor_outcome": MONITOR_OUTCOME,
        "gate_e_lawful_consideration_authorized_now": True,
        "gate_e_open": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convene the Gate E precondition monitor after successor Gate D clear.")
    parser.add_argument("--full-readjudication-receipt", default=DEFAULT_FULL_READJUDICATION_RECEIPT_REL)
    parser.add_argument("--post-clear-packet", default=DEFAULT_POST_CLEAR_PACKET_REL)
    parser.add_argument("--post-clear-receipt", default=DEFAULT_POST_CLEAR_RECEIPT_REL)
    parser.add_argument("--supersession-note", default=DEFAULT_SUPERSESSION_NOTE_REL)
    parser.add_argument("--supersession-receipt", default=DEFAULT_SUPERSESSION_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        full_readjudication_receipt_path=_resolve(root, args.full_readjudication_receipt),
        post_clear_packet_path=_resolve(root, args.post_clear_packet),
        post_clear_receipt_path=_resolve(root, args.post_clear_receipt),
        supersession_note_path=_resolve(root, args.supersession_note),
        supersession_receipt_path=_resolve(root, args.supersession_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "monitor_outcome",
        "gate_e_lawful_consideration_authorized_now",
        "gate_e_open",
        "next_lawful_move",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
