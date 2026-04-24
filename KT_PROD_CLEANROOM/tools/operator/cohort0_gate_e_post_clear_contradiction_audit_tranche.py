from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator import cohort0_successor_gate_d_post_clear_branch_law_tranche as post_clear_branch_law
from tools.operator import cohort0_successor_gate_d_post_clear_supersession_note_tranche as supersession_note
from tools.operator import cohort0_gate_e_precondition_monitor_tranche as gate_e_monitor
from tools.operator import cohort0_gate_e_admissibility_scope_packet_tranche as gate_e_scope
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_FULL_READJUDICATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_readjudication.OUTPUT_RECEIPT}"
DEFAULT_POST_CLEAR_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_PACKET}"
DEFAULT_POST_CLEAR_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_RECEIPT}"
DEFAULT_SUPERSESSION_NOTE_REL = f"KT_PROD_CLEANROOM/reports/{supersession_note.OUTPUT_NOTE}"
DEFAULT_SUPERSESSION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{supersession_note.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_MONITOR_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_monitor.OUTPUT_PACKET}"
DEFAULT_GATE_E_MONITOR_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_monitor.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_SCOPE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_scope.OUTPUT_PACKET}"
DEFAULT_GATE_E_SCOPE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_scope.OUTPUT_RECEIPT}"
DEFAULT_ORCHESTRATOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_packet.json"
DEFAULT_ORCHESTRATOR_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json"
DEFAULT_PREDICATE_BOARD_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_predicate_board.json"
DEFAULT_REPORTS_ROOT_REL = post_clear_branch_law.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_gate_e_post_clear_contradiction_audit_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_e_post_clear_contradiction_audit_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_E_POST_CLEAR_CONTRADICTION_AUDIT_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_E_POST_CLEAR_CONTRADICTION_AUDIT_EXECUTED"
OUTCOME_CLEAN_CLOSED = "NO_LIVE_AUTHORITY_CONTRADICTION__GATE_E_STILL_CLOSED"
OUTCOME_CLEAN_OPEN = "NO_LIVE_AUTHORITY_CONTRADICTION__GATE_E_OPEN"
OUTCOME_DIRTY = "LIVE_AUTHORITY_CONTRADICTION_DETECTED__FAIL_CLOSED"
NEXT_LAWFUL_MOVE = gate_e_scope.NEXT_LAWFUL_MOVE
NEXT_LAWFUL_MOVE_FAIL = "RESOLVE_GATE_E_POST_CLEAR_AUTHORITY_CONTRADICTIONS__FAIL_CLOSED"
EXPECTED_CLEAR_POSTURE = gate_e_scope.EXPECTED_CLEAR_POSTURE
GATE_E_OPEN_POSTURE = "GATE_E_OPEN__POST_SUCCESSOR_GATE_D_CLEAR"
GATE_E_SCREEN_DEFECT_NEXT_MOVE = "AUTHOR_GATE_E_COMPARATOR_GOVERNANCE_BINDING_PACKET__POST_GATE_E_SCREEN"
GATE_E_BINDING_PACKET_NEXT_MOVE = "CONVENE_GATE_E_COMPARATOR_GOVERNANCE_BINDING_SCREEN__POST_BINDING_PACKET"
GATE_E_BINDING_SCREEN_CONFIRMED_NEXT_MOVE = "RECONVENE_GATE_E_ADMISSIBILITY_SCREEN__POST_BINDING_CONFIRMATION"
GATE_E_OPEN_NEXT_MOVE = "MAINTAIN_GATE_E_OPEN_POSTURE__POST_SUCCESSOR_LINE_CLEAR"
GATE_E_OPEN_SCREEN_STATUS = "SATISFIED__GATE_E_OPEN__SUCCESSOR_LINE"


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
        raise RuntimeError("FAIL_CLOSED: Gate E post-clear contradiction audit requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    full_readjudication_receipt: Dict[str, Any],
    post_clear_packet: Dict[str, Any],
    post_clear_receipt: Dict[str, Any],
    supersession_note_payload: Dict[str, Any],
    supersession_receipt: Dict[str, Any],
    gate_e_monitor_packet: Dict[str, Any],
    gate_e_monitor_receipt: Dict[str, Any],
    gate_e_scope_packet: Dict[str, Any],
    gate_e_scope_receipt: Dict[str, Any],
    orchestrator_packet: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
    predicate_board: Dict[str, Any],
) -> None:
    for payload, label in (
        (full_readjudication_receipt, "full successor Gate D readjudication receipt"),
        (post_clear_packet, "post-clear branch law packet"),
        (post_clear_receipt, "post-clear branch law receipt"),
        (supersession_note_payload, "post-clear supersession note"),
        (supersession_receipt, "post-clear supersession receipt"),
        (gate_e_monitor_packet, "Gate E precondition monitor packet"),
        (gate_e_monitor_receipt, "Gate E precondition monitor receipt"),
        (gate_e_scope_packet, "Gate E admissibility scope packet"),
        (gate_e_scope_receipt, "Gate E admissibility scope receipt"),
        (orchestrator_packet, "successor master orchestrator packet"),
        (orchestrator_receipt, "successor master orchestrator receipt"),
        (predicate_board, "successor master predicate board"),
    ):
        _ensure_pass(payload, label=label)


def _status(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _orchestrator_gate_e_next_move_is_lawful(next_move: str) -> bool:
    return next_move in {
        gate_e_scope.NEXT_LAWFUL_MOVE,
        GATE_E_SCREEN_DEFECT_NEXT_MOVE,
        GATE_E_BINDING_PACKET_NEXT_MOVE,
        GATE_E_BINDING_SCREEN_CONFIRMED_NEXT_MOVE,
        GATE_E_OPEN_NEXT_MOVE,
    }


def _orchestrator_claim_nodes_are_lawful(
    claim_nodes: Dict[str, Dict[str, Any]], *, gate_e_open_now: bool
) -> bool:
    monitor_ok = str(claim_nodes.get("gate_e_precondition_monitor", {}).get("status", "")).strip() == (
        "SATISFIED__POST_SUCCESSOR_GATE_D_CLEAR__STILL_GATE_E_CLOSED"
    )
    scope_ok = str(claim_nodes.get("gate_e_admissibility_scope_packet", {}).get("status", "")).strip() == (
        "SATISFIED__GATE_E_ADMISSIBILITY_SCREEN_AUTHORIZED__STILL_NOT_OPEN"
    )
    screen_status = str(claim_nodes.get("gate_e_admissibility_screen", {}).get("status", "")).strip()
    binding_packet_status = str(
        claim_nodes.get("gate_e_comparator_governance_binding_packet", {}).get("status", "")
    ).strip()
    binding_screen_status = str(
        claim_nodes.get("gate_e_comparator_governance_binding_screen", {}).get("status", "")
    ).strip()
    if gate_e_open_now:
        stage_ok = screen_status == GATE_E_OPEN_SCREEN_STATUS
    else:
        stage_ok = screen_status in {
            "",
            "AUTHORIZED__GATE_E_SCREEN_MAY_BE_CONVENED",
            "EXECUTED__BOUNDED_DEFECT_IDENTIFIED",
        } or binding_packet_status == "SATISFIED__GATE_E_BINDING_PACKET_BOUND__STILL_NOT_OPEN" or binding_screen_status == (
            "SATISFIED__GATE_E_BINDING_CONFIRMED__ADMISSIBILITY_REVIEW_MAY_BE_CONVENED"
        )
    return monitor_ok and scope_ok and stage_ok


def _build_rows(
    *,
    full_readjudication_receipt: Dict[str, Any],
    post_clear_packet: Dict[str, Any],
    supersession_receipt: Dict[str, Any],
    gate_e_monitor_receipt: Dict[str, Any],
    gate_e_scope_receipt: Dict[str, Any],
    orchestrator_packet: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
    predicate_board: Dict[str, Any],
) -> List[Dict[str, Any]]:
    claim_nodes = {
        str(node.get("node_id", "")).strip(): node
        for node in orchestrator_packet.get("claim_nodes", [])
        if isinstance(node, dict)
    }
    predicates = dict(predicate_board.get("predicates", {}))
    gate_e_open_now = bool(predicates.get("gate_e_open", False)) and bool(orchestrator_receipt.get("gate_e_open", False))
    rows: List[Dict[str, Any]] = []

    rows.append(
        {
            "check_id": "SUCCESSOR_GATE_D_CLEAR_CANONICAL",
            "status": _status(
                str(full_readjudication_receipt.get("readjudication_outcome", "")).strip()
                == full_readjudication.OUTCOME_CLEARED
                and bool(full_readjudication_receipt.get("same_head_counted_reentry_admissible_now", False))
                and bool(full_readjudication_receipt.get("gate_d_reopened", False))
                and not bool(full_readjudication_receipt.get("gate_e_open", True))
            ),
            "detail": "Successor Gate D clear remains canonical and Gate E remains closed.",
        }
    )
    rows.append(
        {
            "check_id": "POST_CLEAR_BRANCH_LAW_CONSISTENT",
            "status": _status(
                bool(post_clear_packet.get("canonical_live_branch_status", {}).get("gate_d_cleared_on_successor_line", False))
                and bool(post_clear_packet.get("canonical_live_branch_status", {}).get("gate_d_reopened", False))
                and not bool(post_clear_packet.get("canonical_live_branch_status", {}).get("gate_e_open", True))
            ),
            "detail": "Post-clear branch law packet agrees with the successor Gate D clear and closed Gate E posture.",
        }
    )
    rows.append(
        {
            "check_id": "SUPERSESSION_EXPLICIT",
            "status": _status(
                bool(
                    supersession_receipt.get(
                        "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture", False
                    )
                )
            ),
            "detail": "Historical supersession remains explicit instead of erasing the hardened-ceiling history.",
        }
    )
    rows.append(
        {
            "check_id": "GATE_E_MONITOR_CONSISTENT",
            "status": _status(
                bool(gate_e_monitor_receipt.get("gate_e_lawful_consideration_authorized_now", False))
                and not bool(gate_e_monitor_receipt.get("gate_e_open", True))
            ),
            "detail": "Gate E precondition monitor authorizes consideration while keeping Gate E closed.",
        }
    )
    rows.append(
        {
            "check_id": "GATE_E_SCOPE_CONSISTENT",
            "status": _status(
                bool(gate_e_scope_receipt.get("gate_e_admissibility_screen_authorized_now", False))
                and not bool(gate_e_scope_receipt.get("gate_e_open", True))
                and str(gate_e_scope_receipt.get("next_lawful_move", "")).strip() == gate_e_scope.NEXT_LAWFUL_MOVE
            ),
            "detail": "Gate E scope packet authorizes the admissibility screen and still does not open Gate E.",
        }
    )
    rows.append(
        {
            "check_id": "ORCHESTRATOR_PREDICATE_BOARD_CONSISTENT",
            "status": _status(
                not bool(predicates.get("same_head_counted_reentry_blocked", True))
                and not bool(predicates.get("gate_d_closed", True))
                and (
                    (
                        gate_e_open_now
                        and bool(predicates.get("gate_e_open", False))
                        and not bool(predicates.get("gate_e_closed", True))
                        and bool(predicates.get("gate_e_admissibility_screen_executed", False))
                    )
                    or (
                        not gate_e_open_now
                        and bool(predicates.get("gate_e_closed", False))
                        and (
                            not bool(predicates.get("gate_e_admissibility_screen_executed", False))
                            or bool(predicates.get("gate_e_named_binding_defect_from_screen", False))
                            or bool(predicates.get("gate_e_binding_confirmed", False))
                        )
                    )
                )
                and bool(predicates.get("gate_e_precondition_monitor_executed", False))
                and bool(predicates.get("gate_e_admissibility_scope_packet_executed", False))
                and bool(predicates.get("gate_e_admissibility_screen_authorized_now", False))
            ),
            "detail": (
                "Predicate board reflects Gate D clear and the current lawful Gate E stage, whether still closed "
                "during binding progression or fully open after the Gate E court."
            ),
        }
    )
    rows.append(
        {
            "check_id": "ORCHESTRATOR_PACKET_CONSISTENT",
            "status": _status(
                str(orchestrator_receipt.get("current_branch_posture", "")).strip()
                == (GATE_E_OPEN_POSTURE if gate_e_open_now else EXPECTED_CLEAR_POSTURE)
                and _orchestrator_gate_e_next_move_is_lawful(
                    str(orchestrator_receipt.get("next_lawful_move", "")).strip()
                )
                and _orchestrator_claim_nodes_are_lawful(claim_nodes, gate_e_open_now=gate_e_open_now)
            ),
            "detail": (
                "Orchestrator packet and receipt stay aligned with the live post-clear Gate E stack, including lawful "
                "post-screen and binding-stage progression without drifting away from the actual current Gate E posture."
            ),
        }
    )
    return rows


def _build_outputs(
    *,
    rows: List[Dict[str, Any]],
    gate_e_open_now: bool,
    clean_next_lawful_move: str,
    source_refs: Dict[str, str],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    contradictions = [row["check_id"] for row in rows if row.get("status") != "PASS"]
    contradiction_free = not contradictions
    outcome = (
        OUTCOME_CLEAN_OPEN
        if contradiction_free and gate_e_open_now
        else (OUTCOME_CLEAN_CLOSED if contradiction_free else OUTCOME_DIRTY)
    )
    next_lawful_move = clean_next_lawful_move if contradiction_free else NEXT_LAWFUL_MOVE_FAIL

    packet = {
        "schema_id": "kt.operator.cohort0_gate_e_post_clear_contradiction_audit_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This audit checks only the current live post-clear authority stack for contradiction or stale pre-clear drift. "
            "It does not open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "audit_scope": "LIVE_POST_CLEAR_GATE_E_AUTHORITY_STACK_ONLY",
        "audit_rows": rows,
        "audit_outcome": outcome,
        "post_clear_live_authority_contradiction_free": contradiction_free,
        "remaining_open_contradictions": contradictions,
        "next_lawful_move": next_lawful_move,
        "source_refs": source_refs,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_e_post_clear_contradiction_audit_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "audit_outcome": outcome,
        "post_clear_live_authority_contradiction_free": contradiction_free,
        "remaining_open_contradictions": contradictions,
        "next_lawful_move": next_lawful_move,
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    row_lines = "\n".join(
        f"- `{row.get('check_id', '')}`: `{row.get('status', '')}` -> {row.get('detail', '')}"
        for row in packet.get("audit_rows", [])
    )
    contradiction_lines = "\n".join(
        f"- `{item}`" for item in receipt.get("remaining_open_contradictions", [])
    ) or "- none"
    return (
        "# Cohort0 Gate E Post-Clear Contradiction Audit Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Audit outcome: `{receipt.get('audit_outcome', '')}`\n"
        f"- Contradiction free: `{receipt.get('post_clear_live_authority_contradiction_free', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Audit Rows\n"
        f"{row_lines}\n\n"
        "## Remaining Open Contradictions\n"
        f"{contradiction_lines}\n"
    )


def run(
    *,
    full_readjudication_receipt_path: Path,
    post_clear_packet_path: Path,
    post_clear_receipt_path: Path,
    supersession_note_path: Path,
    supersession_receipt_path: Path,
    gate_e_monitor_packet_path: Path,
    gate_e_monitor_receipt_path: Path,
    gate_e_scope_packet_path: Path,
    gate_e_scope_receipt_path: Path,
    orchestrator_packet_path: Path,
    orchestrator_receipt_path: Path,
    predicate_board_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    full_readjudication_receipt = _load_json_required(
        full_readjudication_receipt_path, label="full successor Gate D readjudication receipt"
    )
    post_clear_packet = _load_json_required(post_clear_packet_path, label="post-clear branch law packet")
    post_clear_receipt = _load_json_required(post_clear_receipt_path, label="post-clear branch law receipt")
    supersession_note_payload = _load_json_required(supersession_note_path, label="post-clear supersession note")
    supersession_receipt = _load_json_required(supersession_receipt_path, label="post-clear supersession receipt")
    gate_e_monitor_packet = _load_json_required(gate_e_monitor_packet_path, label="Gate E precondition monitor packet")
    gate_e_monitor_receipt = _load_json_required(gate_e_monitor_receipt_path, label="Gate E precondition monitor receipt")
    gate_e_scope_packet = _load_json_required(gate_e_scope_packet_path, label="Gate E admissibility scope packet")
    gate_e_scope_receipt = _load_json_required(gate_e_scope_receipt_path, label="Gate E admissibility scope receipt")
    orchestrator_packet = _load_json_required(orchestrator_packet_path, label="successor master orchestrator packet")
    orchestrator_receipt = _load_json_required(orchestrator_receipt_path, label="successor master orchestrator receipt")
    predicate_board = _load_json_required(predicate_board_path, label="successor master predicate board")

    _validate_inputs(
        full_readjudication_receipt=full_readjudication_receipt,
        post_clear_packet=post_clear_packet,
        post_clear_receipt=post_clear_receipt,
        supersession_note_payload=supersession_note_payload,
        supersession_receipt=supersession_receipt,
        gate_e_monitor_packet=gate_e_monitor_packet,
        gate_e_monitor_receipt=gate_e_monitor_receipt,
        gate_e_scope_packet=gate_e_scope_packet,
        gate_e_scope_receipt=gate_e_scope_receipt,
        orchestrator_packet=orchestrator_packet,
        orchestrator_receipt=orchestrator_receipt,
        predicate_board=predicate_board,
    )
    subject_head = _require_same_subject_head(
        (
            full_readjudication_receipt,
            post_clear_packet,
            post_clear_receipt,
            supersession_note_payload,
            supersession_receipt,
            gate_e_monitor_packet,
            gate_e_monitor_receipt,
            gate_e_scope_packet,
            gate_e_scope_receipt,
            orchestrator_packet,
            orchestrator_receipt,
            predicate_board,
        )
    )
    source_refs = {
        "full_readjudication_receipt_ref": full_readjudication_receipt_path.as_posix(),
        "post_clear_packet_ref": post_clear_packet_path.as_posix(),
        "post_clear_receipt_ref": post_clear_receipt_path.as_posix(),
        "supersession_note_ref": supersession_note_path.as_posix(),
        "supersession_receipt_ref": supersession_receipt_path.as_posix(),
        "gate_e_monitor_packet_ref": gate_e_monitor_packet_path.as_posix(),
        "gate_e_monitor_receipt_ref": gate_e_monitor_receipt_path.as_posix(),
        "gate_e_scope_packet_ref": gate_e_scope_packet_path.as_posix(),
        "gate_e_scope_receipt_ref": gate_e_scope_receipt_path.as_posix(),
        "orchestrator_packet_ref": orchestrator_packet_path.as_posix(),
        "orchestrator_receipt_ref": orchestrator_receipt_path.as_posix(),
        "predicate_board_ref": predicate_board_path.as_posix(),
    }
    rows = _build_rows(
        full_readjudication_receipt=full_readjudication_receipt,
        post_clear_packet=post_clear_packet,
        supersession_receipt=supersession_receipt,
        gate_e_monitor_receipt=gate_e_monitor_receipt,
        gate_e_scope_receipt=gate_e_scope_receipt,
        orchestrator_packet=orchestrator_packet,
        orchestrator_receipt=orchestrator_receipt,
        predicate_board=predicate_board,
    )
    gate_e_open_now = bool(predicate_board.get("predicates", {}).get("gate_e_open", False)) and bool(
        orchestrator_receipt.get("gate_e_open", False)
    )
    outputs = _build_outputs(
        rows=rows,
        gate_e_open_now=gate_e_open_now,
        clean_next_lawful_move=str(orchestrator_receipt.get("next_lawful_move", "")).strip() or NEXT_LAWFUL_MOVE,
        source_refs=source_refs,
        subject_head=subject_head,
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
        "audit_outcome": outputs["receipt"]["audit_outcome"],
        "post_clear_live_authority_contradiction_free": outputs["receipt"]["post_clear_live_authority_contradiction_free"],
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit the live post-clear Gate E authority stack for contradiction.")
    parser.add_argument("--full-readjudication-receipt", default=DEFAULT_FULL_READJUDICATION_RECEIPT_REL)
    parser.add_argument("--post-clear-packet", default=DEFAULT_POST_CLEAR_PACKET_REL)
    parser.add_argument("--post-clear-receipt", default=DEFAULT_POST_CLEAR_RECEIPT_REL)
    parser.add_argument("--supersession-note", default=DEFAULT_SUPERSESSION_NOTE_REL)
    parser.add_argument("--supersession-receipt", default=DEFAULT_SUPERSESSION_RECEIPT_REL)
    parser.add_argument("--gate-e-monitor-packet", default=DEFAULT_GATE_E_MONITOR_PACKET_REL)
    parser.add_argument("--gate-e-monitor-receipt", default=DEFAULT_GATE_E_MONITOR_RECEIPT_REL)
    parser.add_argument("--gate-e-scope-packet", default=DEFAULT_GATE_E_SCOPE_PACKET_REL)
    parser.add_argument("--gate-e-scope-receipt", default=DEFAULT_GATE_E_SCOPE_RECEIPT_REL)
    parser.add_argument("--orchestrator-packet", default=DEFAULT_ORCHESTRATOR_PACKET_REL)
    parser.add_argument("--orchestrator-receipt", default=DEFAULT_ORCHESTRATOR_RECEIPT_REL)
    parser.add_argument("--predicate-board", default=DEFAULT_PREDICATE_BOARD_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        full_readjudication_receipt_path=_resolve(root, args.full_readjudication_receipt),
        post_clear_packet_path=_resolve(root, args.post_clear_packet),
        post_clear_receipt_path=_resolve(root, args.post_clear_receipt),
        supersession_note_path=_resolve(root, args.supersession_note),
        supersession_receipt_path=_resolve(root, args.supersession_receipt),
        gate_e_monitor_packet_path=_resolve(root, args.gate_e_monitor_packet),
        gate_e_monitor_receipt_path=_resolve(root, args.gate_e_monitor_receipt),
        gate_e_scope_packet_path=_resolve(root, args.gate_e_scope_packet),
        gate_e_scope_receipt_path=_resolve(root, args.gate_e_scope_receipt),
        orchestrator_packet_path=_resolve(root, args.orchestrator_packet),
        orchestrator_receipt_path=_resolve(root, args.orchestrator_receipt),
        predicate_board_path=_resolve(root, args.predicate_board),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "audit_outcome",
        "post_clear_live_authority_contradiction_free",
        "next_lawful_move",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
