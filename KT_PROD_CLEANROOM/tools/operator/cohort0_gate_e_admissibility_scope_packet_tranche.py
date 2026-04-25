from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator import cohort0_successor_gate_d_post_clear_branch_law_tranche as post_clear_branch_law
from tools.operator import cohort0_successor_gate_d_post_clear_supersession_note_tranche as supersession_note
from tools.operator import cohort0_gate_e_precondition_monitor_tranche as gate_e_monitor
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_FULL_READJUDICATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_readjudication.OUTPUT_RECEIPT}"
DEFAULT_POST_CLEAR_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_PACKET}"
DEFAULT_POST_CLEAR_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{post_clear_branch_law.OUTPUT_RECEIPT}"
DEFAULT_SUPERSESSION_NOTE_REL = f"KT_PROD_CLEANROOM/reports/{supersession_note.OUTPUT_NOTE}"
DEFAULT_SUPERSESSION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{supersession_note.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_MONITOR_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_monitor.OUTPUT_PACKET}"
DEFAULT_GATE_E_MONITOR_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_monitor.OUTPUT_RECEIPT}"
DEFAULT_ORCHESTRATOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_packet.json"
DEFAULT_ORCHESTRATOR_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json"
DEFAULT_REPORTS_ROOT_REL = post_clear_branch_law.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_gate_e_admissibility_scope_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_e_admissibility_scope_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_E_ADMISSIBILITY_SCOPE_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_E_ADMISSIBILITY_SCOPE_PACKET_AUTHORED"
OUTCOME_SCOPE_DEFINED = "GATE_E_SCOPE_DEFINED__NOT_YET_ADMISSIBLE"
OUTCOME_SCREEN_AUTHORIZED = "GATE_E_ADMISSIBILITY_SCREEN_AUTHORIZED__STILL_NOT_OPEN"
OUTCOME_DEFERRED = "DEFERRED__MISSING_GATE_E_SCOPE_PREDICATES"
NEXT_LAWFUL_MOVE = "CONVENE_GATE_E_ADMISSIBILITY_SCREEN__STILL_NOT_GATE_E_OPEN"
EXPECTED_CLEAR_POSTURE = "GATE_D_CLEARED__SUCCESSOR_LINE__GATE_E_STILL_CLOSED"


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
        raise RuntimeError("FAIL_CLOSED: Gate E admissibility scope packet requires one same-head authority line")
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
    orchestrator_packet: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (full_readjudication_receipt, "full successor Gate D readjudication receipt"),
        (post_clear_packet, "post-clear branch law packet"),
        (post_clear_receipt, "post-clear branch law receipt"),
        (supersession_note_payload, "post-clear supersession note"),
        (supersession_receipt, "post-clear supersession receipt"),
        (gate_e_monitor_packet, "Gate E precondition monitor packet"),
        (gate_e_monitor_receipt, "Gate E precondition monitor receipt"),
        (orchestrator_packet, "successor master orchestrator packet"),
        (orchestrator_receipt, "successor master orchestrator receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(full_readjudication_receipt.get("readjudication_outcome", "")).strip() != full_readjudication.OUTCOME_CLEARED:
        raise RuntimeError("FAIL_CLOSED: Gate E scope packet requires successor Gate D clear")
    if not bool(full_readjudication_receipt.get("same_head_counted_reentry_admissible_now", False)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must be admissible on the successor line")
    if not bool(full_readjudication_receipt.get("gate_d_reopened", False)):
        raise RuntimeError("FAIL_CLOSED: Gate D must be reopened before Gate E scope is defined")
    if bool(full_readjudication_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering scope definition")
    if not bool(post_clear_receipt.get("gate_d_cleared_on_successor_line", False)):
        raise RuntimeError("FAIL_CLOSED: post-clear branch law must already be bound")
    if not bool(
        supersession_receipt.get("successor_line_supersedes_prior_same_head_failure_for_live_branch_posture", False)
    ):
        raise RuntimeError("FAIL_CLOSED: supersession must be explicit before Gate E scope is defined")
    if not bool(gate_e_monitor_receipt.get("gate_e_lawful_consideration_authorized_now", False)):
        raise RuntimeError("FAIL_CLOSED: Gate E lawful consideration must be authorized before scope definition")
    if bool(gate_e_monitor_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed in the scope packet")
    if str(orchestrator_receipt.get("current_branch_posture", "")).strip() != EXPECTED_CLEAR_POSTURE:
        raise RuntimeError("FAIL_CLOSED: orchestrator must remain on the successor Gate D cleared posture")


def _determine_outcome(*, findings: Dict[str, Any]) -> str:
    core_keys = (
        "successor_gate_d_clear_canonical",
        "same_head_counted_reentry_admissible_on_successor_line",
        "post_clear_branch_law_bound",
        "historical_supersession_explicit",
        "gate_e_consideration_authorized",
        "gate_e_still_closed",
        "comparator_order_preserved",
        "no_automatic_gate_e_opening",
    )
    if all(bool(findings.get(key, False)) for key in core_keys):
        return OUTCOME_SCREEN_AUTHORIZED
    if any(bool(findings.get(key, False)) for key in core_keys):
        return OUTCOME_SCOPE_DEFINED
    return OUTCOME_DEFERRED


def _build_outputs(
    *,
    subject_head: str,
    source_refs: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    findings = {
        "successor_gate_d_clear_canonical": True,
        "same_head_counted_reentry_admissible_on_successor_line": True,
        "post_clear_branch_law_bound": True,
        "historical_supersession_explicit": True,
        "gate_e_consideration_authorized": True,
        "gate_e_still_closed": True,
        "comparator_order_preserved": True,
        "no_automatic_gate_e_opening": True,
    }
    outcome = _determine_outcome(findings=findings)
    gate_e_admissibility_screen_authorized_now = outcome == OUTCOME_SCREEN_AUTHORIZED

    packet = {
        "schema_id": "kt.operator.cohort0_gate_e_admissibility_scope_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet defines only the bounded Gate E admissibility scope after successor Gate D clear. "
            "It does not open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "authority_header": {
            "gate_d_cleared_on_successor_line": True,
            "same_head_counted_reentry_admissible_on_successor_line": True,
            "gate_e_open": False,
            "scope_setting_only": True,
        },
        "gate_e_question": (
            "What bounded conditions must be satisfied for Gate E to become admissible after the successor line "
            "lawfully cleared Gate D, while keeping Gate E itself closed until a later court rules?"
        ),
        "allowed_evidence_classes": [
            {"class_id": "successor_gate_d_clear_receipt", "ref": source_refs["full_readjudication_receipt_ref"]},
            {"class_id": "post_clear_branch_law_packet", "ref": source_refs["post_clear_packet_ref"]},
            {"class_id": "post_clear_branch_law_receipt", "ref": source_refs["post_clear_receipt_ref"]},
            {"class_id": "post_clear_supersession_note", "ref": source_refs["supersession_note_ref"]},
            {"class_id": "post_clear_supersession_receipt", "ref": source_refs["supersession_receipt_ref"]},
            {"class_id": "gate_e_precondition_monitor_packet", "ref": source_refs["gate_e_monitor_packet_ref"]},
            {"class_id": "gate_e_precondition_monitor_receipt", "ref": source_refs["gate_e_monitor_receipt_ref"]},
            {"class_id": "successor_master_orchestrator_packet", "ref": source_refs["orchestrator_packet_ref"]},
            {"class_id": "successor_master_orchestrator_receipt", "ref": source_refs["orchestrator_receipt_ref"]},
        ],
        "explicit_non_claims": [
            "No automatic Gate E opening from Gate D clear.",
            "No retroactive widening of the theorem from this scope packet.",
            "No skipping comparator order or governance predicates.",
            "No treating post-clear momentum as Gate E entitlement.",
        ],
        "scope_findings": findings,
        "allowed_outcomes": [
            OUTCOME_SCOPE_DEFINED,
            OUTCOME_SCREEN_AUTHORIZED,
            OUTCOME_DEFERRED,
        ],
        "scope_outcome": outcome,
        "gate_e_admissibility_screen_authorized_now": gate_e_admissibility_screen_authorized_now,
        "gate_e_open": False,
        "next_lawful_move": (
            NEXT_LAWFUL_MOVE if gate_e_admissibility_screen_authorized_now else "MAINTAIN_GATE_E_SCOPE_ONLY_POSTURE"
        ),
        "source_refs": source_refs,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_e_admissibility_scope_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "scope_outcome": outcome,
        "gate_e_admissibility_screen_authorized_now": gate_e_admissibility_screen_authorized_now,
        "gate_e_open": False,
        "next_lawful_move": packet["next_lawful_move"],
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    non_claim_lines = "\n".join(f"- {item}" for item in packet.get("explicit_non_claims", []))
    evidence_lines = "\n".join(
        f"- `{item.get('class_id', '')}` -> `{item.get('ref', '')}`" for item in packet.get("allowed_evidence_classes", [])
    )
    return (
        "# Cohort0 Gate E Admissibility Scope Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Scope outcome: `{receipt.get('scope_outcome', '')}`\n"
        f"- Gate E admissibility screen authorized now: `{receipt.get('gate_e_admissibility_screen_authorized_now', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Allowed Evidence Classes\n"
        f"{evidence_lines}\n\n"
        "## Explicit Non-Claims\n"
        f"{non_claim_lines}\n"
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
    orchestrator_packet_path: Path,
    orchestrator_receipt_path: Path,
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
    orchestrator_packet = _load_json_required(orchestrator_packet_path, label="successor master orchestrator packet")
    orchestrator_receipt = _load_json_required(orchestrator_receipt_path, label="successor master orchestrator receipt")

    _validate_inputs(
        full_readjudication_receipt=full_readjudication_receipt,
        post_clear_packet=post_clear_packet,
        post_clear_receipt=post_clear_receipt,
        supersession_note_payload=supersession_note_payload,
        supersession_receipt=supersession_receipt,
        gate_e_monitor_packet=gate_e_monitor_packet,
        gate_e_monitor_receipt=gate_e_monitor_receipt,
        orchestrator_packet=orchestrator_packet,
        orchestrator_receipt=orchestrator_receipt,
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
            orchestrator_packet,
            orchestrator_receipt,
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
        "orchestrator_packet_ref": orchestrator_packet_path.as_posix(),
        "orchestrator_receipt_ref": orchestrator_receipt_path.as_posix(),
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
        "scope_outcome": outputs["receipt"]["scope_outcome"],
        "gate_e_admissibility_screen_authorized_now": outputs["receipt"]["gate_e_admissibility_screen_authorized_now"],
        "gate_e_open": False,
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the bounded Gate E admissibility scope packet.")
    parser.add_argument("--full-readjudication-receipt", default=DEFAULT_FULL_READJUDICATION_RECEIPT_REL)
    parser.add_argument("--post-clear-packet", default=DEFAULT_POST_CLEAR_PACKET_REL)
    parser.add_argument("--post-clear-receipt", default=DEFAULT_POST_CLEAR_RECEIPT_REL)
    parser.add_argument("--supersession-note", default=DEFAULT_SUPERSESSION_NOTE_REL)
    parser.add_argument("--supersession-receipt", default=DEFAULT_SUPERSESSION_RECEIPT_REL)
    parser.add_argument("--gate-e-monitor-packet", default=DEFAULT_GATE_E_MONITOR_PACKET_REL)
    parser.add_argument("--gate-e-monitor-receipt", default=DEFAULT_GATE_E_MONITOR_RECEIPT_REL)
    parser.add_argument("--orchestrator-packet", default=DEFAULT_ORCHESTRATOR_PACKET_REL)
    parser.add_argument("--orchestrator-receipt", default=DEFAULT_ORCHESTRATOR_RECEIPT_REL)
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
        orchestrator_packet_path=_resolve(root, args.orchestrator_packet),
        orchestrator_receipt_path=_resolve(root, args.orchestrator_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "scope_outcome",
        "gate_e_admissibility_screen_authorized_now",
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
