from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_FULL_READJUDICATION_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{full_readjudication.OUTPUT_PACKET}"
DEFAULT_FULL_READJUDICATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_readjudication.OUTPUT_RECEIPT}"
DEFAULT_ORCHESTRATOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_packet.json"
DEFAULT_ORCHESTRATOR_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json"
DEFAULT_GATE_E_SCREEN_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_e_admissibility_screen_receipt.json"
DEFAULT_REPORTS_ROOT_REL = full_readjudication.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_gate_d_post_clear_branch_law_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_gate_d_post_clear_branch_law_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_GATE_D_POST_CLEAR_BRANCH_LAW_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_GATE_D_POST_CLEAR_BRANCH_LAW_BOUND"
EXPECTED_CLEAR_POSTURE = "GATE_D_CLEARED__SUCCESSOR_LINE__GATE_E_STILL_CLOSED"
OPEN_POSTURE = "GATE_E_OPEN__POST_SUCCESSOR_GATE_D_CLEAR"
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
        raise RuntimeError("FAIL_CLOSED: post-clear branch law requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    full_readjudication_packet: Dict[str, Any],
    full_readjudication_receipt: Dict[str, Any],
    orchestrator_packet: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
    gate_e_screen_receipt: Optional[Dict[str, Any]],
) -> None:
    for payload, label in (
        (full_readjudication_packet, "full successor Gate D readjudication packet"),
        (full_readjudication_receipt, "full successor Gate D readjudication receipt"),
        (orchestrator_packet, "successor master orchestrator packet"),
        (orchestrator_receipt, "successor master orchestrator receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(full_readjudication_receipt.get("readjudication_outcome", "")).strip() != full_readjudication.OUTCOME_CLEARED:
        raise RuntimeError("FAIL_CLOSED: post-clear branch law requires a cleared successor Gate D receipt")
    if not bool(full_readjudication_receipt.get("same_head_counted_reentry_admissible_now", False)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must be admissible on the cleared successor line")
    if not bool(full_readjudication_receipt.get("gate_d_reopened", False)):
        raise RuntimeError("FAIL_CLOSED: Gate D must be reopened on the cleared successor line")
    gate_e_open_now = bool(
        isinstance(gate_e_screen_receipt, dict) and gate_e_screen_receipt.get("gate_e_open", False)
    )
    current_posture = str(orchestrator_receipt.get("current_branch_posture", "")).strip()
    if gate_e_open_now:
        if str(gate_e_screen_receipt.get("screen_outcome", "")).strip() != GATE_E_OPEN_OUTCOME:
            raise RuntimeError("FAIL_CLOSED: Gate E open branch law requires an open Gate E screen receipt")
        if current_posture != OPEN_POSTURE:
            raise RuntimeError("FAIL_CLOSED: orchestrator must already reflect the Gate E open posture")
    elif current_posture != EXPECTED_CLEAR_POSTURE:
        raise RuntimeError("FAIL_CLOSED: orchestrator must already reflect the Gate D clear posture")


def _build_outputs(
    *,
    subject_head: str,
    full_readjudication_packet: Dict[str, Any],
    full_readjudication_receipt: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
    gate_e_screen_receipt: Optional[Dict[str, Any]],
    source_refs: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    gate_e_open_now = bool(
        isinstance(gate_e_screen_receipt, dict) and gate_e_screen_receipt.get("gate_e_open", False)
    )
    current_branch_posture = OPEN_POSTURE if gate_e_open_now else EXPECTED_CLEAR_POSTURE
    next_lawful_move = (
        str(gate_e_screen_receipt.get("next_lawful_move", "")).strip()
        if gate_e_open_now
        else str(orchestrator_receipt.get("next_lawful_move", "")).strip()
    ) or str(full_readjudication_receipt.get("next_lawful_move", "")).strip()
    packet = {
        "schema_id": "kt.operator.cohort0_successor_gate_d_post_clear_branch_law_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet freezes the canonical live branch law after the successor line cleared Gate D "
            "and any later lawful Gate E movement. It records what changed and what did not change "
            "without widening beyond the receipts it binds."
        ),
        "execution_status": EXECUTION_STATUS,
        "canonical_live_branch_status": {
            "gate_d_cleared_on_successor_line": True,
            "same_head_counted_reentry_admissible_now": True,
            "gate_d_reopened": True,
            "gate_e_open": gate_e_open_now,
            "current_branch_posture": current_branch_posture,
            "counted_verdict_posture": full_readjudication_receipt.get("counted_verdict_posture", ""),
        },
        "what_changed": [
            "Gate D is now cleared on the successor line.",
            "Same-head counted reentry is now admissible on that successor line.",
            "Gate D is reopened on that successor line.",
            *(
                ["Gate E is now open on that successor line."]
                if gate_e_open_now
                else []
            ),
            "The live branch authority now rests on the successor full readjudication receipt and orchestrator recompute.",
        ],
        "what_did_not_change": (
            [
                "The old hardened-ceiling failure remains historically valid and preserved.",
                "The successor clear does not erase the failed prior same-head lane.",
                "This canonical branch law packet does not widen beyond the live D/E receipts.",
            ]
            if gate_e_open_now
            else [
                "Gate E remains closed.",
                "The old hardened-ceiling failure remains historically valid and preserved.",
                "The successor clear does not erase the failed prior same-head lane.",
                "The next lawful move remains Gate E precondition monitoring, not Gate E opening.",
            ]
        ),
        "governing_post_clear_rule": (
            (
                "Gate D cleared on the successor line; Gate E is now open on that line."
                if gate_e_open_now
                else "Gate D cleared on the successor line; Gate E still closed."
            )
            + " All post-clear movement must remain narrower than the live authority stack."
        ),
        "next_lawful_move": next_lawful_move,
        "authoritative_live_surfaces": {
            "full_successor_gate_d_readjudication_packet_ref": source_refs["full_readjudication_packet_ref"],
            "full_successor_gate_d_readjudication_receipt_ref": source_refs["full_readjudication_receipt_ref"],
            "successor_master_orchestrator_packet_ref": source_refs["orchestrator_packet_ref"],
            "successor_master_orchestrator_receipt_ref": source_refs["orchestrator_receipt_ref"],
            **(
                {"gate_e_admissibility_screen_receipt_ref": source_refs["gate_e_screen_receipt_ref"]}
                if "gate_e_screen_receipt_ref" in source_refs
                else {}
            ),
        },
        "readjudication_findings_summary": dict(full_readjudication_packet.get("adjudication_findings", {})),
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_successor_gate_d_post_clear_branch_law_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "gate_d_cleared_on_successor_line": True,
        "same_head_counted_reentry_admissible_now": True,
        "gate_d_reopened": True,
        "gate_e_open": gate_e_open_now,
        "current_branch_posture": current_branch_posture,
        "historical_hardened_ceiling_history_preserved": True,
        "next_lawful_move": packet["next_lawful_move"],
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    changed_lines = "\n".join(f"- {item}" for item in packet.get("what_changed", []))
    unchanged_lines = "\n".join(f"- {item}" for item in packet.get("what_did_not_change", []))
    return (
        "# Cohort0 Successor Gate D Post-Clear Branch Law Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Gate D cleared on successor line: `{receipt.get('gate_d_cleared_on_successor_line', False)}`\n"
        f"- Same-head counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', False)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## What Changed\n"
        f"{changed_lines}\n\n"
        "## What Did Not Change\n"
        f"{unchanged_lines}\n"
    )


def run(
    *,
    full_readjudication_packet_path: Path,
    full_readjudication_receipt_path: Path,
    orchestrator_packet_path: Path,
    orchestrator_receipt_path: Path,
    gate_e_screen_receipt_path: Optional[Path] = None,
    reports_root: Path,
) -> Dict[str, Any]:
    full_readjudication_packet = _load_json_required(
        full_readjudication_packet_path, label="full successor Gate D readjudication packet"
    )
    full_readjudication_receipt = _load_json_required(
        full_readjudication_receipt_path, label="full successor Gate D readjudication receipt"
    )
    orchestrator_packet = _load_json_required(orchestrator_packet_path, label="successor master orchestrator packet")
    orchestrator_receipt = _load_json_required(orchestrator_receipt_path, label="successor master orchestrator receipt")
    gate_e_screen_receipt = _load_json_required(
        gate_e_screen_receipt_path, label="Gate E admissibility screen receipt"
    ) if gate_e_screen_receipt_path and gate_e_screen_receipt_path.is_file() else None

    _validate_inputs(
        full_readjudication_packet=full_readjudication_packet,
        full_readjudication_receipt=full_readjudication_receipt,
        orchestrator_packet=orchestrator_packet,
        orchestrator_receipt=orchestrator_receipt,
        gate_e_screen_receipt=gate_e_screen_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            full_readjudication_packet,
            full_readjudication_receipt,
            orchestrator_packet,
            orchestrator_receipt,
        )
    )
    source_refs = {
        "full_readjudication_packet_ref": full_readjudication_packet_path.as_posix(),
        "full_readjudication_receipt_ref": full_readjudication_receipt_path.as_posix(),
        "orchestrator_packet_ref": orchestrator_packet_path.as_posix(),
        "orchestrator_receipt_ref": orchestrator_receipt_path.as_posix(),
        **(
            {"gate_e_screen_receipt_ref": gate_e_screen_receipt_path.as_posix()}
            if gate_e_screen_receipt_path and isinstance(gate_e_screen_receipt, dict)
            else {}
        ),
    }
    outputs = _build_outputs(
        subject_head=subject_head,
        full_readjudication_packet=full_readjudication_packet,
        full_readjudication_receipt=full_readjudication_receipt,
        orchestrator_receipt=orchestrator_receipt,
        gate_e_screen_receipt=gate_e_screen_receipt,
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
        "gate_d_cleared_on_successor_line": True,
        "gate_e_open": outputs["receipt"]["gate_e_open"],
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze the post-clear branch law after successor Gate D clear.")
    parser.add_argument("--full-readjudication-packet", default=DEFAULT_FULL_READJUDICATION_PACKET_REL)
    parser.add_argument("--full-readjudication-receipt", default=DEFAULT_FULL_READJUDICATION_RECEIPT_REL)
    parser.add_argument("--orchestrator-packet", default=DEFAULT_ORCHESTRATOR_PACKET_REL)
    parser.add_argument("--orchestrator-receipt", default=DEFAULT_ORCHESTRATOR_RECEIPT_REL)
    parser.add_argument("--gate-e-screen-receipt", default=DEFAULT_GATE_E_SCREEN_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        full_readjudication_packet_path=_resolve(root, args.full_readjudication_packet),
        full_readjudication_receipt_path=_resolve(root, args.full_readjudication_receipt),
        orchestrator_packet_path=_resolve(root, args.orchestrator_packet),
        orchestrator_receipt_path=_resolve(root, args.orchestrator_receipt),
        gate_e_screen_receipt_path=_resolve(root, args.gate_e_screen_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "gate_d_cleared_on_successor_line",
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
