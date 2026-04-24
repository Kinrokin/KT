from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator import cohort0_successor_gate_d_post_clear_branch_law_tranche as post_clear_branch_law
from tools.operator import cohort0_successor_gate_d_post_clear_supersession_note_tranche as supersession_note
from tools.operator import cohort0_gate_e_precondition_monitor_tranche as gate_e_monitor
from tools.operator import cohort0_gate_e_admissibility_scope_packet_tranche as gate_e_scope
from tools.operator import cohort0_gate_e_post_clear_contradiction_audit_tranche as gate_e_audit
from tools.operator import cohort0_gate_e_comparator_governance_binding_packet_tranche as gate_e_binding_packet
from tools.operator import cohort0_gate_e_comparator_governance_binding_screen_tranche as gate_e_binding_screen
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
DEFAULT_GATE_E_AUDIT_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_audit.OUTPUT_PACKET}"
DEFAULT_GATE_E_AUDIT_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_audit.OUTPUT_RECEIPT}"
DEFAULT_ORCHESTRATOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_packet.json"
DEFAULT_ORCHESTRATOR_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json"
DEFAULT_GATE_E_BINDING_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_binding_packet.OUTPUT_PACKET}"
DEFAULT_GATE_E_BINDING_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_binding_packet.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_BINDING_SCREEN_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_binding_screen.OUTPUT_PACKET}"
DEFAULT_GATE_E_BINDING_SCREEN_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_binding_screen.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = post_clear_branch_law.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_gate_e_admissibility_screen_packet.json"
OUTPUT_BLOCKER_LEDGER = "cohort0_gate_e_admissibility_blocker_ledger.json"
OUTPUT_RECEIPT = "cohort0_gate_e_admissibility_screen_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_E_ADMISSIBILITY_SCREEN_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_E_ADMISSIBILITY_SCREEN_CONVENED"
OUTCOME_OPEN = "GATE_E_OPENED__SUCCESSOR_LINE"
OUTCOME_BOUNDED_DEFECT = "GATE_E_NOT_OPEN__BOUNDED_DEFECT_IDENTIFIED"
OUTCOME_DEFERRED = "DEFERRED__MISSING_GATE_E_SCOPE_PREDICATES"
PREDICATE_GATE_E_BINDING = "gate_e_scope_specific_comparator_governance_bundle_bound"
NEXT_LAWFUL_MOVE_OPEN = "MAINTAIN_GATE_E_OPEN_POSTURE__POST_SUCCESSOR_LINE_CLEAR"
NEXT_LAWFUL_MOVE_DEFECT = "AUTHOR_GATE_E_COMPARATOR_GOVERNANCE_BINDING_PACKET__POST_GATE_E_SCREEN"
NEXT_LAWFUL_MOVE_BINDING_SCREEN = gate_e_binding_packet.NEXT_LAWFUL_MOVE
NEXT_LAWFUL_MOVE_DEFERRED = "RESOLVE_GATE_E_SCOPE_PREDICATES__FAIL_CLOSED"
EXPECTED_CLEAR_POSTURE = gate_e_scope.EXPECTED_CLEAR_POSTURE


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


def _load_json_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: optional JSON must be an object when present: {path.as_posix()}")
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: optional JSON must have status PASS when present: {path.as_posix()}")
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
        raise RuntimeError("FAIL_CLOSED: Gate E admissibility screen requires one same-head authority line")
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
    gate_e_audit_packet: Dict[str, Any],
    gate_e_audit_receipt: Dict[str, Any],
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
        (gate_e_scope_packet, "Gate E admissibility scope packet"),
        (gate_e_scope_receipt, "Gate E admissibility scope receipt"),
        (gate_e_audit_packet, "Gate E post-clear contradiction audit packet"),
        (gate_e_audit_receipt, "Gate E post-clear contradiction audit receipt"),
        (orchestrator_packet, "successor master orchestrator packet"),
        (orchestrator_receipt, "successor master orchestrator receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(full_readjudication_receipt.get("readjudication_outcome", "")).strip() != full_readjudication.OUTCOME_CLEARED:
        raise RuntimeError("FAIL_CLOSED: Gate E admissibility screen requires successor Gate D clear")
    if not bool(full_readjudication_receipt.get("same_head_counted_reentry_admissible_now", False)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain admissible on the successor line")
    if not bool(full_readjudication_receipt.get("gate_d_reopened", False)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain reopened on the successor line")
    if bool(full_readjudication_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must still be closed entering admissibility screen")
    if str(orchestrator_receipt.get("current_branch_posture", "")).strip() != EXPECTED_CLEAR_POSTURE:
        raise RuntimeError("FAIL_CLOSED: orchestrator must remain on the successor Gate D clear posture")


def _determine_core_findings(
    *,
    full_readjudication_receipt: Dict[str, Any],
    post_clear_receipt: Dict[str, Any],
    supersession_receipt: Dict[str, Any],
    gate_e_monitor_receipt: Dict[str, Any],
    gate_e_scope_receipt: Dict[str, Any],
    gate_e_audit_receipt: Dict[str, Any],
) -> Dict[str, bool]:
    return {
        "successor_gate_d_clear_canonical": str(full_readjudication_receipt.get("readjudication_outcome", "")).strip()
        == full_readjudication.OUTCOME_CLEARED,
        "same_head_counted_reentry_admissible_on_successor_line": bool(
            full_readjudication_receipt.get("same_head_counted_reentry_admissible_now", False)
        ),
        "post_clear_branch_law_bound": bool(post_clear_receipt.get("gate_d_cleared_on_successor_line", False)),
        "historical_supersession_explicit": bool(
            supersession_receipt.get(
                "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture", False
            )
        ),
        "gate_e_consideration_authorized": bool(
            gate_e_monitor_receipt.get("gate_e_lawful_consideration_authorized_now", False)
        ),
        "gate_e_scope_authorizes_screen": bool(
            gate_e_scope_receipt.get("gate_e_admissibility_screen_authorized_now", False)
        ),
        "post_clear_live_authority_contradiction_free": bool(
            gate_e_audit_receipt.get("post_clear_live_authority_contradiction_free", False)
        ),
        "gate_e_still_closed": not bool(full_readjudication_receipt.get("gate_e_open", True)),
    }


def _determine_binding_predicate(
    *,
    binding_packet: Optional[Dict[str, Any]],
    binding_receipt: Optional[Dict[str, Any]],
    binding_screen_packet: Optional[Dict[str, Any]],
    binding_screen_receipt: Optional[Dict[str, Any]],
) -> bool:
    if isinstance(binding_screen_receipt, dict):
        return bool(binding_screen_receipt.get("gate_e_binding_confirmed", False)) and bool(
            binding_screen_receipt.get(PREDICATE_GATE_E_BINDING, False)
        )
    if isinstance(binding_screen_packet, dict):
        return bool(binding_screen_packet.get("gate_e_binding_confirmed", False)) and bool(
            binding_screen_packet.get(PREDICATE_GATE_E_BINDING, False)
        )
    return False


def _binding_packet_present(*, binding_packet: Optional[Dict[str, Any]], binding_receipt: Optional[Dict[str, Any]]) -> bool:
    return bool(
        isinstance(binding_receipt, dict)
        and binding_receipt.get(PREDICATE_GATE_E_BINDING, False)
    ) or bool(
        isinstance(binding_packet, dict)
        and binding_packet.get(PREDICATE_GATE_E_BINDING, False)
    )


def _determine_outcome(*, findings: Dict[str, bool]) -> str:
    core_keys = (
        "successor_gate_d_clear_canonical",
        "same_head_counted_reentry_admissible_on_successor_line",
        "post_clear_branch_law_bound",
        "historical_supersession_explicit",
        "gate_e_consideration_authorized",
        "gate_e_scope_authorizes_screen",
        "post_clear_live_authority_contradiction_free",
        "gate_e_still_closed",
    )
    if not all(bool(findings.get(key, False)) for key in core_keys):
        return OUTCOME_DEFERRED
    if bool(findings.get(PREDICATE_GATE_E_BINDING, False)):
        return OUTCOME_OPEN
    return OUTCOME_BOUNDED_DEFECT


def _ranked_missing_predicates(
    *,
    findings: Dict[str, bool],
    binding_packet_present: bool,
    binding_screen_receipt: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    rank = 1
    if not bool(findings.get("post_clear_live_authority_contradiction_free", False)):
        items.append(
            {
                "rank": rank,
                "predicate_id": "post_clear_live_authority_contradiction_free",
                "status": "MISSING",
                "why_it_matters": "Gate E cannot open while the live post-clear authority stack still contradicts itself.",
                "next_tranche": gate_e_audit.NEXT_LAWFUL_MOVE_FAIL,
            }
        )
        rank += 1
    if not bool(findings.get(PREDICATE_GATE_E_BINDING, False)):
        next_tranche = (
            str(binding_screen_receipt.get("next_lawful_move", "")).strip()
            if isinstance(binding_screen_receipt, dict)
            else (
                NEXT_LAWFUL_MOVE_BINDING_SCREEN
                if binding_packet_present
                else NEXT_LAWFUL_MOVE_DEFECT
            )
        )
        items.append(
            {
                "rank": rank,
                "predicate_id": PREDICATE_GATE_E_BINDING,
                "status": "MISSING",
                "why_it_matters": (
                    "Gate E scope exists, but the scope-specific comparator and governance bundle has not yet been "
                    "confirmed by the dedicated binding court."
                ),
                "next_tranche": next_tranche,
            }
        )
    return items


def _build_outputs(
    *,
    findings: Dict[str, bool],
    missing_predicates: List[Dict[str, Any]],
    source_refs: Dict[str, str],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    outcome = _determine_outcome(findings=findings)
    gate_e_open = outcome == OUTCOME_OPEN
    if outcome == OUTCOME_OPEN:
        next_lawful_move = NEXT_LAWFUL_MOVE_OPEN
    elif outcome == OUTCOME_BOUNDED_DEFECT:
        next_lawful_move = missing_predicates[0]["next_tranche"] if missing_predicates else NEXT_LAWFUL_MOVE_DEFECT
    else:
        next_lawful_move = NEXT_LAWFUL_MOVE_DEFERRED
    bounded_defect_id = missing_predicates[0]["predicate_id"] if missing_predicates else ""

    blocker_ledger = {
        "schema_id": "kt.operator.cohort0_gate_e_admissibility_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This ledger ranks only the bounded blockers still preventing Gate E from opening after the admissibility screen. "
            "It does not widen beyond Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "screen_outcome": outcome,
        "ranked_missing_predicates": missing_predicates,
        "bounded_defect_id": bounded_defect_id,
        "source_refs": source_refs,
        "subject_head": subject_head,
    }
    packet = {
        "schema_id": "kt.operator.cohort0_gate_e_admissibility_screen_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This court decides only whether Gate E may open after the successor line cleared Gate D. "
            "It does not widen beyond Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "authority_header": {
            "gate_d_cleared_on_successor_line": True,
            "same_head_counted_reentry_admissible_on_successor_line": True,
            "gate_e_open": gate_e_open,
            "gate_e_screen_only": True,
        },
        "adjudication_question": (
            "Does the bound post-clear successor evidence bundle now justify opening Gate E, or does Gate E remain closed "
            "with one bounded defect still named?"
        ),
        "allowed_outcomes": [
            OUTCOME_OPEN,
            OUTCOME_BOUNDED_DEFECT,
            OUTCOME_DEFERRED,
        ],
        "screen_findings": findings,
        "screen_outcome": outcome,
        "named_bounded_defect_id": bounded_defect_id,
        "gate_e_admissibility_screen_executed": True,
        "gate_e_open": gate_e_open,
        "next_lawful_move": next_lawful_move,
        "blocker_ledger_ref": source_refs["blocker_ledger_ref"],
        "source_refs": source_refs,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_e_admissibility_screen_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "screen_outcome": outcome,
        "named_bounded_defect_id": bounded_defect_id,
        "gate_e_admissibility_screen_executed": True,
        "gate_e_open": gate_e_open,
        "next_lawful_move": next_lawful_move,
        "subject_head": subject_head,
    }
    return {"blocker_ledger": blocker_ledger, "packet": packet, "receipt": receipt}


def _build_report(
    *,
    packet: Dict[str, Any],
    blocker_ledger: Dict[str, Any],
    receipt: Dict[str, Any],
) -> str:
    missing_lines = "\n".join(
        f"- `{item.get('predicate_id', '')}` -> `{item.get('next_tranche', '')}`"
        for item in blocker_ledger.get("ranked_missing_predicates", [])
    ) or "- none"
    return (
        "# Cohort0 Gate E Admissibility Screen Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Screen outcome: `{receipt.get('screen_outcome', '')}`\n"
        f"- Named bounded defect id: `{receipt.get('named_bounded_defect_id', '')}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Ranked Missing Predicates\n"
        f"{missing_lines}\n"
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
    gate_e_audit_packet_path: Path,
    gate_e_audit_receipt_path: Path,
    orchestrator_packet_path: Path,
    orchestrator_receipt_path: Path,
    gate_e_binding_packet_path: Optional[Path] = None,
    gate_e_binding_receipt_path: Optional[Path] = None,
    gate_e_binding_screen_packet_path: Optional[Path] = None,
    gate_e_binding_screen_receipt_path: Optional[Path] = None,
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
    gate_e_audit_packet = _load_json_required(gate_e_audit_packet_path, label="Gate E post-clear contradiction audit packet")
    gate_e_audit_receipt = _load_json_required(gate_e_audit_receipt_path, label="Gate E post-clear contradiction audit receipt")
    orchestrator_packet = _load_json_required(orchestrator_packet_path, label="successor master orchestrator packet")
    orchestrator_receipt = _load_json_required(orchestrator_receipt_path, label="successor master orchestrator receipt")
    binding_packet = _load_json_optional(gate_e_binding_packet_path) if gate_e_binding_packet_path else None
    binding_receipt = _load_json_optional(gate_e_binding_receipt_path) if gate_e_binding_receipt_path else None
    binding_screen_packet = _load_json_optional(gate_e_binding_screen_packet_path) if gate_e_binding_screen_packet_path else None
    binding_screen_receipt = _load_json_optional(gate_e_binding_screen_receipt_path) if gate_e_binding_screen_receipt_path else None

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
        gate_e_audit_packet=gate_e_audit_packet,
        gate_e_audit_receipt=gate_e_audit_receipt,
        orchestrator_packet=orchestrator_packet,
        orchestrator_receipt=orchestrator_receipt,
    )
    packets: List[Dict[str, Any]] = [
        full_readjudication_receipt,
        post_clear_packet,
        post_clear_receipt,
        supersession_note_payload,
        supersession_receipt,
        gate_e_monitor_packet,
        gate_e_monitor_receipt,
        gate_e_scope_packet,
        gate_e_scope_receipt,
        gate_e_audit_packet,
        gate_e_audit_receipt,
        orchestrator_packet,
        orchestrator_receipt,
    ]
    for payload in (binding_packet, binding_receipt, binding_screen_packet, binding_screen_receipt):
        if isinstance(payload, dict):
            packets.append(payload)
    subject_head = _require_same_subject_head(packets)

    findings = _determine_core_findings(
        full_readjudication_receipt=full_readjudication_receipt,
        post_clear_receipt=post_clear_receipt,
        supersession_receipt=supersession_receipt,
        gate_e_monitor_receipt=gate_e_monitor_receipt,
        gate_e_scope_receipt=gate_e_scope_receipt,
        gate_e_audit_receipt=gate_e_audit_receipt,
    )
    findings[PREDICATE_GATE_E_BINDING] = _determine_binding_predicate(
        binding_packet=binding_packet,
        binding_receipt=binding_receipt,
        binding_screen_packet=binding_screen_packet,
        binding_screen_receipt=binding_screen_receipt,
    )
    missing_predicates = _ranked_missing_predicates(
        findings=findings,
        binding_packet_present=_binding_packet_present(
            binding_packet=binding_packet,
            binding_receipt=binding_receipt,
        ),
        binding_screen_receipt=binding_screen_receipt,
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
        "gate_e_audit_packet_ref": gate_e_audit_packet_path.as_posix(),
        "gate_e_audit_receipt_ref": gate_e_audit_receipt_path.as_posix(),
        "orchestrator_packet_ref": orchestrator_packet_path.as_posix(),
        "orchestrator_receipt_ref": orchestrator_receipt_path.as_posix(),
    }
    if gate_e_binding_packet_path and isinstance(binding_packet, dict):
        source_refs["gate_e_binding_packet_ref"] = gate_e_binding_packet_path.as_posix()
    if gate_e_binding_receipt_path and isinstance(binding_receipt, dict):
        source_refs["gate_e_binding_receipt_ref"] = gate_e_binding_receipt_path.as_posix()
    if gate_e_binding_screen_packet_path and isinstance(binding_screen_packet, dict):
        source_refs["gate_e_binding_screen_packet_ref"] = gate_e_binding_screen_packet_path.as_posix()
    if gate_e_binding_screen_receipt_path and isinstance(binding_screen_receipt, dict):
        source_refs["gate_e_binding_screen_receipt_ref"] = gate_e_binding_screen_receipt_path.as_posix()

    reports_root.mkdir(parents=True, exist_ok=True)
    blocker_ledger_path = reports_root / OUTPUT_BLOCKER_LEDGER
    source_refs["blocker_ledger_ref"] = blocker_ledger_path.resolve().as_posix()
    outputs = _build_outputs(
        findings=findings,
        missing_predicates=missing_predicates,
        source_refs=source_refs,
        subject_head=subject_head,
    )

    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(blocker_ledger_path, outputs["blocker_ledger"])
    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(
        report_path,
        _build_report(
            packet=outputs["packet"],
            blocker_ledger=outputs["blocker_ledger"],
            receipt=outputs["receipt"],
        ),
    )

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "screen_outcome": outputs["receipt"]["screen_outcome"],
        "named_bounded_defect_id": outputs["receipt"]["named_bounded_defect_id"],
        "gate_e_open": outputs["receipt"]["gate_e_open"],
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 4,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convene the bounded Gate E admissibility screen.")
    parser.add_argument("--full-readjudication-receipt", default=DEFAULT_FULL_READJUDICATION_RECEIPT_REL)
    parser.add_argument("--post-clear-packet", default=DEFAULT_POST_CLEAR_PACKET_REL)
    parser.add_argument("--post-clear-receipt", default=DEFAULT_POST_CLEAR_RECEIPT_REL)
    parser.add_argument("--supersession-note", default=DEFAULT_SUPERSESSION_NOTE_REL)
    parser.add_argument("--supersession-receipt", default=DEFAULT_SUPERSESSION_RECEIPT_REL)
    parser.add_argument("--gate-e-monitor-packet", default=DEFAULT_GATE_E_MONITOR_PACKET_REL)
    parser.add_argument("--gate-e-monitor-receipt", default=DEFAULT_GATE_E_MONITOR_RECEIPT_REL)
    parser.add_argument("--gate-e-scope-packet", default=DEFAULT_GATE_E_SCOPE_PACKET_REL)
    parser.add_argument("--gate-e-scope-receipt", default=DEFAULT_GATE_E_SCOPE_RECEIPT_REL)
    parser.add_argument("--gate-e-audit-packet", default=DEFAULT_GATE_E_AUDIT_PACKET_REL)
    parser.add_argument("--gate-e-audit-receipt", default=DEFAULT_GATE_E_AUDIT_RECEIPT_REL)
    parser.add_argument("--orchestrator-packet", default=DEFAULT_ORCHESTRATOR_PACKET_REL)
    parser.add_argument("--orchestrator-receipt", default=DEFAULT_ORCHESTRATOR_RECEIPT_REL)
    parser.add_argument("--gate-e-binding-packet", default=DEFAULT_GATE_E_BINDING_PACKET_REL)
    parser.add_argument("--gate-e-binding-receipt", default=DEFAULT_GATE_E_BINDING_RECEIPT_REL)
    parser.add_argument("--gate-e-binding-screen-packet", default=DEFAULT_GATE_E_BINDING_SCREEN_PACKET_REL)
    parser.add_argument("--gate-e-binding-screen-receipt", default=DEFAULT_GATE_E_BINDING_SCREEN_RECEIPT_REL)
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
        gate_e_audit_packet_path=_resolve(root, args.gate_e_audit_packet),
        gate_e_audit_receipt_path=_resolve(root, args.gate_e_audit_receipt),
        orchestrator_packet_path=_resolve(root, args.orchestrator_packet),
        orchestrator_receipt_path=_resolve(root, args.orchestrator_receipt),
        gate_e_binding_packet_path=_resolve(root, args.gate_e_binding_packet),
        gate_e_binding_receipt_path=_resolve(root, args.gate_e_binding_receipt),
        gate_e_binding_screen_packet_path=_resolve(root, args.gate_e_binding_screen_packet),
        gate_e_binding_screen_receipt_path=_resolve(root, args.gate_e_binding_screen_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "screen_outcome",
        "named_bounded_defect_id",
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
