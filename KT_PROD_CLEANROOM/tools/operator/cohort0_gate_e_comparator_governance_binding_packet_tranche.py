from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator import cohort0_successor_gate_d_post_clear_branch_law_tranche as post_clear_branch_law
from tools.operator import cohort0_successor_gate_d_post_clear_supersession_note_tranche as supersession_note
from tools.operator import cohort0_gate_e_precondition_monitor_tranche as gate_e_monitor
from tools.operator import cohort0_gate_e_admissibility_scope_packet_tranche as gate_e_scope
from tools.operator import cohort0_gate_e_post_clear_contradiction_audit_tranche as gate_e_audit
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
DEFAULT_GATE_E_SCREEN_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_e_admissibility_screen_packet.json"
DEFAULT_GATE_E_SCREEN_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_e_admissibility_screen_receipt.json"
DEFAULT_ORCHESTRATOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_packet.json"
DEFAULT_ORCHESTRATOR_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json"
DEFAULT_REPORTS_ROOT_REL = post_clear_branch_law.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_gate_e_comparator_governance_binding_packet.json"
OUTPUT_RECEIPT = "cohort0_gate_e_comparator_governance_binding_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_E_COMPARATOR_GOVERNANCE_BINDING_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_E_COMPARATOR_GOVERNANCE_BINDING_PACKET_AUTHORED"
PREDICATE_GATE_E_BINDING = "gate_e_scope_specific_comparator_governance_bundle_bound"
ARTIFACT_READY_PREDICATE = "gate_e_binding_packet_artifact_ready_for_screen"
GATE_E_SCREEN_OUTCOME_BOUNDED_DEFECT = "GATE_E_NOT_OPEN__BOUNDED_DEFECT_IDENTIFIED"
EXPECTED_CLEAR_POSTURE = gate_e_scope.EXPECTED_CLEAR_POSTURE
NEXT_LAWFUL_MOVE = "CONVENE_GATE_E_COMPARATOR_GOVERNANCE_BINDING_SCREEN__POST_BINDING_PACKET"


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
        raise RuntimeError("FAIL_CLOSED: Gate E comparator/governance binding packet requires one same-head authority line")
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
    gate_e_screen_packet: Dict[str, Any],
    gate_e_screen_receipt: Dict[str, Any],
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
        (gate_e_screen_packet, "Gate E admissibility screen packet"),
        (gate_e_screen_receipt, "Gate E admissibility screen receipt"),
        (orchestrator_packet, "successor master orchestrator packet"),
        (orchestrator_receipt, "successor master orchestrator receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(full_readjudication_receipt.get("readjudication_outcome", "")).strip() != full_readjudication.OUTCOME_CLEARED:
        raise RuntimeError("FAIL_CLOSED: Gate E binding packet requires successor Gate D clear")
    if not bool(full_readjudication_receipt.get("same_head_counted_reentry_admissible_now", False)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain admissible on the successor line")
    if not bool(full_readjudication_receipt.get("gate_d_reopened", False)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain reopened entering Gate E binding")
    if bool(full_readjudication_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering Gate E binding")
    if not bool(post_clear_receipt.get("gate_d_cleared_on_successor_line", False)):
        raise RuntimeError("FAIL_CLOSED: post-clear branch law must already be bound")
    if not bool(
        supersession_receipt.get("successor_line_supersedes_prior_same_head_failure_for_live_branch_posture", False)
    ):
        raise RuntimeError("FAIL_CLOSED: supersession must be explicit before Gate E binding")
    if not bool(gate_e_monitor_receipt.get("gate_e_lawful_consideration_authorized_now", False)):
        raise RuntimeError("FAIL_CLOSED: Gate E consideration must already be authorized")
    if not bool(gate_e_scope_receipt.get("gate_e_admissibility_screen_authorized_now", False)):
        raise RuntimeError("FAIL_CLOSED: Gate E admissibility screen must already be authorized")
    if not bool(gate_e_audit_receipt.get("post_clear_live_authority_contradiction_free", False)):
        raise RuntimeError("FAIL_CLOSED: live post-clear authority must remain contradiction-free")
    if str(gate_e_screen_receipt.get("screen_outcome", "")).strip() != GATE_E_SCREEN_OUTCOME_BOUNDED_DEFECT:
        raise RuntimeError("FAIL_CLOSED: Gate E binding packet requires a real bounded-defect screen result")
    if str(gate_e_screen_receipt.get("named_bounded_defect_id", "")).strip() != PREDICATE_GATE_E_BINDING:
        raise RuntimeError("FAIL_CLOSED: Gate E binding packet requires the exact comparator/governance blocker seam")
    if bool(gate_e_screen_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E screen must still keep Gate E closed")
    if str(orchestrator_receipt.get("current_branch_posture", "")).strip() != EXPECTED_CLEAR_POSTURE:
        raise RuntimeError("FAIL_CLOSED: orchestrator must remain on the successor Gate D cleared posture")


def _build_outputs(*, subject_head: str, source_refs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    governance_bundle = [
        {
            "bundle_element_id": "bounded_operator_authority",
            "status": "BOUND",
            "obligation": "Gate E must remain within explicitly bounded operator authority and may not widen from Gate D clear by momentum.",
            "source_refs": [
                source_refs["gate_e_monitor_packet_ref"],
                source_refs["post_clear_packet_ref"],
            ],
        },
        {
            "bundle_element_id": "replayability_and_audit_completeness",
            "status": "BOUND",
            "obligation": "Gate E-facing objects must remain replayable, audit-complete, and contradiction-free across the live authority stack.",
            "source_refs": [
                source_refs["gate_e_audit_packet_ref"],
                source_refs["gate_e_audit_receipt_ref"],
                source_refs["orchestrator_packet_ref"],
            ],
        },
        {
            "bundle_element_id": "promotion_and_rollback_governance",
            "status": "BOUND",
            "obligation": "Any Gate E movement must preserve explicit promotion and rollback implications rather than assuming post-D momentum equals entitlement.",
            "source_refs": [
                source_refs["post_clear_packet_ref"],
                source_refs["supersession_note_ref"],
                source_refs["orchestrator_receipt_ref"],
            ],
        },
        {
            "bundle_element_id": "scope_limited_control_expectations",
            "status": "BOUND",
            "obligation": "Gate E remains scope-limited and fail-closed until a later court opens it; control expectations remain constrained to the current E-scope object.",
            "source_refs": [
                source_refs["gate_e_scope_packet_ref"],
                source_refs["gate_e_scope_receipt_ref"],
                source_refs["gate_e_screen_packet_ref"],
            ],
        },
        {
            "bundle_element_id": "fail_closed_stage_progression",
            "status": "BOUND",
            "obligation": "The branch must continue to fail closed on any missing Gate E predicate and may not infer E opening from D clear plus scope alone.",
            "source_refs": [
                source_refs["gate_e_screen_receipt_ref"],
                source_refs["orchestrator_receipt_ref"],
            ],
        },
    ]
    predicate_to_evidence_map = [
        {
            "predicate_id": "successor_gate_d_clear_canonical",
            "current_status": "SATISFIED",
            "source_refs": [source_refs["full_readjudication_receipt_ref"]],
            "satisfaction_rule": "The successor line must already have a receipt-backed Gate D clear.",
            "failure_rule": "If Gate D is not cleared on the successor line, Gate E binding cannot lawfully begin.",
        },
        {
            "predicate_id": "gate_e_lawful_consideration_authorized_now",
            "current_status": "SATISFIED",
            "source_refs": [source_refs["gate_e_monitor_receipt_ref"]],
            "satisfaction_rule": "Gate E consideration must already be authorized by the post-clear precondition monitor.",
            "failure_rule": "If Gate E consideration is not authorized, the comparator/governance bundle cannot advance beyond precondition monitoring.",
        },
        {
            "predicate_id": "gate_e_admissibility_screen_authorized_now",
            "current_status": "SATISFIED",
            "source_refs": [source_refs["gate_e_scope_receipt_ref"]],
            "satisfaction_rule": "Gate E scope must already authorize a later admissibility screen while keeping Gate E closed.",
            "failure_rule": "If the admissibility screen is not authorized, Gate E binding cannot become a lawful next court.",
        },
        {
            "predicate_id": "post_clear_live_authority_contradiction_free",
            "current_status": "SATISFIED",
            "source_refs": [source_refs["gate_e_audit_receipt_ref"]],
            "satisfaction_rule": "The live post-clear authority stack must remain contradiction-free.",
            "failure_rule": "Any stale contradiction fail-closes the binding layer until corrected.",
        },
        {
            "predicate_id": PREDICATE_GATE_E_BINDING,
            "current_status": "SATISFIED",
            "source_refs": [
                source_refs["gate_e_screen_receipt_ref"],
                source_refs["post_clear_packet_ref"],
                source_refs["gate_e_monitor_packet_ref"],
                source_refs["gate_e_scope_packet_ref"],
                source_refs["orchestrator_packet_ref"],
            ],
            "satisfaction_rule": (
                "Gate E-specific comparator definition, governance bundle, predicate-to-evidence map, and non-claim boundary "
                "are all bound into one reproducible packet while Gate E remains closed."
            ),
            "failure_rule": (
                "If comparator definition, governance obligations, or non-claim boundaries are missing or ambiguous, "
                "the Gate E comparator/governance seam remains unclosed."
            ),
        },
    ]
    packet = {
        "schema_id": "kt.operator.cohort0_gate_e_comparator_governance_binding_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet binds only the Gate E-specific comparator and governance bundle after successor Gate D clear. "
            "It does not open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "authority_header": {
            "gate_d_cleared_on_successor_line": True,
            "same_head_counted_reentry_admissible_on_successor_line": True,
            "gate_e_open": False,
            "gate_e_binding_only": True,
        },
        "gate_e_comparator_definition": {
            "gate_e_scope_specific_comparator_id": "GATE_E_SCOPE_SPECIFIC_COMPARATOR__SUCCESSOR_LINE_V1",
            "gate_d_inherited_court": "SUCCESSOR_SAME_HEAD_ROUTE_CONSEQUENCE_COURT",
            "gate_d_question": (
                "Did routed successor judgment become causally consequential enough over the best static path to clear Gate D?"
            ),
            "gate_e_question": (
                "Given Gate D clear on the successor line, what exact comparator and governance relationship must now hold "
                "before Gate E can become admissible without widening beyond current receipts?"
            ),
            "gate_e_difference_from_gate_d": (
                "Gate D asked for route-consequence superiority on the same-head court. Gate E keeps that clear fixed and adds "
                "a post-clear comparator/governance burden: E may advance only if the successor line stays comparator-legible, "
                "governance-bound, replayable, and fail-closed under the E-specific bundle."
            ),
            "lawful_gate_e_win_or_derisk_condition": (
                "A lawful Gate E move must show either a bounded comparator win or sufficient governance-backed de-risking "
                "under the E-specific bundle; Gate D clear alone is not enough."
            ),
        },
        "gate_e_governance_bundle": governance_bundle,
        "predicate_to_evidence_map": predicate_to_evidence_map,
        "explicit_non_claims": [
            "This packet does not open Gate E.",
            "This packet does not imply Gate F.",
            "This packet does not imply re-audit.",
            "This packet does not widen the theorem beyond current receipts.",
            "This packet does not treat Gate D clear as automatic Gate E entitlement.",
        ],
        "allowed_next_outcomes": [
            "GATE_E_BINDING_CONFIRMED__ADMISSIBILITY_REVIEW_MAY_BE_CONVENED",
            "GATE_E_BINDING_INCOMPLETE__BOUNDED_DEFECT_REMAINS",
            "DEFERRED__SPECIFIC_BINDING_PREDICATE_MISSING",
        ],
        "binding_findings": {
            "successor_gate_d_clear_canonical": True,
            "gate_e_consideration_authorized": True,
            "gate_e_scope_authorizes_screen": True,
            "post_clear_live_authority_contradiction_free": True,
            "gate_e_specific_comparator_defined": True,
            "gate_e_specific_governance_bundle_defined": True,
            "predicate_to_evidence_map_complete": True,
            "explicit_non_claims_bound": True,
            PREDICATE_GATE_E_BINDING: True,
            ARTIFACT_READY_PREDICATE: True,
        },
        PREDICATE_GATE_E_BINDING: True,
        ARTIFACT_READY_PREDICATE: True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "source_refs": source_refs,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_e_comparator_governance_binding_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "gate_e_comparator_governance_binding_packet_authored": True,
        PREDICATE_GATE_E_BINDING: True,
        ARTIFACT_READY_PREDICATE: True,
        "gate_e_open": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    governance_lines = "\n".join(
        f"- `{item.get('bundle_element_id', '')}` -> `{item.get('status', '')}`"
        for item in packet.get("gate_e_governance_bundle", [])
    )
    predicate_lines = "\n".join(
        f"- `{item.get('predicate_id', '')}` -> `{item.get('current_status', '')}`"
        for item in packet.get("predicate_to_evidence_map", [])
    )
    return (
        "# Cohort0 Gate E Comparator Governance Binding Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Binding predicate: `{PREDICATE_GATE_E_BINDING}`\n"
        f"- Bound now: `{receipt.get(PREDICATE_GATE_E_BINDING, False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Governance Bundle\n"
        f"{governance_lines}\n\n"
        "## Predicate Map\n"
        f"{predicate_lines}\n"
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
    gate_e_screen_packet_path: Path,
    gate_e_screen_receipt_path: Path,
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
    gate_e_scope_packet = _load_json_required(gate_e_scope_packet_path, label="Gate E admissibility scope packet")
    gate_e_scope_receipt = _load_json_required(gate_e_scope_receipt_path, label="Gate E admissibility scope receipt")
    gate_e_audit_packet = _load_json_required(gate_e_audit_packet_path, label="Gate E post-clear contradiction audit packet")
    gate_e_audit_receipt = _load_json_required(gate_e_audit_receipt_path, label="Gate E post-clear contradiction audit receipt")
    gate_e_screen_packet = _load_json_required(gate_e_screen_packet_path, label="Gate E admissibility screen packet")
    gate_e_screen_receipt = _load_json_required(gate_e_screen_receipt_path, label="Gate E admissibility screen receipt")
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
        gate_e_scope_packet=gate_e_scope_packet,
        gate_e_scope_receipt=gate_e_scope_receipt,
        gate_e_audit_packet=gate_e_audit_packet,
        gate_e_audit_receipt=gate_e_audit_receipt,
        gate_e_screen_packet=gate_e_screen_packet,
        gate_e_screen_receipt=gate_e_screen_receipt,
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
            gate_e_scope_packet,
            gate_e_scope_receipt,
            gate_e_audit_packet,
            gate_e_audit_receipt,
            gate_e_screen_packet,
            gate_e_screen_receipt,
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
        "gate_e_scope_packet_ref": gate_e_scope_packet_path.as_posix(),
        "gate_e_scope_receipt_ref": gate_e_scope_receipt_path.as_posix(),
        "gate_e_audit_packet_ref": gate_e_audit_packet_path.as_posix(),
        "gate_e_audit_receipt_ref": gate_e_audit_receipt_path.as_posix(),
        "gate_e_screen_packet_ref": gate_e_screen_packet_path.as_posix(),
        "gate_e_screen_receipt_ref": gate_e_screen_receipt_path.as_posix(),
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
        PREDICATE_GATE_E_BINDING: outputs["receipt"][PREDICATE_GATE_E_BINDING],
        "gate_e_open": False,
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the Gate E comparator/governance binding packet.")
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
    parser.add_argument("--gate-e-screen-packet", default=DEFAULT_GATE_E_SCREEN_PACKET_REL)
    parser.add_argument("--gate-e-screen-receipt", default=DEFAULT_GATE_E_SCREEN_RECEIPT_REL)
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
        gate_e_scope_packet_path=_resolve(root, args.gate_e_scope_packet),
        gate_e_scope_receipt_path=_resolve(root, args.gate_e_scope_receipt),
        gate_e_audit_packet_path=_resolve(root, args.gate_e_audit_packet),
        gate_e_audit_receipt_path=_resolve(root, args.gate_e_audit_receipt),
        gate_e_screen_packet_path=_resolve(root, args.gate_e_screen_packet),
        gate_e_screen_receipt_path=_resolve(root, args.gate_e_screen_receipt),
        orchestrator_packet_path=_resolve(root, args.orchestrator_packet),
        orchestrator_receipt_path=_resolve(root, args.orchestrator_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        PREDICATE_GATE_E_BINDING,
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
