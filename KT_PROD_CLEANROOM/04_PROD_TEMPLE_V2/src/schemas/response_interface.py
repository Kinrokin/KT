"""Explicit prospective interfaces; legacy task/checker/training semantics stay v1.

Binding derives provenance, not answers or authority. Raw model text is retained
separately by the runtime. Only an operator-admitted v2 operation selects this.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from schemas.checked_task import (
    CheckedTaskError, MAX_BYTES, PROPOSAL_SCHEMA, _constraint_feedback,
    canonical_bytes, check_proposal, identity, parse_proposal, strict_json, validate_task,
)


def validate_interface(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {"mode", "display_nonce"}:
        raise CheckedTaskError("INTERFACE_FIELDS")
    mode, display = value["mode"], value["display_nonce"]
    if mode == "host_bound_answer":
        if display is not None:
            raise CheckedTaskError("INTERFACE_DISPLAY_FORBIDDEN")
    elif mode == "full_envelope_control":
        if type(display) is not str or re.fullmatch(r"[0-9a-f]{32}", display) is None:
            raise CheckedTaskError("INTERFACE_DISPLAY_NONCE")
    else:
        raise CheckedTaskError("INTERFACE_MODE")
    return strict_json(canonical_bytes(value))


def bind_proposal(raw: str, task: dict[str, Any], *, nonce: str,
                  interface: dict[str, Any]) -> dict[str, Any]:
    interface = validate_interface(interface)
    task = validate_task(task)
    if interface["mode"] == "host_bound_answer":
        value = strict_json(raw)
        if type(value) is not dict or set(value) != {"answer"}:
            raise CheckedTaskError("ANSWER_ONLY_FIELDS")
    else:
        value = parse_proposal(raw, task, nonce=interface["display_nonce"])
    proposal = {"schema_id": PROPOSAL_SCHEMA, "task_hash": identity(task),
                "nonce": nonce, "answer": value["answer"]}
    # Reuse all strict answer types and identity validation; no solver or fallback.
    return parse_proposal(canonical_bytes(proposal), task, nonce=nonce)


def derive_proposal(raw: str, task: dict[str, Any], *, nonce: str,
                    interface: dict[str, Any], contract_hash: str,
                    operation_id: str, attempt: int, request: dict[str, Any]):
    interface = validate_interface(interface)
    derivation = {"schema_id": "kt.lab.host_derivation.v1", "interface": interface,
                  "contract_sha256": contract_hash, "operation_id": operation_id,
                  "attempt": attempt, "request_hash": identity(request),
                  "task_hash": identity(task), "outer_nonce": nonce,
                  "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                  "origin": "HOST_DERIVED_FROM_PRESERVED_MODEL_TEXT",
                  "execution_permission": "NOT_GRANTED"}
    try:
        proposal = bind_proposal(raw, task, nonce=nonce, interface=interface)
        check = check_proposal(task, proposal, nonce=nonce)
        derivation.update(proposal=proposal, proposal_hash=identity(proposal), rejection=None)
    except CheckedTaskError as exc:
        proposal = None
        check = {"satisfied": False, "diagnostics": [str(exc)], "scope": "MALFORMED_OR_UNBOUND_PROPOSAL"}
        derivation.update(proposal=None, proposal_hash=None, rejection=str(exc))
    return proposal, check, derivation


def build_interface_prompt(task: dict[str, Any], *, nonce: str,
                           history: list[dict[str, Any]], interface: dict[str, Any]) -> str:
    task, interface = validate_task(task), validate_interface(interface)
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise CheckedTaskError("NONCE")
    if type(history) is not list or len(history) > 2:
        raise CheckedTaskError("REVISION_LIMIT")
    sanitized = []
    for entry in history:
        if type(entry) is not dict or set(entry) != {"raw", "nonce", "feedback_mode"}:
            raise CheckedTaskError("HISTORY_FIELDS")
        mode = entry["feedback_mode"]
        if mode not in ("self_review", "kt_diagnostic", "kt_constraint_detail", "sham", "nonconsuming"):
            raise CheckedTaskError("HISTORY_MODE")
        try:
            previous = bind_proposal(entry["raw"], task, nonce=entry["nonce"], interface=interface)
        except CheckedTaskError:
            previous = None
        feedback = "Review your prior answer independently against the public task."
        if mode in ("kt_diagnostic", "nonconsuming"):
            feedback = (check_proposal(task, previous, nonce=entry["nonce"])["diagnostics"]
                        if previous is not None else ["MALFORMED_OR_UNBOUND_PROPOSAL"])
        elif mode == "kt_constraint_detail":
            feedback = (_constraint_feedback(task, previous, nonce=entry["nonce"])
                        if previous is not None else ["MALFORMED_OR_UNBOUND_PROPOSAL"])
        elif mode == "sham":
            feedback = "A diagnostic stage ran. No task-specific diagnostic is supplied."
        # Never relay outer identities or host envelopes into model-visible history.
        sanitized.append({"previous_answer": previous["answer"] if previous is not None else None,
                          "feedback": feedback})
    answer_type = ("JSON integer, not quoted and not null" if task["kind"] == "integer_arithmetic"
                   else "JSON array of selected project ID strings")
    required = {"answer": answer_type}
    instructions = "Return exactly one JSON object with the single key answer. "
    if interface["mode"] == "full_envelope_control":
        required = {"schema_id": PROPOSAL_SCHEMA, "task_hash": identity(task),
                    "nonce": interface["display_nonce"], "answer": answer_type}
        instructions = ("Return exactly one JSON object with all four keys: schema_id, task_hash, nonce, answer. "
                        "Copy schema_id, task_hash and nonce exactly from required_output; compute only answer. ")
    body = canonical_bytes({"task": task, "prior_attempts": sanitized, "required_output": required})
    if len(body) > MAX_BYTES:
        raise CheckedTaskError("PROMPT_SIZE")
    return ("Solve the public task. " + instructions +
            "Use the specified JSON answer type. The answer type description is an instruction, "
            "not the answer to copy. For constrained_plan maximize value subject to every declared constraint. "
            "No commentary or additional keys.\n" + body.decode("utf-8"))
