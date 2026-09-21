"""Canonical laboratory path: fresh generation, bounded checks and a sandbox effect."""
from __future__ import annotations

import hashlib
from pathlib import Path
import secrets
import time
from typing import Any

from core.semantic_probe import require_canonical_entry_attestation
from council.providers.local_qwen import LocalQwenBackend
from governance.lab_admission import REQUEST_SCHEMA, current_session, validate_contract
from memory.lab_effect import apply_checked_effect, read_record, recover_effect, write_record
from schemas.checked_task import (CheckedTaskError, build_prompt, canonical_bytes, check_proposal,
                                 identity, parse_proposal, strict_json)

from schemas.response_interface import build_interface_prompt, derive_proposal


def _prompt(op, *, nonce, history):
    if "response_interface" in op:
        return build_interface_prompt(op["task"], nonce=nonce, history=history, interface=op["response_interface"])
    return build_prompt(op["task"], nonce=nonce, history=history)


def verify_generation(raw: dict[str, Any], *, nonce: str, prompt: str, cap: int,
                      contract_sha256: str, adapter_required: bool) -> None:
    if (raw.get("kind") != "GENERATED" or raw.get("fresh_generation") is not True
            or raw.get("contract_sha256") != contract_sha256 or raw.get("nonce") != nonce
            or raw.get("prompt_sha256") != hashlib.sha256(prompt.encode()).hexdigest()):
        raise RuntimeError("LAB_GENERATION_IDENTITY")
    for field, count in (("input_token_ids", "input_tokens"), ("generated_token_ids", "output_tokens")):
        ids = raw.get(field)
        if (type(ids) is not list or not ids or len(ids) > 8192
                or any(type(token) is not int or not 0 <= token < 2**32 for token in ids)
                or type(raw.get(count)) is not int or raw[count] != len(ids)):
            raise RuntimeError("LAB_GENERATION_USAGE")
    if type(raw.get("max_new_tokens")) is not int or raw["max_new_tokens"] != cap or raw["output_tokens"] > cap:
        raise RuntimeError("LAB_OUTPUT_CAP")
    if (type(raw.get("output_text")) is not str or len(raw["output_text"].encode()) > 32768
            or type(raw.get("eos_token_ids")) is not list or not raw["eos_token_ids"]
            or any(type(token) is not int for token in raw["eos_token_ids"])
            or raw.get("finish_reason") != "EOS" or raw["generated_token_ids"][-1] not in raw["eos_token_ids"]):
        raise RuntimeError("LAB_GENERATION_INCOMPLETE")
    if adapter_required:
        observation = raw.get("adapter_observation", {})
        magnitude = observation.get("abs_max")
        if (type(observation.get("calls")) is not int or observation["calls"] <= 0
                or type(magnitude) not in (int, float) or not 0 < magnitude < float("inf")):
            raise RuntimeError("LAB_ADAPTER_CONTRIBUTION_UNOBSERVED")


def _terminal(root: Path, result: dict[str, Any]) -> dict[str, Any]:
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(root.iterdir()) if p.is_file() and p.name not in {"result.json", "sandbox_state.json"}}
    result = {**result, "files": files}
    write_record(root / "result.json", result)
    return result


def verify_operation(root: Path, *, expected_contract_sha256: str) -> dict[str, Any]:
    """Reconstruct a completed verdict; no inference, effect, or authority activation."""
    result = read_record(root / "result.json")
    contract_bytes = (root.parent / "operator_contract.json").read_bytes()
    if hashlib.sha256(contract_bytes).hexdigest() != expected_contract_sha256:
        raise RuntimeError("LAB_REPLAY_TRUST_ANCHOR")
    contract = validate_contract(strict_json(contract_bytes, max_bytes=2 * 1024 * 1024))
    op = contract["operations"].get(root.name)
    if (op is None or result.get("operation_id") != root.name or result.get("contract_sha256") != expected_contract_sha256
            or result.get("task") != op["task"] or result.get("strategy") != op["strategy"]
            or result.get("adapter_required") != (contract["backend"]["adapter_root"] is not None)):
        raise RuntimeError("LAB_REPLAY_OPERATION_BINDING")
    versioned = "response_interface" in op
    if (result.get("schema_id") != ("kt.lab.operation_result.v2" if versioned else "kt.lab.operation_result.v1")
            or (versioned and result.get("response_interface") != op["response_interface"])
            or (not versioned and "response_interface" in result)):
        raise RuntimeError("LAB_REPLAY_INTERFACE_BINDING")
    post_recovery = (root / "effect_recovered.json").exists() and "effect_recovered.json" not in result["files"]
    excluded = {"result.json", "sandbox_state.json"} | ({"effect_recovered.json"} if post_recovery else set())
    actual = {p.name for p in root.iterdir() if p.is_file() and p.name not in excluded}
    if actual != set(result["files"]):
        raise RuntimeError("LAB_REPLAY_FILE_COVERAGE")
    for name, sha in result["files"].items():
        if Path(name).name != name or hashlib.sha256((root / name).read_bytes()).hexdigest() != sha:
            raise RuntimeError("LAB_REPLAY_BYTES")
    reservations = sorted(root.glob("attempt_*_reserved.json"))
    if (not reservations or len(reservations) > op["attempts"]
            or [p.name for p in reservations] != [f"attempt_{i}_reserved.json" for i in range(len(reservations))]
            or result.get("model_calls") != len(reservations)):
        raise RuntimeError("LAB_REPLAY_ATTEMPT_ACCOUNTING")
    completed = [i for i in range(len(reservations)) if (root / f"attempt_{i}_check.json").exists()]
    if result.get("attempts") != completed or completed != list(range(len(completed))):
        raise RuntimeError("LAB_REPLAY_COMPLETED_ROSTER")
    expected_derivations = {f"attempt_{i}_derivation.json" for i in completed} if versioned else set()
    if {p.name for p in root.glob("*_derivation.json")} != expected_derivations:
        raise RuntimeError("LAB_REPLAY_DERIVATION_ROSTER")
    history = []
    seen_nonces = set()
    input_tokens = output_tokens = 0
    final_proposal = None
    final_check = {"satisfied": False}
    for attempt in completed:
        request = read_record(root / f"attempt_{attempt}_request.json")
        raw = read_record(root / f"attempt_{attempt}_raw.json")
        check = read_record(root / f"attempt_{attempt}_check.json")
        if request["max_new_tokens"] != contract["limits"]["max_new_tokens"]:
            raise RuntimeError("LAB_REPLAY_AUTHORIZED_CAP")
        if versioned:
            if (set(request) != {"prompt", "nonce", "max_new_tokens", "task_hash", "response_interface"}
                    or request["response_interface"] != op["response_interface"]):
                raise RuntimeError("LAB_REPLAY_REQUEST_INTERFACE")
            if request["nonce"] in seen_nonces:
                raise RuntimeError("LAB_REPLAY_DUPLICATE_NONCE")
            seen_nonces.add(request["nonce"])
        expected_prompt = _prompt(op, nonce=request["nonce"], history=history)
        reservation = read_record(root / f"attempt_{attempt}_reserved.json")
        if (request["prompt"] != expected_prompt or request["task_hash"] != identity(op["task"])
                or reservation != {"operation_id": root.name, "attempt": attempt,
                    "prompt_hash": hashlib.sha256(expected_prompt.encode()).hexdigest(),
                    "max_new_tokens": contract["limits"]["max_new_tokens"], "contract_sha256": expected_contract_sha256}):
            raise RuntimeError("LAB_REPLAY_REQUEST_BINDING")
        verify_generation(raw, nonce=request["nonce"], prompt=request["prompt"], cap=contract["limits"]["max_new_tokens"],
                          contract_sha256=result["contract_sha256"], adapter_required=result["adapter_required"])
        if versioned:
            proposal, computed, derived = derive_proposal(raw["output_text"], op["task"], nonce=request["nonce"],
                interface=op["response_interface"], contract_hash=expected_contract_sha256,
                operation_id=root.name, attempt=attempt, request=request)
            if read_record(root / f"attempt_{attempt}_derivation.json") != derived:
                raise RuntimeError("LAB_REPLAY_DERIVATION_MISMATCH")
        else:
            try:
                proposal = parse_proposal(raw["output_text"], result["task"], nonce=request["nonce"])
                computed = check_proposal(result["task"], proposal, nonce=request["nonce"])
            except CheckedTaskError as exc:
                proposal = None
                computed = {"satisfied": False, "diagnostics": [str(exc)], "scope": "MALFORMED_OR_UNBOUND_PROPOSAL"}
        if computed != check:
            raise RuntimeError("LAB_REPLAY_CHECKER_MISMATCH")
        final_proposal, final_check = proposal, check
        input_tokens += raw["input_tokens"]
        output_tokens += raw["output_tokens"]
        if op["strategy"] != "direct":
            history.append({"raw": raw["output_text"], "nonce": request["nonce"], "feedback_mode": op["strategy"]})
        if attempt < len(reservations) - 1 and (op["strategy"] == "direct" or
                (op["strategy"] in ("kt_diagnostic", "kt_constraint_detail", "nonconsuming") and check["satisfied"])):
            raise RuntimeError("LAB_REPLAY_UNAUTHORIZED_EXTRA_ATTEMPT")
    if result.get("input_tokens") != input_tokens or result.get("output_tokens") != output_tokens:
        raise RuntimeError("LAB_REPLAY_TOKEN_TOTALS")
    status = result.get("status")
    if len(completed) != len(reservations):
        if (len(reservations) != len(completed) + 1 or status != "HOLD_GENERATION_FAILED"
                or not (root / f"attempt_{len(completed)}_failure.json").exists()):
            raise RuntimeError("LAB_REPLAY_PARTIAL_GENERATION_CLAIM")
    elif (len(completed) != op["attempts"] and not (op["strategy"] == "direct" or
            (op["strategy"] in ("kt_diagnostic", "kt_constraint_detail", "nonconsuming") and final_check["satisfied"]))):
        raise RuntimeError("LAB_REPLAY_TRUNCATED_ROSTER")
    elif not final_check["satisfied"]:
        if status != "HELD_TASK_PREDICATE" or (root / "effect_applied.json").exists():
            raise RuntimeError("LAB_REPLAY_FALSE_ACCEPTANCE")
    elif not op["consume"]:
        if status != "CHECKED_NONCONSUMING" or (root / "effect_applied.json").exists():
            raise RuntimeError("LAB_REPLAY_NONCONSUMING_CLAIM")
    elif status not in {"CHECKED_EFFECT_RESTORED", "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED"}:
        raise RuntimeError("LAB_REPLAY_EFFECT_CLAIM")
    if result.get("status") == "CHECKED_EFFECT_RESTORED":
        last = result["attempts"][-1]
        final_check = read_record(root / f"attempt_{last}_check.json")
        receipt = read_record(root / "effect_receipt.json")
        applied = read_record(root / "effect_applied.json")
        restored = read_record(root / "effect_restored.json")
        authority = read_record(root / "effect_authority.json")
        expected_state = {"schema_id": "kt.lab.checked_sandbox_state.v1", "task_hash": identity(op["task"]),
                          "answer": final_proposal["answer"], "check_hash": identity(final_check)}
        prepared = read_record(root / "effect_prepared.json")
        if (not op["consume"] or authority.get("operation_id") != root.name
                or authority.get("contract_sha256") != expected_contract_sha256
                or authority.get("authority_sha256") != contract["authority_sha256"]
                or authority.get("action") != "BOUNDED_SANDBOX_EFFECT"
                or not 0 < authority.get("checked_at", 0) < contract["expires_at"]
                or identity(authority) != receipt.get("authority_hash")
                or not final_check["satisfied"] or receipt.get("effect_count") != 1
                or receipt.get("application_observed") is not True
                or restored.get("restored_absence_observed") is not True
                or prepared.get("state") != expected_state
                or read_record(root / "effect_payload.json") != expected_state
                or applied["observed_state"] != expected_state
                or restored.get("prepared_hash") != identity(prepared)
                or applied.get("authority_hash") != identity(authority)
                or identity(applied["observed_state"]) != receipt["state_hash"]
                or (root / "sandbox_state.json").exists()):
            raise RuntimeError("LAB_REPLAY_EFFECT")
    if post_recovery:
        recovered = read_record(root / "effect_recovered.json")
        if (status != "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED" or recovered.get("reapplied") is not False
                or recovered.get("restored_absence_observed") is not True or (root / "sandbox_state.json").exists()
                or recovered.get("prepared_hash") != identity(read_record(root / "effect_prepared.json"))):
            raise RuntimeError("LAB_REPLAY_POST_TERMINAL_RECOVERY")
    return {"status": "REPLAY_NO_INFERENCE_NO_EFFECT", "original": result,
            "ceiling": "RECORDED_LOCAL_PROCESS_EVIDENCE_NOT_PROVIDER_ATTESTATION_OR_INDEPENDENT_OBSERVATION"}


def run_checked_generation(context: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    attestation, execution_id = require_canonical_entry_attestation(context)
    if set(request) != {"schema_id", "operation_id"} or request.get("schema_id") != REQUEST_SCHEMA:
        raise RuntimeError("LAB_REQUEST_FIELDS")
    session = current_session()
    operation_id = request["operation_id"]
    if type(operation_id) is not str or operation_id not in session.contract["operations"]:
        raise RuntimeError("LAB_REQUEST_NOT_ADMITTED")
    if context.get("artifact_root") != str(session.root):
        raise RuntimeError("LAB_CONTEXT_ROOT_BINDING")
    op = session.contract["operations"][operation_id]
    root = session.root / operation_id
    if (root / "result.json").exists():
        replay = verify_operation(root, expected_contract_sha256=session.contract_hash)
        if replay["original"]["status"] == "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED" and (root / "sandbox_state.json").exists():
            recovery = recover_effect(root)
            return {"status": "RECOVERED_HELD_OPERATION_NO_RETRY", "original": replay["original"], "recovery": recovery}
        return replay
    if root.exists() and any(root.iterdir()):
        recovery = recover_effect(root) if (root / "effect_prepared.json").exists() else None
        return {"status": "HOLD_INTERRUPTED_OPERATION_NO_RETRY", "operation_id": operation_id,
                "recovery": recovery, "inference_outcome": "RETAINED_RECORDS_ONLY_NO_AUTOMATIC_REGENERATION"}
    session.authority(operation_id)
    task, limits = op["task"], session.contract["limits"]
    result = {"schema_id": "kt.lab.operation_result.v1", "operation_id": operation_id,
              "contract_sha256": session.contract_hash, "task": task, "strategy": op["strategy"],
              "entry_attestation_hash": attestation, "execution_id": execution_id, "attempts": [],
              "adapter_required": session.contract["backend"]["adapter_root"] is not None,
              "claim_ceiling": "BOUNDED_TASK_CHECKED_LOCAL_LAB_EFFECT_ONLY", "model_calls": 0,
              "model_calls_accounting": "RESERVED_ATTEMPTS_INCLUDING_UNKNOWN_OR_FAILED_GENERATION",
              "input_tokens": 0, "output_tokens": 0, "checker_seconds": 0.0}
    if "response_interface" in op:
        result.update(schema_id="kt.lab.operation_result.v2", response_interface=op["response_interface"])
    history = []
    seen_nonces = set()
    final_proposal = None
    final_check = {"satisfied": False}
    for attempt in range(op["attempts"]):
        nonce = secrets.token_hex(16)
        if "response_interface" in op and nonce in seen_nonces:
            raise RuntimeError("LAB_DUPLICATE_OUTER_NONCE")
        seen_nonces.add(nonce)
        prompt = _prompt(op, nonce=nonce, history=history)
        root = session.reserve(operation_id, attempt, hashlib.sha256(prompt.encode()).hexdigest())
        request_record = {"prompt": prompt, "nonce": nonce,
                          "max_new_tokens": limits["max_new_tokens"], "task_hash": identity(task)}
        if "response_interface" in op:
            request_record["response_interface"] = op["response_interface"]
        write_record(root / f"attempt_{attempt}_request.json", request_record)
        result["model_calls"] += 1
        try:
            if session.backend is None:
                session.backend = LocalQwenBackend(contract_path=session.contract_path,
                    contract_sha256=session.contract_hash, output_root=session.root,
                    backend=session.contract["backend"], timeout=session.remaining_seconds())
                write_record(session.root / f"backend_{session.backend.worker_id}.json", session.backend.load_record)
            session.authority(operation_id)
            session.backend.timeout = session.remaining_seconds()
            raw = session.backend.generate(prompt=prompt, nonce=nonce, max_new_tokens=limits["max_new_tokens"])
            write_record(root / f"attempt_{attempt}_raw.json", raw)
            verify_generation(raw, nonce=nonce, prompt=prompt, cap=limits["max_new_tokens"],
                              contract_sha256=session.contract_hash, adapter_required=result["adapter_required"])
        except Exception as exc:
            write_record(root / f"attempt_{attempt}_failure.json", {"error_type": type(exc).__name__, "reason": str(exc),
                         "usage_accounting": "FULL_CAP_RESERVED_ACTUAL_PARTIAL_USAGE_MAY_BE_UNKNOWN"})
            result["status"] = "HOLD_GENERATION_FAILED"
            return _terminal(root, result)
        before = time.perf_counter()
        if "response_interface" in op:
            final_proposal, final_check, derived = derive_proposal(raw["output_text"], task, nonce=nonce,
                interface=op["response_interface"], contract_hash=session.contract_hash,
                operation_id=operation_id, attempt=attempt, request=request_record)
            write_record(root / f"attempt_{attempt}_derivation.json", derived)
        else:
            try:
                final_proposal = parse_proposal(raw["output_text"], task, nonce=nonce)
                final_check = check_proposal(task, final_proposal, nonce=nonce)
            except CheckedTaskError as exc:
                final_proposal = None
                final_check = {"satisfied": False, "diagnostics": [str(exc)], "scope": "MALFORMED_OR_UNBOUND_PROPOSAL"}
        result["checker_seconds"] += time.perf_counter() - before
        write_record(root / f"attempt_{attempt}_check.json", final_check)
        result["attempts"].append(attempt)
        result["input_tokens"] += raw["input_tokens"]
        result["output_tokens"] += raw["output_tokens"]
        if op["strategy"] == "direct" or (op["strategy"] in ("kt_diagnostic", "kt_constraint_detail", "nonconsuming") and final_check["satisfied"]):
            break
        history.append({"raw": raw["output_text"], "nonce": nonce, "feedback_mode": op["strategy"]})
    if final_check["satisfied"] and op["consume"]:
        try:
            result["effect"] = apply_checked_effect(root=root, task=task, proposal=final_proposal,
                check=final_check, authorize=lambda: session.authority(operation_id, effect=True))
            result["status"] = "CHECKED_EFFECT_RESTORED"
        except Exception as exc:
            result.update(status="HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED", reason=str(exc))
    else:
        result["status"] = "CHECKED_NONCONSUMING" if final_check["satisfied"] else "HELD_TASK_PREDICATE"
    return _terminal(root, result)
