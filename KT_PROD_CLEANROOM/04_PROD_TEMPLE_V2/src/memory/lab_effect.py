"""Immutable lab records and an observed, reversible, local sandbox effect.

The operator owns this directory; same-user hostile filesystem races are outside
this contract. Recovery never executes the task again and never removes bytes
that differ from the recorded effect. Callers hold the exclusive run lock.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from schemas.checked_task import canonical_bytes, identity, strict_json
from schemas.trusted_local_path import assert_no_link_or_reparse_path


def read_record(path: Path) -> dict[str, Any]:
    assert_no_link_or_reparse_path(path, label="lab record")
    value = strict_json(path.read_bytes(), max_bytes=2 * 1024 * 1024)
    if type(value) is not dict:
        raise RuntimeError("LAB_RECORD_OBJECT_REQUIRED")
    return value


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_bytes_once(path: Path, raw: bytes) -> None:
    """Publish complete bytes once; preserve any interrupted temporary file."""
    assert_no_link_or_reparse_path(path, label="lab record")
    temporary = path.with_name(path.name + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # link is atomic and fails on collision; unlike replace it cannot overwrite evidence.
    os.link(temporary, path, follow_symlinks=False)
    _sync_dir(path.parent)
    temporary.unlink()
    _sync_dir(path.parent)


def write_record(path: Path, value: dict[str, Any]) -> str:
    write_bytes_once(path, canonical_bytes(value))
    return identity(value)


def _restore_owned_target(root: Path, prepared: dict[str, Any]) -> str:
    target = root / "sandbox_state.json"
    assert_no_link_or_reparse_path(target, label="lab effect target")
    if target.exists():
        if target.read_bytes() != canonical_bytes(prepared["state"]):
            raise RuntimeError("LAB_RECOVERY_COLLISION_PRESERVED")
        target.unlink()
        _sync_dir(root)
        return "OWNED_STATE_REMOVED"
    return "ALREADY_ABSENT"


def recover_effect(root: Path) -> dict[str, Any]:
    """Recover a previously prepared operation, without inference or reapplication."""
    prepared = read_record(root / "effect_prepared.json")
    outcome = _restore_owned_target(root, prepared)
    path = root / "effect_recovered.json"
    if path.exists():
        return read_record(path)
    result = {"schema_id": "kt.lab.effect_recovery.v1", "prepared_hash": identity(prepared),
              "state": outcome, "restored_absence_observed": not (root / "sandbox_state.json").exists(),
              "reapplied": False, "effect_count_if_no_applied_record": "UNKNOWN_ZERO_OR_ONE"}
    write_record(path, result)
    return result


def apply_checked_effect(*, root: Path, task: dict[str, Any], proposal: dict[str, Any],
                         check: dict[str, Any], authorize: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Consume a checked answer once, observe its actual bytes, then restore absence."""
    if (check.get("satisfied") is not True or check.get("task_hash") != identity(task)
            or check.get("proposal_hash") != identity(proposal)
            or check.get("execution_permission") != "NOT_GRANTED"):
        raise RuntimeError("LAB_EFFECT_REQUIRES_BOUND_TASK_CHECK")
    target = root / "sandbox_state.json"
    assert_no_link_or_reparse_path(target, label="lab effect target")
    if target.exists():
        raise RuntimeError("LAB_EFFECT_TARGET_COLLISION")
    state = {"schema_id": "kt.lab.checked_sandbox_state.v1", "task_hash": identity(task),
             "answer": proposal["answer"], "check_hash": identity(check)}
    prepared = {"schema_id": "kt.lab.effect_prepared.v1", "state": state,
                "pre_state": "ABSENT", "task_hash": identity(task)}
    write_record(root / "effect_prepared.json", prepared)
    payload_path = root / "effect_payload.json"
    write_record(payload_path, state)
    os.chmod(payload_path, 0o400)
    # This is the permission decision at the actual effect boundary, not at planning.
    applied = False
    try:
        authority = authorize()
        # Publish only complete fsynced bytes, atomically and without overwriting.
        os.link(payload_path, target, follow_symlinks=False)
        _sync_dir(root)
        if target.read_bytes() != canonical_bytes(state):
            raise RuntimeError("LAB_EFFECT_OBSERVATION_MISMATCH")
        applied = True
        write_record(root / "effect_authority.json", authority)
        write_record(root / "effect_applied.json", {"state_hash": identity(state),
                     "observed_state": read_record(target), "authority_hash": identity(authority)})
    finally:
        _restore_owned_target(root, prepared)
        write_record(root / "effect_restored.json", {"restored_absence_observed": not target.exists(),
                     "prepared_hash": identity(prepared), "application_observed": applied})
    receipt = {"schema_id": "kt.lab.effect_receipt.v1", "state_hash": identity(state),
               "application_observed": applied, "restored_absence_observed": not target.exists(),
               "effect_count": 1, "authority_hash": identity(authority),
               "scope": "TRUSTED_OPERATOR_LOCAL_SANDBOX_ONLY"}
    write_record(root / "effect_receipt.json", receipt)
    return receipt
