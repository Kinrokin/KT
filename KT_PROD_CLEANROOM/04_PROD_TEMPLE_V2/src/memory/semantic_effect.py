from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from schemas.semantic_vertical_schemas import AdmittedMeaningSchema, SemanticVerticalError
from schemas.trusted_local_path import assert_no_link_or_reparse_path, is_link_or_reparse_point


CONSUMER_ID = "memory.semantic_advisory_consumer.v1"
STATE_SCHEMA_ID = "kt.semantic_advisory_state.v1"
RECEIPT_SCHEMA_ID = "kt.semantic_effect_receipt.v1"
ROLLBACK_SCHEMA_ID = "kt.semantic_rollback_receipt.v1"
JOURNAL_SCHEMA_ID = "kt.semantic_effect_journal.v1"
MAX_SEMANTIC_STATE_BYTES = 64 * 1024


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _state_hash(*, present: bool, data: bytes) -> str:
    return _sha256_json({"present": present, "bytes_sha256": _sha256_bytes(data) if present else "0" * 64})


def _is_link_or_junction(path: Path) -> bool:
    return is_link_or_reparse_point(path)


def _assert_no_link_path(path: Path) -> None:
    try:
        assert_no_link_or_reparse_path(path, label="semantic effect path")
    except RuntimeError as exc:
        raise SemanticVerticalError(str(exc)) from exc


def _safe_effect_root(run_artifact_root: Path) -> Path:
    if not run_artifact_root.is_absolute():
        raise SemanticVerticalError("semantic run root must be absolute (fail-closed)")
    _assert_no_link_path(run_artifact_root)
    try:
        root = run_artifact_root.resolve(strict=True)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("semantic run root missing (fail-closed)") from exc
    effect_root = root / "semantic_vertical"
    _assert_no_link_path(effect_root)
    try:
        effect_root.mkdir(parents=False, exist_ok=True)
        receipt_root = effect_root / "effect_receipts"
        receipt_root.mkdir(parents=False, exist_ok=True)
        rollback_root = effect_root / "rollback_receipts"
        rollback_root.mkdir(parents=False, exist_ok=True)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("unable to prepare semantic effect root (fail-closed)") from exc
    _assert_no_link_path(effect_root)
    return effect_root


def _atomic_write(path: Path, data: bytes, *, transaction_id: str) -> None:
    if path.exists() and _is_link_or_junction(path):
        raise SemanticVerticalError("semantic target link/reparse point forbidden (fail-closed)")
    temp = path.with_name(f".{path.name}.{transaction_id}.tmp")
    if temp.exists() or _is_link_or_junction(temp):
        raise SemanticVerticalError("semantic transaction temp collision (fail-closed)")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = None
    try:
        fd = os.open(str(temp), flags, 0o600)
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise SemanticVerticalError("semantic atomic write failed (fail-closed)")
            written += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        _assert_no_link_path(path.parent)
        os.replace(temp, path)
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            temp.unlink()
        except Exception:
            pass
        raise


def _phase_journal(
    *,
    path: Path,
    execution_id: str,
    semantic_request_id: str,
    effect_id: str,
    phase: str,
    pre_state_hash: str,
    post_state_hash: str,
    restored_state_hash: str | None,
    rollback_receipt_hash: str | None,
    effect_receipt_hash: str | None,
) -> str:
    payload: Dict[str, Any] = {
        "schema_id": JOURNAL_SCHEMA_ID,
        "execution_id": execution_id,
        "semantic_request_id": semantic_request_id,
        "effect_id": effect_id,
        "phase": phase,
        "pre_state_hash": pre_state_hash,
        "post_state_hash": post_state_hash,
        "restored_state_hash": restored_state_hash,
        "rollback_receipt_hash": rollback_receipt_hash,
        "effect_receipt_hash": effect_receipt_hash,
        "journal_hash": "",
    }
    payload["journal_hash"] = _sha256_json({key: value for key, value in payload.items() if key != "journal_hash"})
    _atomic_write(path, _canonical_bytes(payload), transaction_id=effect_id + "." + phase.lower())
    return str(payload["journal_hash"])


def _read_self_hashed(path: Path, *, hash_field: str) -> Dict[str, Any]:
    try:
        if path.stat().st_size > MAX_SEMANTIC_STATE_BYTES:
            raise SemanticVerticalError("semantic evidence artifact oversized (fail-closed)")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except SemanticVerticalError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("semantic evidence replay failed (fail-closed)") from exc
    if not isinstance(payload, dict):
        raise SemanticVerticalError("semantic evidence artifact must be object (fail-closed)")
    expected = payload.get(hash_field)
    actual = _sha256_json({key: value for key, value in payload.items() if key != hash_field})
    if expected != actual:
        raise SemanticVerticalError("semantic evidence self-hash mismatch (fail-closed)")
    return payload


@dataclass(frozen=True)
class SemanticEffectResult:
    data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


def consume_and_apply_with_rollback(
    *,
    artifact_root: Path,
    admitted: AdmittedMeaningSchema,
    semantic_request_id: str,
    execution_id: str,
) -> SemanticEffectResult:
    meaning = admitted.to_dict()
    try:
        AdmittedMeaningSchema.from_dict(meaning)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("consumer received invalid admitted meaning (fail-closed)") from exc
    if meaning.get("request_id") != execution_id:
        raise SemanticVerticalError("effect execution binding mismatch (fail-closed)")
    decision = meaning["decision"]
    reason_code = meaning["reason_code"]
    decision_hash = meaning["decision_hash"]
    effect_id = _sha256_json(
        {
            "consumer_id": CONSUMER_ID,
            "semantic_request_id": semantic_request_id,
            "decision_hash": decision_hash,
            "target_id": "semantic_vertical/advisory_state.json",
        }
    )
    effect_root = _safe_effect_root(artifact_root)
    target = effect_root / "advisory_state.json"
    receipt_path = effect_root / "effect_receipts" / f"{effect_id}.json"
    rollback_path = effect_root / "rollback_receipts" / f"{effect_id}.json"
    journal_path = effect_root / f"effect_journal.{effect_id}.json"
    lock_path = effect_root / ".effect.lock"
    for path in (target, receipt_path, rollback_path, journal_path, lock_path):
        _assert_no_link_path(path)
    if any(path.exists() for path in (target, receipt_path, rollback_path, journal_path, lock_path)):
        raise SemanticVerticalError("semantic run effect state collision/partial run (fail-closed)")

    lock_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = None
    try:
        lock_fd = os.open(str(lock_path), lock_flags, 0o600)
        os.write(lock_fd, _canonical_bytes({"execution_id": execution_id, "pid": os.getpid()}))
        os.fsync(lock_fd)
    except Exception as exc:  # noqa: BLE001
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except Exception:
                pass
        try:
            lock_path.unlink()
        except Exception:
            pass
        raise SemanticVerticalError("semantic effect lock unavailable (fail-closed)") from exc

    try:
        pre_state_hash = _state_hash(present=False, data=b"")
        state = {
            "schema_id": STATE_SCHEMA_ID,
            "consumer_id": CONSUMER_ID,
            "semantic_request_id": semantic_request_id,
            "subject_hash": meaning["subject_hash"],
            "decision": decision,
            "reason_code": reason_code,
            "decision_hash": decision_hash,
            "meaning_hash": meaning["meaning_hash"],
            "effect_id": effect_id,
        }
        post_bytes = _canonical_bytes(state)
        post_state_hash = _state_hash(present=True, data=post_bytes)
        if post_state_hash == pre_state_hash:
            raise SemanticVerticalError("semantic decision produced no state delta (fail-closed)")

        _phase_journal(
            path=journal_path,
            execution_id=execution_id,
            semantic_request_id=semantic_request_id,
            effect_id=effect_id,
            phase="PREPARED",
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            restored_state_hash=None,
            rollback_receipt_hash=None,
            effect_receipt_hash=None,
        )
        primary_error: Exception | None = None
        rollback_error: Exception | None = None
        try:
            _atomic_write(target, post_bytes, transaction_id=effect_id)
            if target.read_bytes() != post_bytes:
                raise SemanticVerticalError("semantic post-state verification failed (fail-closed)")
            _phase_journal(
                path=journal_path,
                execution_id=execution_id,
                semantic_request_id=semantic_request_id,
                effect_id=effect_id,
                phase="APPLIED",
                pre_state_hash=pre_state_hash,
                post_state_hash=post_state_hash,
                restored_state_hash=None,
                rollback_receipt_hash=None,
                effect_receipt_hash=None,
            )
        except Exception as exc:  # noqa: BLE001
            primary_error = exc
        finally:
            try:
                if target.exists() or _is_link_or_junction(target):
                    target.unlink()
                restored_state_hash = _state_hash(
                    present=target.exists(),
                    data=target.read_bytes() if target.exists() else b"",
                )
                if restored_state_hash != pre_state_hash:
                    raise SemanticVerticalError("semantic rollback state mismatch (fail-closed)")
            except Exception as exc:  # noqa: BLE001
                rollback_error = exc
        if rollback_error is not None:
            raise SemanticVerticalError("semantic rollback failed after effect attempt (fail-closed)") from rollback_error
        restored_journal_hash = _phase_journal(
            path=journal_path,
            execution_id=execution_id,
            semantic_request_id=semantic_request_id,
            effect_id=effect_id,
            phase="RESTORED",
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            restored_state_hash=restored_state_hash,
            rollback_receipt_hash=None,
            effect_receipt_hash=None,
        )
        if primary_error is not None:
            raise SemanticVerticalError("semantic effect attempt failed and was restored (fail-closed)") from primary_error

        rollback: Dict[str, Any] = {
            "schema_id": ROLLBACK_SCHEMA_ID,
            "semantic_request_id": semantic_request_id,
            "execution_id": execution_id,
            "effect_id": effect_id,
            "pre_state_hash": pre_state_hash,
            "post_state_hash": post_state_hash,
            "restored_state_hash": restored_state_hash,
            "rollback_status": "RESTORED",
            "restored_journal_hash": restored_journal_hash,
            "rollback_receipt_hash": "",
        }
        rollback["rollback_receipt_hash"] = _sha256_json(
            {key: value for key, value in rollback.items() if key != "rollback_receipt_hash"}
        )
        _atomic_write(rollback_path, _canonical_bytes(rollback), transaction_id=effect_id + ".rollback_receipt")

        receipt: Dict[str, Any] = {
            "schema_id": RECEIPT_SCHEMA_ID,
            "consumer_id": CONSUMER_ID,
            "semantic_request_id": semantic_request_id,
            "execution_id": execution_id,
            "meaning_hash": meaning["meaning_hash"],
            "decision_hash": decision_hash,
            "effect_id": effect_id,
            "effect_status": "APPLIED_AT_MOST_ONCE_IN_THIS_EXECUTION_AND_RESTORED",
            "semantic_effects_applied": 1,
            "pre_state_hash": pre_state_hash,
            "post_state_hash": post_state_hash,
            "restored_state_hash": restored_state_hash,
            "rollback_status": "RESTORED",
            "rollback_receipt_hash": rollback["rollback_receipt_hash"],
            "target_id": "semantic_vertical/advisory_state.json",
            "durability_ceiling": "IN_PROCESS_ROLLBACK_PROVEN__PROCESS_KILL_DURABILITY_NOT_PROVEN",
            "receipt_hash": "",
        }
        receipt["receipt_hash"] = _sha256_json({key: value for key, value in receipt.items() if key != "receipt_hash"})
        _atomic_write(receipt_path, _canonical_bytes(receipt), transaction_id=effect_id + ".effect_receipt")
        committed_journal_hash = _phase_journal(
            path=journal_path,
            execution_id=execution_id,
            semantic_request_id=semantic_request_id,
            effect_id=effect_id,
            phase="COMMITTED",
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            restored_state_hash=restored_state_hash,
            rollback_receipt_hash=rollback["rollback_receipt_hash"],
            effect_receipt_hash=receipt["receipt_hash"],
        )
        replayed_rollback = _read_self_hashed(rollback_path, hash_field="rollback_receipt_hash")
        replayed_receipt = _read_self_hashed(receipt_path, hash_field="receipt_hash")
        replayed_journal = _read_self_hashed(journal_path, hash_field="journal_hash")
        if (
            replayed_rollback.get("execution_id") != execution_id
            or replayed_receipt.get("execution_id") != execution_id
            or replayed_journal.get("execution_id") != execution_id
            or replayed_journal.get("phase") != "COMMITTED"
            or replayed_journal.get("rollback_receipt_hash") != rollback["rollback_receipt_hash"]
            or replayed_journal.get("effect_receipt_hash") != receipt["receipt_hash"]
        ):
            raise SemanticVerticalError("semantic effect evidence cross-link mismatch (fail-closed)")
        result = {**receipt, "journal_hash": committed_journal_hash}
        result["result_envelope_hash"] = _sha256_json(result)
        return SemanticEffectResult(data=result)
    finally:
        try:
            if lock_fd is not None:
                os.close(lock_fd)
        finally:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


__all__ = ["CONSUMER_ID", "SemanticEffectResult", "consume_and_apply_with_rollback"]
