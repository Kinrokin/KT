from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from schemas.base_schema import SchemaRegistryError, SchemaValidationError
from schemas.schema_registry import validate_object_with_binding
from schemas.state_vault_schema import (
    GENESIS_PARENT_HASH,
    build_state_vault_record,
    utc_now_iso_z,
)
from versioning.constitution_registry import ConstitutionVersionError, get_constitution_version_hash, validate_constitution_version_hash

from memory.replay import StateVaultReplayError, validate_state_vault_chain


class StateVaultWriteError(RuntimeError):
    pass


class StateVaultCorruptionError(RuntimeError):
    pass


@dataclass(frozen=True)
class AppendResult:
    record: Dict[str, Any]
    head_hash: str
    record_count: int


def resolve_state_vault_path() -> Path:
    # .../04_PROD_TEMPLE_V2/src/memory/state_vault.py -> .../src
    src_root = Path(__file__).resolve().parents[1]
    return src_root / "_state_vault" / "state_vault.jsonl"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _assert_file_ends_with_newline(path: Path) -> None:
    try:
        size = path.stat().st_size
    except Exception as exc:
        raise StateVaultCorruptionError(f"Unable to stat state vault: {exc.__class__.__name__}")

    if size == 0:
        return

    try:
        with path.open("rb") as handle:
            handle.seek(-1, os.SEEK_END)
            last = handle.read(1)
    except Exception as exc:
        raise StateVaultCorruptionError(f"Unable to read state vault tail: {exc.__class__.__name__}")

    if last != b"\n":
        raise StateVaultCorruptionError("State vault does not end with newline (possible partial write)")


def _read_last_event_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS_PARENT_HASH

    _assert_file_ends_with_newline(path)

    # Read a bounded tail window to find the last JSONL line.
    max_bytes = 64 * 1024
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            read_size = min(size, max_bytes)
            handle.seek(size - read_size, os.SEEK_SET)
            tail = handle.read(read_size)
    except Exception as exc:
        raise StateVaultCorruptionError(f"Unable to read state vault tail window: {exc.__class__.__name__}")

    if not tail.endswith(b"\n"):
        raise StateVaultCorruptionError("State vault does not end with newline (possible partial write)")

    # Drop final newline and locate previous newline.
    body = tail[:-1]
    idx = body.rfind(b"\n")
    if idx < 0 and size > max_bytes:
        raise StateVaultCorruptionError("State vault last line exceeds max tail window (fail-closed)")
    last_line = body[idx + 1 :] if idx >= 0 else body

    try:
        text = last_line.decode("utf-8")
    except Exception as exc:
        raise StateVaultCorruptionError(f"Unable to decode last JSONL line: {exc.__class__.__name__}")

    try:
        obj = json.loads(text)
    except Exception as exc:
        raise StateVaultCorruptionError(f"Unable to parse last JSONL line: {exc.__class__.__name__}")
    if not isinstance(obj, dict):
        raise StateVaultCorruptionError("Last state-vault record is not an object (fail-closed)")
    event_hash = obj.get("event_hash")
    if not isinstance(event_hash, str):
        raise StateVaultCorruptionError("Last state-vault record missing event_hash (fail-closed)")
    return event_hash


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise StateVaultWriteError("os.write returned 0 (fail-closed)")
        written += n


class StateVault:
    def __init__(self, *, path: Optional[Path] = None) -> None:
        self._path = path.resolve() if isinstance(path, Path) else (resolve_state_vault_path() if path is None else Path(path).resolve())
        self._head_hash = GENESIS_PARENT_HASH
        self._record_count = 0

        if self._path.exists():
            # Fail closed on any corruption before allowing further appends.
            _assert_file_ends_with_newline(self._path)
            try:
                result = validate_state_vault_chain(self._path)
            except StateVaultReplayError as exc:
                raise StateVaultCorruptionError(str(exc))
            self._head_hash = result.head_hash
            self._record_count = result.record_count

    @property
    def path(self) -> Path:
        return self._path

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def record_count(self) -> int:
        return self._record_count

    def append(
        self,
        *,
        event_type: str,
        organ_id: str,
        inputs_hash: Optional[str] = None,
        outputs_hash: Optional[str] = None,
        energy_cost: Optional[float] = None,
        energy_source: Optional[str] = None,
        crisis_mode: Optional[str] = None,
    ) -> AppendResult:
        # Defensive: ensure the on-disk head matches our in-memory head.
        if self._record_count:
            disk_head = _read_last_event_hash(self._path)
            if disk_head != self._head_hash:
                raise StateVaultCorruptionError("State vault head mismatch; external mutation suspected (fail-closed)")

        created_at = utc_now_iso_z()
        constitution_version_hash = get_constitution_version_hash()
        try:
            validate_constitution_version_hash(constitution_version_hash)
        except ConstitutionVersionError as exc:
            raise StateVaultWriteError(str(exc))

        # Deterministic receipt_id material (hash-only; no raw payload content).
        receipt_id = _sha256_text(
            _canonical_json(
                {
                    "created_at": created_at,
                    "event_type": event_type,
                    "organ_id": organ_id,
                    "parent_hash": self._head_hash,
                    "constitution_version_hash": constitution_version_hash,
                }
            )
        )

        record = build_state_vault_record(
            receipt_id=receipt_id,
            created_at=created_at,
            event_type=event_type,
            organ_id=organ_id,
            parent_hash=self._head_hash,
            constitution_version_hash=constitution_version_hash,
            inputs_hash=inputs_hash,
            outputs_hash=outputs_hash,
            energy_cost=energy_cost,
            energy_source=energy_source,
            crisis_mode=crisis_mode,
        )

        # C002 enforcement: registry-bound schema validation, fail-closed.
        try:
            validate_object_with_binding(record)
        except (SchemaRegistryError, SchemaValidationError) as exc:
            raise StateVaultWriteError(str(exc))

        # Persist append-only (no rewrite).
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = (_canonical_json(record) + "\n").encode("utf-8")

        try:
            fd = os.open(str(self._path), os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        except Exception as exc:
            raise StateVaultWriteError(f"Unable to open state vault for append: {exc.__class__.__name__}")

        try:
            _write_all(fd, line)
            os.fsync(fd)
        except Exception as exc:
            raise StateVaultWriteError(f"State vault append failed: {exc.__class__.__name__}")
        finally:
            try:
                os.close(fd)
            except Exception:
                pass

        self._head_hash = record["event_hash"]
        self._record_count += 1
        return AppendResult(record=record, head_hash=self._head_hash, record_count=self._record_count)

