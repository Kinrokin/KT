from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple

from schemas.base_schema import SchemaRegistryError, SchemaValidationError
from schemas.schema_registry import validate_object_with_binding
from schemas.state_vault_schema import (
    GENESIS_PARENT_HASH,
    STATE_VAULT_PAYLOAD_FIELDS_ORDER,
    STATE_VAULT_SCHEMA_ID,
    STATE_VAULT_SCHEMA_VERSION_HASH,
    compute_event_hash,
    compute_payload_hash,
)
from versioning.constitution_registry import ConstitutionVersionError, validate_constitution_version_hash


@dataclass(frozen=True)
class StateVaultReplayResult:
    record_count: int
    head_hash: str


class StateVaultReplayError(RuntimeError):
    pass


def _assert_file_ends_with_newline(path: Path) -> None:
    try:
        size = path.stat().st_size
    except Exception as exc:
        raise StateVaultReplayError(f"Unable to stat state vault: {exc.__class__.__name__}")

    if size == 0:
        return

    try:
        with path.open("rb") as handle:
            handle.seek(-1, os.SEEK_END)
            last = handle.read(1)
    except Exception as exc:
        raise StateVaultReplayError(f"Unable to read state vault tail: {exc.__class__.__name__}")

    if last != b"\n":
        raise StateVaultReplayError("State vault does not end with newline (possible partial write)")


def _iter_jsonl_lines(path: Path) -> Iterator[Tuple[int, str]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n")
            if not line:
                raise StateVaultReplayError(f"Empty JSONL line encountered at line {line_no}")
            yield line_no, line


def validate_state_vault_chain(path: Path) -> StateVaultReplayResult:
    path = path.resolve()

    if not path.exists():
        return StateVaultReplayResult(record_count=0, head_hash=GENESIS_PARENT_HASH)

    _assert_file_ends_with_newline(path)

    parent_hash = GENESIS_PARENT_HASH
    count = 0

    for line_no, line in _iter_jsonl_lines(path):
        try:
            obj = json.loads(line)
        except Exception as exc:
            raise StateVaultReplayError(f"JSON parse error at line {line_no}: {exc.__class__.__name__}")

        if not isinstance(obj, dict):
            raise StateVaultReplayError(f"Non-object JSON record at line {line_no} (fail-closed)")

        try:
            validate_object_with_binding(obj)
        except (SchemaRegistryError, SchemaValidationError) as exc:
            raise StateVaultReplayError(f"Schema validation failed at line {line_no}: {exc}")

        # Schema binding must match state-vault schema (no runtime schema records here).
        if obj.get("schema_id") != STATE_VAULT_SCHEMA_ID:
            raise StateVaultReplayError(f"Unexpected schema_id at line {line_no} (fail-closed)")
        if obj.get("schema_version_hash") != STATE_VAULT_SCHEMA_VERSION_HASH:
            raise StateVaultReplayError(f"Unexpected schema_version_hash at line {line_no} (fail-closed)")

        try:
            validate_constitution_version_hash(str(obj.get("constitution_version_hash", "")))
        except ConstitutionVersionError as exc:
            raise StateVaultReplayError(f"Unknown constitution_version_hash at line {line_no}: {exc}")

        if obj.get("parent_hash") != parent_hash:
            raise StateVaultReplayError(f"parent_hash mismatch at line {line_no} (fail-closed)")

        payload_fields: Dict[str, Any] = {}
        for key in STATE_VAULT_PAYLOAD_FIELDS_ORDER:
            if key in obj:
                payload_fields[key] = obj[key]

        computed_payload_hash = compute_payload_hash(payload_fields)
        if obj.get("payload_hash") != computed_payload_hash:
            raise StateVaultReplayError(f"payload_hash mismatch at line {line_no} (fail-closed)")

        computed_event_hash = compute_event_hash(
            payload_hash=computed_payload_hash,
            event_type=str(obj.get("event_type", "")),
            organ_id=str(obj.get("organ_id", "")),
            parent_hash=parent_hash,
            schema_version_hash=str(obj.get("schema_version_hash", "")),
            constitution_version_hash=str(obj.get("constitution_version_hash", "")),
        )
        if obj.get("event_hash") != computed_event_hash:
            raise StateVaultReplayError(f"event_hash mismatch at line {line_no} (fail-closed)")

        parent_hash = computed_event_hash
        count += 1

    head = parent_hash if count else GENESIS_PARENT_HASH
    return StateVaultReplayResult(record_count=count, head_hash=head)

