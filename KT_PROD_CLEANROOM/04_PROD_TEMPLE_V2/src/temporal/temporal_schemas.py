from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_bounded_json_value,
    validate_hex_64,
    validate_short_string,
)
from schemas.schema_hash import sha256_json


TEMPORAL_MAX_DEPTH = 5
TEMPORAL_MAX_STRING_LEN = 128
TEMPORAL_MAX_LIST_LEN = 16

_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")


@dataclass(frozen=True)
class BaseSchema:
    data: Dict[str, Any]

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "BaseSchema":
        require_dict(payload, name="Schema payload")
        cls.validate(payload)
        return cls(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


def _require_id(payload: Dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise SchemaValidationError(f"{field} must be a string")
    if not _ID_RE.match(value):
        raise SchemaValidationError(f"{field} must match {_ID_RE.pattern} (fail-closed)")
    return value


def _require_int_range(payload: Dict[str, Any], field: str, *, lo: int, hi: int) -> int:
    value = payload.get(field)
    if not isinstance(value, int):
        raise SchemaValidationError(f"{field} must be an integer")
    if value < lo or value > hi:
        raise SchemaValidationError(f"{field} must be in range {lo}..{hi} (fail-closed)")
    return value


def _zero_hash() -> str:
    return "0" * 64


class TemporalForkRequestSchema(BaseSchema):
    SCHEMA_ID = "temporal.fork.request"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "trace_id",
        "epoch_id",
        "runtime_registry_hash",
        "anchor_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"parent_fork_hash"}

    MAX_FIELDS = 10
    MAX_BYTES = 3072

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="TemporalForkRequest")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        _require_id(payload, "trace_id")
        _require_id(payload, "epoch_id")
        validate_hex_64(payload, "runtime_registry_hash")
        validate_hex_64(payload, "anchor_hash")

        if "parent_fork_hash" in payload and payload["parent_fork_hash"] is not None:
            validate_hex_64(payload, "parent_fork_hash")

        validate_bounded_json_value(
            payload,
            max_depth=TEMPORAL_MAX_DEPTH,
            max_string_len=TEMPORAL_MAX_STRING_LEN,
            max_list_len=TEMPORAL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class TemporalForkSchema(BaseSchema):
    SCHEMA_ID = "temporal.fork"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "fork_hash",
        "request_hash",
        "context_identity_hash",
        "runtime_registry_hash",
        "anchor_hash",
        "trace_id",
        "epoch_id",
        "parent_fork_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 14
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="TemporalFork")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_hex_64(payload, "fork_hash")
        validate_hex_64(payload, "request_hash")
        validate_hex_64(payload, "context_identity_hash")
        validate_hex_64(payload, "runtime_registry_hash")
        validate_hex_64(payload, "anchor_hash")

        _require_id(payload, "trace_id")
        _require_id(payload, "epoch_id")

        if payload["parent_fork_hash"] is not None:
            validate_hex_64(payload, "parent_fork_hash")

        validate_bounded_json_value(
            payload,
            max_depth=TEMPORAL_MAX_DEPTH,
            max_string_len=TEMPORAL_MAX_STRING_LEN,
            max_list_len=TEMPORAL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class TemporalReplayRequestSchema(BaseSchema):
    SCHEMA_ID = "temporal.replay.request"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "fork",
        "replay_mode",
        "runtime_registry_hash",
        "max_steps",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 10
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="TemporalReplayRequest")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        fork = require_dict(payload.get("fork"), name="Temporal fork")
        TemporalForkSchema.validate(fork)

        replay_mode = payload.get("replay_mode")
        if replay_mode not in {"DRY_RUN"}:
            raise SchemaValidationError("replay_mode must be DRY_RUN (fail-closed)")

        validate_hex_64(payload, "runtime_registry_hash")
        _require_int_range(payload, "max_steps", lo=0, hi=1000)

        validate_bounded_json_value(
            payload,
            max_depth=TEMPORAL_MAX_DEPTH,
            max_string_len=TEMPORAL_MAX_STRING_LEN,
            max_list_len=TEMPORAL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class TemporalReplayResultSchema(BaseSchema):
    SCHEMA_ID = "temporal.replay.result"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "status",
        "fork_hash",
        "replay_hash",
        "outcome_hash",
        "steps_executed",
        "rejection_code",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 12
    MAX_BYTES = 3072

    STATUS_OK = "OK"
    STATUS_REJECTED = "REJECTED"

    @staticmethod
    def compute_outcome_hash(*, status: str, fork_hash: str, replay_hash: str, steps_executed: int) -> str:
        return sha256_json(
            {
                "status": status,
                "fork_hash": fork_hash,
                "replay_hash": replay_hash,
                "steps_executed": steps_executed,
            }
        )

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="TemporalReplayResult")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        status = payload.get("status")
        if status not in {cls.STATUS_OK, cls.STATUS_REJECTED}:
            raise SchemaValidationError("status must be OK or REJECTED (fail-closed)")

        validate_hex_64(payload, "fork_hash")
        validate_hex_64(payload, "replay_hash")
        validate_hex_64(payload, "outcome_hash")

        steps_executed = payload.get("steps_executed")
        if not isinstance(steps_executed, int) or steps_executed < 0 or steps_executed > 1000:
            raise SchemaValidationError("steps_executed out of range (fail-closed)")

        rejection_code = payload.get("rejection_code")
        if status == cls.STATUS_OK:
            if rejection_code is not None:
                raise SchemaValidationError("rejection_code must be null for OK results (fail-closed)")
        else:
            if not isinstance(rejection_code, str) or not _ID_RE.match(rejection_code):
                raise SchemaValidationError("rejection_code must be a bounded identifier for REJECTED (fail-closed)")

        expected = cls.compute_outcome_hash(
            status=status,
            fork_hash=payload["fork_hash"],
            replay_hash=payload["replay_hash"],
            steps_executed=steps_executed,
        )
        if payload["outcome_hash"] != expected:
            raise SchemaValidationError("outcome_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=TEMPORAL_MAX_DEPTH,
            max_string_len=TEMPORAL_MAX_STRING_LEN,
            max_list_len=TEMPORAL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


def _compute_temporal_fork_request_schema_version_hash() -> str:
    spec = {
        "schema_id": TemporalForkRequestSchema.SCHEMA_ID,
        "schema_version": TemporalForkRequestSchema.SCHEMA_VERSION,
        "required_fields": list(TemporalForkRequestSchema._REQUIRED_FIELDS_ORDER),
        "allowed_fields": sorted(TemporalForkRequestSchema._ALLOWED_FIELDS),
        "limits": {
            "max_fields": TemporalForkRequestSchema.MAX_FIELDS,
            "max_bytes": TemporalForkRequestSchema.MAX_BYTES,
            "max_depth": TEMPORAL_MAX_DEPTH,
            "max_string_len": TEMPORAL_MAX_STRING_LEN,
            "max_list_len": TEMPORAL_MAX_LIST_LEN,
        },
    }
    return sha256_json(spec)


def _compute_temporal_fork_schema_version_hash() -> str:
    spec = {
        "schema_id": TemporalForkSchema.SCHEMA_ID,
        "schema_version": TemporalForkSchema.SCHEMA_VERSION,
        "required_fields": list(TemporalForkSchema._REQUIRED_FIELDS_ORDER),
        "allowed_fields": sorted(TemporalForkSchema._ALLOWED_FIELDS),
        "limits": {
            "max_fields": TemporalForkSchema.MAX_FIELDS,
            "max_bytes": TemporalForkSchema.MAX_BYTES,
            "max_depth": TEMPORAL_MAX_DEPTH,
            "max_string_len": TEMPORAL_MAX_STRING_LEN,
            "max_list_len": TEMPORAL_MAX_LIST_LEN,
        },
    }
    return sha256_json(spec)


def _compute_temporal_replay_request_schema_version_hash() -> str:
    spec = {
        "schema_id": TemporalReplayRequestSchema.SCHEMA_ID,
        "schema_version": TemporalReplayRequestSchema.SCHEMA_VERSION,
        "required_fields": list(TemporalReplayRequestSchema._REQUIRED_FIELDS_ORDER),
        "allowed_fields": sorted(TemporalReplayRequestSchema._ALLOWED_FIELDS),
        "limits": {
            "max_fields": TemporalReplayRequestSchema.MAX_FIELDS,
            "max_bytes": TemporalReplayRequestSchema.MAX_BYTES,
            "max_depth": TEMPORAL_MAX_DEPTH,
            "max_string_len": TEMPORAL_MAX_STRING_LEN,
            "max_list_len": TEMPORAL_MAX_LIST_LEN,
        },
    }
    return sha256_json(spec)


def _compute_temporal_replay_result_schema_version_hash() -> str:
    spec = {
        "schema_id": TemporalReplayResultSchema.SCHEMA_ID,
        "schema_version": TemporalReplayResultSchema.SCHEMA_VERSION,
        "required_fields": list(TemporalReplayResultSchema._REQUIRED_FIELDS_ORDER),
        "allowed_fields": sorted(TemporalReplayResultSchema._ALLOWED_FIELDS),
        "limits": {
            "max_fields": TemporalReplayResultSchema.MAX_FIELDS,
            "max_bytes": TemporalReplayResultSchema.MAX_BYTES,
            "max_depth": TEMPORAL_MAX_DEPTH,
            "max_string_len": TEMPORAL_MAX_STRING_LEN,
            "max_list_len": TEMPORAL_MAX_LIST_LEN,
        },
    }
    return sha256_json(spec)


setattr(TemporalForkRequestSchema, "SCHEMA_VERSION_HASH", _compute_temporal_fork_request_schema_version_hash())
setattr(TemporalForkSchema, "SCHEMA_VERSION_HASH", _compute_temporal_fork_schema_version_hash())
setattr(TemporalReplayRequestSchema, "SCHEMA_VERSION_HASH", _compute_temporal_replay_request_schema_version_hash())
setattr(TemporalReplayResultSchema, "SCHEMA_VERSION_HASH", _compute_temporal_replay_result_schema_version_hash())

