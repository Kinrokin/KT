from __future__ import annotations

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


PARADOX_MAX_DEPTH = 4
PARADOX_MAX_STRING_LEN = 128
PARADOX_MAX_LIST_LEN = 16


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


def _require_int_range(payload: Dict[str, Any], field: str, *, lo: int, hi: int) -> int:
    value = payload.get(field)
    if not isinstance(value, int):
        raise SchemaValidationError(f"{field} must be an integer")
    if value < lo or value > hi:
        raise SchemaValidationError(f"{field} must be in range {lo}..{hi} (fail-closed)")
    return value


def _require_bool(payload: Dict[str, Any], field: str) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise SchemaValidationError(f"{field} must be a boolean")
    return value


def _zero_hash() -> str:
    return "0" * 64


class ParadoxTriggerSchema(BaseSchema):
    SCHEMA_ID = "paradox.trigger"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "trigger_type",
        "condition",
        "severity",
        "confidence",
        "subject_hash",
        "signal_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 10
    MAX_BYTES = 2048
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="ParadoxTrigger")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_short_string(payload, "trigger_type", max_len=32)
        validate_short_string(payload, "condition", max_len=64)
        _require_int_range(payload, "severity", lo=0, hi=10)
        _require_int_range(payload, "confidence", lo=0, hi=100)
        validate_hex_64(payload, "subject_hash")
        validate_hex_64(payload, "signal_hash")

        validate_bounded_json_value(
            payload,
            max_depth=PARADOX_MAX_DEPTH,
            max_string_len=PARADOX_MAX_STRING_LEN,
            max_list_len=PARADOX_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class ParadoxTaskSchema(BaseSchema):
    SCHEMA_ID = "paradox.task"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "task_hash",
        "trigger_hash",
        "task_type",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 8
    MAX_BYTES = 2048
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="ParadoxTask")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_hex_64(payload, "task_hash")
        validate_hex_64(payload, "trigger_hash")
        validate_short_string(payload, "task_type", max_len=32)

        validate_bounded_json_value(
            payload,
            max_depth=PARADOX_MAX_DEPTH,
            max_string_len=PARADOX_MAX_STRING_LEN,
            max_list_len=PARADOX_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class ParadoxResultSchema(BaseSchema):
    SCHEMA_ID = "paradox.result"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "status",
        "eligible",
        "trigger_hash",
        "task_hash",
        "task",
        "result_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 12
    MAX_BYTES = 4096
    MAX_ID_LEN = 64

    STATUS_NOOP = "NOOP"
    STATUS_INJECTED = "INJECTED"

    @staticmethod
    def compute_result_hash(*, status: str, eligible: bool, trigger_hash: str, task_hash: str) -> str:
        payload = {
            "status": status,
            "eligible": eligible,
            "trigger_hash": trigger_hash,
            "task_hash": task_hash,
        }
        return sha256_json(payload)

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="ParadoxResult")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        status = payload.get("status")
        if status not in {cls.STATUS_NOOP, cls.STATUS_INJECTED}:
            raise SchemaValidationError("status must be NOOP or INJECTED")

        eligible = _require_bool(payload, "eligible")
        validate_hex_64(payload, "trigger_hash")
        validate_hex_64(payload, "task_hash")
        validate_hex_64(payload, "result_hash")

        task_value = payload.get("task")
        if task_value is None:
            if status == cls.STATUS_INJECTED:
                raise SchemaValidationError("Injected result requires task (fail-closed)")
            if payload["task_hash"] != _zero_hash():
                raise SchemaValidationError("NOOP result requires task_hash to be zero-hash (fail-closed)")
        else:
            task = require_dict(task_value, name="Paradox task")
            ParadoxTaskSchema.validate(task)
            if task["task_hash"] != payload["task_hash"]:
                raise SchemaValidationError("task_hash mismatch between result and task (fail-closed)")
            if task["trigger_hash"] != payload["trigger_hash"]:
                raise SchemaValidationError("trigger_hash mismatch between result and task (fail-closed)")

        expected = cls.compute_result_hash(
            status=status, eligible=eligible, trigger_hash=payload["trigger_hash"], task_hash=payload["task_hash"]
        )
        if payload["result_hash"] != expected:
            raise SchemaValidationError("result_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=PARADOX_MAX_DEPTH,
            max_string_len=PARADOX_MAX_STRING_LEN,
            max_list_len=PARADOX_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


def _compute_paradox_trigger_schema_version_hash() -> str:
    spec = {
        "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
        "schema_version": ParadoxTriggerSchema.SCHEMA_VERSION,
        "required_fields": list(ParadoxTriggerSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": ParadoxTriggerSchema.MAX_FIELDS,
            "max_bytes": ParadoxTriggerSchema.MAX_BYTES,
            "max_id_len": ParadoxTriggerSchema.MAX_ID_LEN,
            "max_depth": PARADOX_MAX_DEPTH,
            "max_string_len": PARADOX_MAX_STRING_LEN,
            "max_list_len": PARADOX_MAX_LIST_LEN,
            "severity_range": [0, 10],
            "confidence_range": [0, 100],
        },
    }
    return sha256_json(spec)


def _compute_paradox_task_schema_version_hash() -> str:
    spec = {
        "schema_id": ParadoxTaskSchema.SCHEMA_ID,
        "schema_version": ParadoxTaskSchema.SCHEMA_VERSION,
        "required_fields": list(ParadoxTaskSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": ParadoxTaskSchema.MAX_FIELDS,
            "max_bytes": ParadoxTaskSchema.MAX_BYTES,
            "max_id_len": ParadoxTaskSchema.MAX_ID_LEN,
            "max_depth": PARADOX_MAX_DEPTH,
            "max_string_len": PARADOX_MAX_STRING_LEN,
            "max_list_len": PARADOX_MAX_LIST_LEN,
        },
    }
    return sha256_json(spec)


def _compute_paradox_result_schema_version_hash() -> str:
    spec = {
        "schema_id": ParadoxResultSchema.SCHEMA_ID,
        "schema_version": ParadoxResultSchema.SCHEMA_VERSION,
        "required_fields": list(ParadoxResultSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": ParadoxResultSchema.MAX_FIELDS,
            "max_bytes": ParadoxResultSchema.MAX_BYTES,
            "max_id_len": ParadoxResultSchema.MAX_ID_LEN,
            "max_depth": PARADOX_MAX_DEPTH,
            "max_string_len": PARADOX_MAX_STRING_LEN,
            "max_list_len": PARADOX_MAX_LIST_LEN,
        },
    }
    return sha256_json(spec)


setattr(ParadoxTriggerSchema, "SCHEMA_VERSION_HASH", _compute_paradox_trigger_schema_version_hash())
setattr(ParadoxTaskSchema, "SCHEMA_VERSION_HASH", _compute_paradox_task_schema_version_hash())
setattr(ParadoxResultSchema, "SCHEMA_VERSION_HASH", _compute_paradox_result_schema_version_hash())
