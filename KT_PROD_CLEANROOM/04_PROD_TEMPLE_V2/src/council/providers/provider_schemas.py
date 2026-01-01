from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from council.council_schemas import SchemaValidationError, sha256_json, validate_hex_64, validate_short_string


STATUS_OK = "OK"
STATUS_FAIL_CLOSED = "FAIL_CLOSED"
STATUS_DISABLED = "DISABLED"

STATUSES_ALLOWED: Set[str] = {STATUS_OK, STATUS_FAIL_CLOSED, STATUS_DISABLED}

MODE_DRY_RUN = "DRY_RUN"
MODE_LIVE = "LIVE"
MODES_ALLOWED: Set[str] = {MODE_DRY_RUN, MODE_LIVE}


def _require_enum(payload: Dict[str, Any], field: str, *, allowed: Set[str]) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or value not in allowed:
        raise SchemaValidationError(f"{field} must be one of {sorted(allowed)} (fail-closed)")
    return value


def _require_int_range(payload: Dict[str, Any], field: str, *, lo: int, hi: int) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise SchemaValidationError(f"{field} must be int (fail-closed)")
    if not (lo <= value <= hi):
        raise SchemaValidationError(f"{field} out of bounds (fail-closed)")
    return value


def _zero_hash() -> str:
    return "0" * 64


@dataclass(frozen=True)
class ProviderRequestSchema:
    SCHEMA_ID = "provider.request"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = sha256_json({"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION})

    data: Dict[str, Any]

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        allowed = {
            "schema_id",
            "schema_version_hash",
            "request_id",
            "provider_id",
            "model_id",
            "input_hash",
            "max_output_tokens",
            "timeout_ms",
            "mode",
        }
        extra = set(payload.keys()) - allowed
        if extra:
            raise SchemaValidationError(f"ProviderRequest has unknown keys (fail-closed): {sorted(extra)}")

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")
        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_short_string(payload, "provider_id", max_len=32)
        validate_short_string(payload, "model_id", max_len=64)
        validate_hex_64(payload, "input_hash")
        _require_int_range(payload, "max_output_tokens", lo=0, hi=4096)
        _require_int_range(payload, "timeout_ms", lo=1, hi=10_000)
        _require_enum(payload, "mode", allowed=MODES_ALLOWED)

        validate_hex_64(payload, "request_id")
        expected = cls.compute_request_id(payload)
        if payload["request_id"] != expected:
            raise SchemaValidationError("request_id mismatch (fail-closed)")

    @classmethod
    def compute_request_id(cls, payload: Dict[str, Any]) -> str:
        obj = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "provider_id": payload.get("provider_id"),
            "model_id": payload.get("model_id"),
            "input_hash": payload.get("input_hash"),
            "max_output_tokens": payload.get("max_output_tokens"),
            "timeout_ms": payload.get("timeout_ms"),
            "mode": payload.get("mode"),
        }
        return sha256_json(obj)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "ProviderRequestSchema":
        cls.validate(payload)
        return ProviderRequestSchema(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


@dataclass(frozen=True)
class ProviderResponseSchema:
    SCHEMA_ID = "provider.response"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = sha256_json({"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION})

    data: Dict[str, Any]

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        allowed = {
            "schema_id",
            "schema_version_hash",
            "request_id",
            "provider_id",
            "status",
            "output_hash",
            "output_bytes_len",
            "latency_ms",
            "error_code",
        }
        extra = set(payload.keys()) - allowed
        if extra:
            raise SchemaValidationError(f"ProviderResponse has unknown keys (fail-closed): {sorted(extra)}")

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")
        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_hex_64(payload, "request_id")
        validate_short_string(payload, "provider_id", max_len=32)
        status = _require_enum(payload, "status", allowed=STATUSES_ALLOWED)
        validate_hex_64(payload, "output_hash")
        _require_int_range(payload, "output_bytes_len", lo=0, hi=1_000_000)
        _require_int_range(payload, "latency_ms", lo=0, hi=60_000)

        err = payload.get("error_code")
        if err is not None:
            validate_short_string(payload, "error_code", max_len=32)
            if status == STATUS_OK:
                raise SchemaValidationError("error_code forbidden when status=OK (fail-closed)")

        # Hash-only posture: if not OK, output_hash must be zero.
        if status != STATUS_OK and payload["output_hash"] != _zero_hash():
            raise SchemaValidationError("non-zero output_hash forbidden for non-OK status (fail-closed)")

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "ProviderResponseSchema":
        cls.validate(payload)
        return ProviderResponseSchema(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


def make_disabled_response(*, request: ProviderRequestSchema, error_code: str) -> ProviderResponseSchema:
    req = request.to_dict()
    payload: Dict[str, Any] = {
        "schema_id": ProviderResponseSchema.SCHEMA_ID,
        "schema_version_hash": ProviderResponseSchema.SCHEMA_VERSION_HASH,
        "request_id": req["request_id"],
        "provider_id": req["provider_id"],
        "status": STATUS_DISABLED,
        "output_hash": _zero_hash(),
        "output_bytes_len": 0,
        "latency_ms": 0,
        "error_code": error_code,
    }
    return ProviderResponseSchema.from_dict(payload)


def make_fail_closed_response(*, request: ProviderRequestSchema, error_code: str) -> ProviderResponseSchema:
    req = request.to_dict()
    payload: Dict[str, Any] = {
        "schema_id": ProviderResponseSchema.SCHEMA_ID,
        "schema_version_hash": ProviderResponseSchema.SCHEMA_VERSION_HASH,
        "request_id": req["request_id"],
        "provider_id": req["provider_id"],
        "status": STATUS_FAIL_CLOSED,
        "output_hash": _zero_hash(),
        "output_bytes_len": 0,
        "latency_ms": 0,
        "error_code": error_code,
    }
    return ProviderResponseSchema.from_dict(payload)
