from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

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

COUNCIL_MAX_DEPTH = 5
COUNCIL_MAX_STRING_LEN = 256
COUNCIL_MAX_LIST_LEN = 32

MAX_PROVIDER_CALLS = 8
MAX_TOTAL_TOKENS = 8192
MAX_PER_CALL_TOKENS = 4096

MODE_DRY_RUN = "DRY_RUN"
MODE_LIVE_REQUESTED = "LIVE_REQUESTED"

PLAN_STATUS_OK = "OK"
PLAN_STATUS_REFUSED = "REFUSED"

RESULT_STATUS_OK = "OK"
RESULT_STATUS_DRY_RUN = "DRY_RUN"
RESULT_STATUS_REFUSED = "REFUSED"
RESULT_STATUS_ERROR = "ERROR"


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


def _require_enum(payload: Dict[str, Any], field: str, allowed: Set[str]) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise SchemaValidationError(f"{field} must be a string")
    if value not in allowed:
        raise SchemaValidationError(f"{field} must be one of {sorted(allowed)} (fail-closed)")
    return value


def _zero_hash() -> str:
    return "0" * 64


class CouncilRequestSchema(BaseSchema):
    SCHEMA_ID = "council.request"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "request_id",
        "runtime_registry_hash",
        "mode",
        "provider_ids",
        "fanout_cap",
        "per_call_token_cap",
        "total_token_cap",
        "input_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 16
    MAX_BYTES = 4096
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CouncilRequest")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_short_string(payload, "request_id", max_len=cls.MAX_ID_LEN)
        validate_hex_64(payload, "runtime_registry_hash")

        _require_enum(payload, "mode", allowed={MODE_DRY_RUN, MODE_LIVE_REQUESTED})

        provider_ids = payload.get("provider_ids")
        if not isinstance(provider_ids, list) or not provider_ids:
            raise SchemaValidationError("provider_ids must be a non-empty list of strings")
        if len(provider_ids) > MAX_PROVIDER_CALLS:
            raise SchemaValidationError("provider_ids exceeds max providers (fail-closed)")
        for p in provider_ids:
            if not isinstance(p, str) or not p:
                raise SchemaValidationError("provider_ids must contain non-empty strings")
            if len(p) > 32:
                raise SchemaValidationError("provider_id exceeds max length (fail-closed)")

        fanout_cap = _require_int_range(payload, "fanout_cap", lo=1, hi=MAX_PROVIDER_CALLS)
        if len(provider_ids) > fanout_cap:
            raise SchemaValidationError("provider_ids exceeds fanout_cap (fail-closed)")

        per_call = _require_int_range(payload, "per_call_token_cap", lo=1, hi=MAX_PER_CALL_TOKENS)
        total = _require_int_range(payload, "total_token_cap", lo=1, hi=MAX_TOTAL_TOKENS)
        if per_call > total:
            raise SchemaValidationError("per_call_token_cap exceeds total_token_cap (fail-closed)")

        validate_hex_64(payload, "input_hash")

        validate_bounded_json_value(
            payload,
            max_depth=COUNCIL_MAX_DEPTH,
            max_string_len=COUNCIL_MAX_STRING_LEN,
            max_list_len=COUNCIL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_request_hash(cls, payload: Dict[str, Any]) -> str:
        provider_ids = sorted([str(x) for x in payload["provider_ids"]])
        obj = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "request_id": payload["request_id"],
            "runtime_registry_hash": payload["runtime_registry_hash"],
            "mode": payload["mode"],
            "provider_ids": provider_ids,
            "fanout_cap": payload["fanout_cap"],
            "per_call_token_cap": payload["per_call_token_cap"],
            "total_token_cap": payload["total_token_cap"],
            "input_hash": payload["input_hash"],
        }
        return sha256_json(obj)


class CouncilProviderCallSchema(BaseSchema):
    SCHEMA_ID = "council.provider_call"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "provider_id",
        "max_tokens",
        "performed",
        "success",
        "duration_ms",
        "output_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"error_code"}

    MAX_FIELDS = 16
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CouncilProviderCall")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_short_string(payload, "provider_id", max_len=32)
        _require_int_range(payload, "max_tokens", lo=1, hi=MAX_PER_CALL_TOKENS)

        performed = payload.get("performed")
        if not isinstance(performed, bool):
            raise SchemaValidationError("performed must be a boolean")
        success = payload.get("success")
        if not isinstance(success, bool):
            raise SchemaValidationError("success must be a boolean")

        _require_int_range(payload, "duration_ms", lo=0, hi=60_000)
        validate_hex_64(payload, "output_hash")

        err = payload.get("error_code")
        if err is not None:
            validate_short_string(payload, "error_code", max_len=32)

        validate_bounded_json_value(
            payload,
            max_depth=COUNCIL_MAX_DEPTH,
            max_string_len=COUNCIL_MAX_STRING_LEN,
            max_list_len=COUNCIL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class CouncilPlanSchema(BaseSchema):
    SCHEMA_ID = "council.plan"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "plan_id",
        "runtime_registry_hash",
        "request_hash",
        "status",
        "mode",
        "provider_calls",
        "plan_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"refusal_code"}

    MAX_FIELDS = 16
    MAX_BYTES = 8192
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CouncilPlan")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_short_string(payload, "plan_id", max_len=cls.MAX_ID_LEN)
        validate_hex_64(payload, "runtime_registry_hash")
        validate_hex_64(payload, "request_hash")

        status = _require_enum(payload, "status", allowed={PLAN_STATUS_OK, PLAN_STATUS_REFUSED})
        _require_enum(payload, "mode", allowed={MODE_DRY_RUN, MODE_LIVE_REQUESTED})

        calls_value = payload.get("provider_calls")
        if not isinstance(calls_value, list):
            raise SchemaValidationError("provider_calls must be a list")
        if len(calls_value) > MAX_PROVIDER_CALLS:
            raise SchemaValidationError("provider_calls exceeds max providers (fail-closed)")
        for c in calls_value:
            call = require_dict(c, name="provider_call")
            CouncilProviderCallSchema.validate(call)

        refusal = payload.get("refusal_code")
        if status == PLAN_STATUS_REFUSED:
            if not isinstance(refusal, str) or not refusal:
                raise SchemaValidationError("refusal_code required when status=REFUSED (fail-closed)")
            if len(refusal) > 32:
                raise SchemaValidationError("refusal_code exceeds max length (fail-closed)")
        else:
            if refusal is not None:
                raise SchemaValidationError("refusal_code forbidden when status=OK (fail-closed)")

        validate_hex_64(payload, "plan_hash")
        expected = cls.compute_plan_hash(payload)
        if payload["plan_hash"] != expected:
            raise SchemaValidationError("plan_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=COUNCIL_MAX_DEPTH,
            max_string_len=COUNCIL_MAX_STRING_LEN,
            max_list_len=COUNCIL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_plan_hash(cls, payload: Dict[str, Any]) -> str:
        calls = payload.get("provider_calls")
        calls_sorted = (
            sorted(
                [require_dict(c, name="provider_call") for c in calls],
                key=lambda c: str(c.get("provider_id", "")),
            )
            if isinstance(calls, list)
            else []
        )
        obj: Dict[str, Any] = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "plan_id": payload.get("plan_id"),
            "runtime_registry_hash": payload.get("runtime_registry_hash"),
            "request_hash": payload.get("request_hash"),
            "status": payload.get("status"),
            "mode": payload.get("mode"),
            "provider_calls": calls_sorted,
            "refusal_code": payload.get("refusal_code"),
        }
        return sha256_json(obj)


class CouncilResultSchema(BaseSchema):
    SCHEMA_ID = "council.result"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "status",
        "plan_hash",
        "calls",
        "result_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"refusal_code", "error_code", "output_hashes"}

    MAX_FIELDS = 20
    MAX_BYTES = 8192
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CouncilResult")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        status = _require_enum(
            payload,
            "status",
            allowed={RESULT_STATUS_OK, RESULT_STATUS_DRY_RUN, RESULT_STATUS_REFUSED, RESULT_STATUS_ERROR},
        )

        validate_hex_64(payload, "plan_hash")

        calls_value = payload.get("calls")
        if not isinstance(calls_value, list):
            raise SchemaValidationError("calls must be a list")
        if len(calls_value) > MAX_PROVIDER_CALLS:
            raise SchemaValidationError("calls exceeds max providers (fail-closed)")
        for c in calls_value:
            call = require_dict(c, name="provider_call")
            CouncilProviderCallSchema.validate(call)

        output_hashes = payload.get("output_hashes")
        if output_hashes is not None:
            if not isinstance(output_hashes, list):
                raise SchemaValidationError("output_hashes must be a list of hex hashes")
            if len(output_hashes) > MAX_PROVIDER_CALLS:
                raise SchemaValidationError("output_hashes exceeds max outputs (fail-closed)")
            for h in output_hashes:
                if not isinstance(h, str):
                    raise SchemaValidationError("output_hashes must contain strings")
                if h != _zero_hash():
                    raise SchemaValidationError("Non-zero output_hashes are forbidden in C014 (fail-closed)")

        refusal_code = payload.get("refusal_code")
        error_code = payload.get("error_code")
        if status == RESULT_STATUS_REFUSED:
            if not isinstance(refusal_code, str) or not refusal_code:
                raise SchemaValidationError("refusal_code required when status=REFUSED (fail-closed)")
            if len(refusal_code) > 32:
                raise SchemaValidationError("refusal_code exceeds max length (fail-closed)")
        else:
            if refusal_code is not None:
                raise SchemaValidationError("refusal_code forbidden unless status=REFUSED (fail-closed)")

        if status == RESULT_STATUS_ERROR:
            if not isinstance(error_code, str) or not error_code:
                raise SchemaValidationError("error_code required when status=ERROR (fail-closed)")
            if len(error_code) > 32:
                raise SchemaValidationError("error_code exceeds max length (fail-closed)")
        else:
            if error_code is not None:
                raise SchemaValidationError("error_code forbidden unless status=ERROR (fail-closed)")

        validate_hex_64(payload, "result_hash")
        expected = cls.compute_result_hash(payload)
        if payload["result_hash"] != expected:
            raise SchemaValidationError("result_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=COUNCIL_MAX_DEPTH,
            max_string_len=COUNCIL_MAX_STRING_LEN,
            max_list_len=COUNCIL_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_result_hash(cls, payload: Dict[str, Any]) -> str:
        calls = payload.get("calls")
        calls_sorted = (
            sorted(
                [require_dict(c, name="provider_call") for c in calls],
                key=lambda c: str(c.get("provider_id", "")),
            )
            if isinstance(calls, list)
            else []
        )

        obj: Dict[str, Any] = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "status": payload.get("status"),
            "plan_hash": payload.get("plan_hash"),
            "calls": calls_sorted,
            "refusal_code": payload.get("refusal_code"),
            "error_code": payload.get("error_code"),
            "output_hashes": payload.get("output_hashes"),
        }
        return sha256_json(obj)


def _compute_council_request_schema_version_hash() -> str:
    spec = {
        "schema_id": CouncilRequestSchema.SCHEMA_ID,
        "schema_version": CouncilRequestSchema.SCHEMA_VERSION,
        "required_fields": list(CouncilRequestSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": CouncilRequestSchema.MAX_FIELDS,
            "max_bytes": CouncilRequestSchema.MAX_BYTES,
            "max_providers": MAX_PROVIDER_CALLS,
            "max_total_tokens": MAX_TOTAL_TOKENS,
            "max_per_call_tokens": MAX_PER_CALL_TOKENS,
        },
    }
    return sha256_json(spec)


def _compute_council_provider_call_schema_version_hash() -> str:
    spec = {
        "schema_id": CouncilProviderCallSchema.SCHEMA_ID,
        "schema_version": CouncilProviderCallSchema.SCHEMA_VERSION,
        "required_fields": list(CouncilProviderCallSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": CouncilProviderCallSchema.MAX_FIELDS,
            "max_bytes": CouncilProviderCallSchema.MAX_BYTES,
        },
    }
    return sha256_json(spec)


def _compute_council_plan_schema_version_hash() -> str:
    spec = {
        "schema_id": CouncilPlanSchema.SCHEMA_ID,
        "schema_version": CouncilPlanSchema.SCHEMA_VERSION,
        "required_fields": list(CouncilPlanSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": CouncilPlanSchema.MAX_FIELDS,
            "max_bytes": CouncilPlanSchema.MAX_BYTES,
            "max_providers": MAX_PROVIDER_CALLS,
        },
    }
    return sha256_json(spec)


def _compute_council_result_schema_version_hash() -> str:
    spec = {
        "schema_id": CouncilResultSchema.SCHEMA_ID,
        "schema_version": CouncilResultSchema.SCHEMA_VERSION,
        "required_fields": list(CouncilResultSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": CouncilResultSchema.MAX_FIELDS,
            "max_bytes": CouncilResultSchema.MAX_BYTES,
            "max_providers": MAX_PROVIDER_CALLS,
        },
    }
    return sha256_json(spec)


setattr(CouncilRequestSchema, "SCHEMA_VERSION_HASH", _compute_council_request_schema_version_hash())
setattr(CouncilProviderCallSchema, "SCHEMA_VERSION_HASH", _compute_council_provider_call_schema_version_hash())
setattr(CouncilPlanSchema, "SCHEMA_VERSION_HASH", _compute_council_plan_schema_version_hash())
setattr(CouncilResultSchema, "SCHEMA_VERSION_HASH", _compute_council_result_schema_version_hash())

