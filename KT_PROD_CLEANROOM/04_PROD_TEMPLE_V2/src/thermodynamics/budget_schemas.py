from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Set

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


BUDGET_MAX_DEPTH = 4
BUDGET_MAX_STRING_LEN = 128
BUDGET_MAX_LIST_LEN = 16


STATUS_OK = "OK"
STATUS_REFUSED = "REFUSED"


REFUSE_TOKENS_EXCEEDED = "REFUSE_TOKENS_EXCEEDED"
REFUSE_STEPS_EXCEEDED = "REFUSE_STEPS_EXCEEDED"
REFUSE_BRANCHES_EXCEEDED = "REFUSE_BRANCHES_EXCEEDED"
REFUSE_MEMORY_EXCEEDED = "REFUSE_MEMORY_EXCEEDED"
REFUSE_DURATION_EXCEEDED = "REFUSE_DURATION_EXCEEDED"
REFUSE_SCHEMA = "REFUSE_SCHEMA"
REFUSE_ILLEGAL_REQUEST = "REFUSE_ILLEGAL_REQUEST"
REFUSE_NESTED_ALLOCATION = "REFUSE_NESTED_ALLOCATION"


MAX_TOKEN_CEILING = 8192
MAX_STEP_CEILING = 256
MAX_BRANCH_CEILING = 64
MAX_MEMORY_CEILING_BYTES = 16 * 1024 * 1024
MAX_DURATION_CEILING_MILLIS = 60_000


def _require_int_range(payload: Dict[str, Any], field: str, *, lo: int, hi: int) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
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


class BudgetRequestSchema(BaseSchema):
    SCHEMA_ID = "budget.request"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "request_id",
        "runtime_registry_hash",
        "token_ceiling",
        "step_ceiling",
        "branch_ceiling",
        "memory_ceiling_bytes",
        "duration_ceiling_millis",
        "parent_allocation_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 16
    MAX_BYTES = 4096
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="BudgetRequest")
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

        _require_int_range(payload, "token_ceiling", lo=1, hi=MAX_TOKEN_CEILING)
        _require_int_range(payload, "step_ceiling", lo=1, hi=MAX_STEP_CEILING)
        _require_int_range(payload, "branch_ceiling", lo=0, hi=MAX_BRANCH_CEILING)
        _require_int_range(payload, "memory_ceiling_bytes", lo=1, hi=MAX_MEMORY_CEILING_BYTES)
        _require_int_range(payload, "duration_ceiling_millis", lo=0, hi=MAX_DURATION_CEILING_MILLIS)

        validate_hex_64(payload, "parent_allocation_hash")

        validate_bounded_json_value(
            payload,
            max_depth=BUDGET_MAX_DEPTH,
            max_string_len=BUDGET_MAX_STRING_LEN,
            max_list_len=BUDGET_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_request_hash(cls, payload: Dict[str, Any]) -> str:
        obj = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "request_id": payload["request_id"],
            "runtime_registry_hash": payload["runtime_registry_hash"],
            "token_ceiling": int(payload["token_ceiling"]),
            "step_ceiling": int(payload["step_ceiling"]),
            "branch_ceiling": int(payload["branch_ceiling"]),
            "memory_ceiling_bytes": int(payload["memory_ceiling_bytes"]),
            "duration_ceiling_millis": int(payload["duration_ceiling_millis"]),
            "parent_allocation_hash": payload["parent_allocation_hash"],
        }
        return sha256_json(obj)


class BudgetAllocationSchema(BaseSchema):
    SCHEMA_ID = "budget.allocation"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "allocation_id",
        "runtime_registry_hash",
        "request_hash",
        "status",
        "allocation_hash",
        "token_ceiling",
        "step_ceiling",
        "branch_ceiling",
        "memory_ceiling_bytes",
        "duration_ceiling_millis",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"refusal_code"}

    MAX_FIELDS = 20
    MAX_BYTES = 8192
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="BudgetAllocation")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_short_string(payload, "allocation_id", max_len=cls.MAX_ID_LEN)
        validate_hex_64(payload, "runtime_registry_hash")
        validate_hex_64(payload, "request_hash")

        status = _require_enum(payload, "status", allowed={STATUS_OK, STATUS_REFUSED})
        refusal = payload.get("refusal_code")
        if status == STATUS_REFUSED:
            if not isinstance(refusal, str) or not refusal:
                raise SchemaValidationError("refusal_code required when status=REFUSED (fail-closed)")
        else:
            if refusal is not None:
                raise SchemaValidationError("refusal_code forbidden when status=OK (fail-closed)")

        validate_hex_64(payload, "allocation_hash")

        _require_int_range(payload, "token_ceiling", lo=0, hi=MAX_TOKEN_CEILING)
        _require_int_range(payload, "step_ceiling", lo=0, hi=MAX_STEP_CEILING)
        _require_int_range(payload, "branch_ceiling", lo=0, hi=MAX_BRANCH_CEILING)
        _require_int_range(payload, "memory_ceiling_bytes", lo=0, hi=MAX_MEMORY_CEILING_BYTES)
        _require_int_range(payload, "duration_ceiling_millis", lo=0, hi=MAX_DURATION_CEILING_MILLIS)

        validate_bounded_json_value(
            payload,
            max_depth=BUDGET_MAX_DEPTH,
            max_string_len=BUDGET_MAX_STRING_LEN,
            max_list_len=BUDGET_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_allocation_hash(cls, payload: Dict[str, Any]) -> str:
        obj: Dict[str, Any] = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "allocation_id": payload["allocation_id"],
            "runtime_registry_hash": payload["runtime_registry_hash"],
            "request_hash": payload["request_hash"],
            "status": payload["status"],
            "refusal_code": payload.get("refusal_code"),
            "token_ceiling": int(payload["token_ceiling"]),
            "step_ceiling": int(payload["step_ceiling"]),
            "branch_ceiling": int(payload["branch_ceiling"]),
            "memory_ceiling_bytes": int(payload["memory_ceiling_bytes"]),
            "duration_ceiling_millis": int(payload["duration_ceiling_millis"]),
        }
        return sha256_json(obj)


class BudgetConsumptionSchema(BaseSchema):
    SCHEMA_ID = "budget.consumption"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "allocation_hash",
        "tokens_used",
        "steps_used",
        "branches_used",
        "memory_bytes_used",
        "duration_millis_used",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 16
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="BudgetConsumption")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")
        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_hex_64(payload, "allocation_hash")

        _require_int_range(payload, "tokens_used", lo=0, hi=MAX_TOKEN_CEILING)
        _require_int_range(payload, "steps_used", lo=0, hi=MAX_STEP_CEILING)
        _require_int_range(payload, "branches_used", lo=0, hi=MAX_BRANCH_CEILING)
        _require_int_range(payload, "memory_bytes_used", lo=0, hi=MAX_MEMORY_CEILING_BYTES)
        _require_int_range(payload, "duration_millis_used", lo=0, hi=MAX_DURATION_CEILING_MILLIS)

        validate_bounded_json_value(
            payload,
            max_depth=BUDGET_MAX_DEPTH,
            max_string_len=BUDGET_MAX_STRING_LEN,
            max_list_len=BUDGET_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class BudgetResultSchema(BaseSchema):
    SCHEMA_ID = "budget.result"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "status",
        "allocation_hash",
        "tokens_remaining",
        "steps_remaining",
        "branches_remaining",
        "memory_bytes_remaining",
        "duration_millis_remaining",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"refusal_code"}

    MAX_FIELDS = 18
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="BudgetResult")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        status = _require_enum(payload, "status", allowed={STATUS_OK, STATUS_REFUSED})
        refusal = payload.get("refusal_code")
        if status == STATUS_REFUSED:
            if not isinstance(refusal, str) or not refusal:
                raise SchemaValidationError("refusal_code required when status=REFUSED (fail-closed)")
        else:
            if refusal is not None:
                raise SchemaValidationError("refusal_code forbidden when status=OK (fail-closed)")

        validate_hex_64(payload, "allocation_hash")

        _require_int_range(payload, "tokens_remaining", lo=0, hi=MAX_TOKEN_CEILING)
        _require_int_range(payload, "steps_remaining", lo=0, hi=MAX_STEP_CEILING)
        _require_int_range(payload, "branches_remaining", lo=0, hi=MAX_BRANCH_CEILING)
        _require_int_range(payload, "memory_bytes_remaining", lo=0, hi=MAX_MEMORY_CEILING_BYTES)
        _require_int_range(payload, "duration_millis_remaining", lo=0, hi=MAX_DURATION_CEILING_MILLIS)

        validate_bounded_json_value(
            payload,
            max_depth=BUDGET_MAX_DEPTH,
            max_string_len=BUDGET_MAX_STRING_LEN,
            max_list_len=BUDGET_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


def _compute_schema_version_hash(schema_id: str, required_fields: list[str], limits: Dict[str, Any]) -> str:
    spec = {"schema_id": schema_id, "schema_version": "1.0", "required_fields": list(required_fields), "limits": dict(limits)}
    return sha256_json(spec)


BudgetRequestSchema.SCHEMA_VERSION_HASH = _compute_schema_version_hash(
    BudgetRequestSchema.SCHEMA_ID,
    list(BudgetRequestSchema._REQUIRED_FIELDS_ORDER),
    {
        "max_fields": BudgetRequestSchema.MAX_FIELDS,
        "max_bytes": BudgetRequestSchema.MAX_BYTES,
        "max_token_ceiling": MAX_TOKEN_CEILING,
        "max_step_ceiling": MAX_STEP_CEILING,
        "max_branch_ceiling": MAX_BRANCH_CEILING,
        "max_memory_ceiling_bytes": MAX_MEMORY_CEILING_BYTES,
        "max_duration_ceiling_millis": MAX_DURATION_CEILING_MILLIS,
    },
)

BudgetAllocationSchema.SCHEMA_VERSION_HASH = _compute_schema_version_hash(
    BudgetAllocationSchema.SCHEMA_ID,
    list(BudgetAllocationSchema._REQUIRED_FIELDS_ORDER),
    {
        "max_fields": BudgetAllocationSchema.MAX_FIELDS,
        "max_bytes": BudgetAllocationSchema.MAX_BYTES,
        "max_token_ceiling": MAX_TOKEN_CEILING,
        "max_step_ceiling": MAX_STEP_CEILING,
        "max_branch_ceiling": MAX_BRANCH_CEILING,
        "max_memory_ceiling_bytes": MAX_MEMORY_CEILING_BYTES,
        "max_duration_ceiling_millis": MAX_DURATION_CEILING_MILLIS,
    },
)

BudgetConsumptionSchema.SCHEMA_VERSION_HASH = _compute_schema_version_hash(
    BudgetConsumptionSchema.SCHEMA_ID,
    list(BudgetConsumptionSchema._REQUIRED_FIELDS_ORDER),
    {
        "max_fields": BudgetConsumptionSchema.MAX_FIELDS,
        "max_bytes": BudgetConsumptionSchema.MAX_BYTES,
        "max_token_ceiling": MAX_TOKEN_CEILING,
        "max_step_ceiling": MAX_STEP_CEILING,
        "max_branch_ceiling": MAX_BRANCH_CEILING,
        "max_memory_ceiling_bytes": MAX_MEMORY_CEILING_BYTES,
        "max_duration_ceiling_millis": MAX_DURATION_CEILING_MILLIS,
    },
)

BudgetResultSchema.SCHEMA_VERSION_HASH = _compute_schema_version_hash(
    BudgetResultSchema.SCHEMA_ID,
    list(BudgetResultSchema._REQUIRED_FIELDS_ORDER),
    {
        "max_fields": BudgetResultSchema.MAX_FIELDS,
        "max_bytes": BudgetResultSchema.MAX_BYTES,
        "max_token_ceiling": MAX_TOKEN_CEILING,
        "max_step_ceiling": MAX_STEP_CEILING,
        "max_branch_ceiling": MAX_BRANCH_CEILING,
        "max_memory_ceiling_bytes": MAX_MEMORY_CEILING_BYTES,
        "max_duration_ceiling_millis": MAX_DURATION_CEILING_MILLIS,
    },
)


def default_budget_request(*, runtime_registry_hash: str) -> BudgetRequestSchema:
    payload: Dict[str, Any] = {
        "schema_id": BudgetRequestSchema.SCHEMA_ID,
        "schema_version_hash": BudgetRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "budget.default.v1",
        "runtime_registry_hash": runtime_registry_hash,
        "token_ceiling": MAX_TOKEN_CEILING,
        "step_ceiling": 64,
        "branch_ceiling": 16,
        "memory_ceiling_bytes": 4 * 1024 * 1024,
        "duration_ceiling_millis": 60_000,
        "parent_allocation_hash": _zero_hash(),
    }
    BudgetRequestSchema.validate(payload)
    return BudgetRequestSchema.from_dict(payload)


def budget_refusal_allocation(*, request: BudgetRequestSchema, refusal_code: str) -> BudgetAllocationSchema:
    req = request.to_dict()
    request_hash = BudgetRequestSchema.compute_request_hash(req)
    payload: Dict[str, Any] = {
        "schema_id": BudgetAllocationSchema.SCHEMA_ID,
        "schema_version_hash": BudgetAllocationSchema.SCHEMA_VERSION_HASH,
        "allocation_id": f"budget.alloc.{request_hash[:16]}",
        "runtime_registry_hash": req["runtime_registry_hash"],
        "request_hash": request_hash,
        "status": STATUS_REFUSED,
        "refusal_code": refusal_code,
        "allocation_hash": "",
        "token_ceiling": 0,
        "step_ceiling": 0,
        "branch_ceiling": 0,
        "memory_ceiling_bytes": 0,
        "duration_ceiling_millis": 0,
    }
    payload["allocation_hash"] = BudgetAllocationSchema.compute_allocation_hash(payload)
    BudgetAllocationSchema.validate(payload)
    return BudgetAllocationSchema.from_dict(payload)


def budget_ok_allocation(*, request: BudgetRequestSchema) -> BudgetAllocationSchema:
    req = request.to_dict()
    request_hash = BudgetRequestSchema.compute_request_hash(req)
    payload: Dict[str, Any] = {
        "schema_id": BudgetAllocationSchema.SCHEMA_ID,
        "schema_version_hash": BudgetAllocationSchema.SCHEMA_VERSION_HASH,
        "allocation_id": f"budget.alloc.{request_hash[:16]}",
        "runtime_registry_hash": req["runtime_registry_hash"],
        "request_hash": request_hash,
        "status": STATUS_OK,
        "allocation_hash": "",
        "token_ceiling": int(req["token_ceiling"]),
        "step_ceiling": int(req["step_ceiling"]),
        "branch_ceiling": int(req["branch_ceiling"]),
        "memory_ceiling_bytes": int(req["memory_ceiling_bytes"]),
        "duration_ceiling_millis": int(req["duration_ceiling_millis"]),
    }
    payload["allocation_hash"] = BudgetAllocationSchema.compute_allocation_hash(payload)
    BudgetAllocationSchema.validate(payload)
    return BudgetAllocationSchema.from_dict(payload)


def budget_result_ok(*, allocation: BudgetAllocationSchema, usage: BudgetConsumptionSchema) -> BudgetResultSchema:
    alloc = allocation.to_dict()
    u = usage.to_dict()
    payload: Dict[str, Any] = {
        "schema_id": BudgetResultSchema.SCHEMA_ID,
        "schema_version_hash": BudgetResultSchema.SCHEMA_VERSION_HASH,
        "status": STATUS_OK,
        "allocation_hash": alloc["allocation_hash"],
        "tokens_remaining": max(int(alloc["token_ceiling"]) - int(u["tokens_used"]), 0),
        "steps_remaining": max(int(alloc["step_ceiling"]) - int(u["steps_used"]), 0),
        "branches_remaining": max(int(alloc["branch_ceiling"]) - int(u["branches_used"]), 0),
        "memory_bytes_remaining": max(int(alloc["memory_ceiling_bytes"]) - int(u["memory_bytes_used"]), 0),
        "duration_millis_remaining": max(int(alloc["duration_ceiling_millis"]) - int(u["duration_millis_used"]), 0),
    }
    BudgetResultSchema.validate(payload)
    return BudgetResultSchema.from_dict(payload)


def budget_result_refused(*, allocation: BudgetAllocationSchema, refusal_code: str) -> BudgetResultSchema:
    alloc = allocation.to_dict()
    payload: Dict[str, Any] = {
        "schema_id": BudgetResultSchema.SCHEMA_ID,
        "schema_version_hash": BudgetResultSchema.SCHEMA_VERSION_HASH,
        "status": STATUS_REFUSED,
        "refusal_code": refusal_code,
        "allocation_hash": alloc.get("allocation_hash", _zero_hash()),
        "tokens_remaining": 0,
        "steps_remaining": 0,
        "branches_remaining": 0,
        "memory_bytes_remaining": 0,
        "duration_millis_remaining": 0,
    }
    BudgetResultSchema.validate(payload)
    return BudgetResultSchema.from_dict(payload)

