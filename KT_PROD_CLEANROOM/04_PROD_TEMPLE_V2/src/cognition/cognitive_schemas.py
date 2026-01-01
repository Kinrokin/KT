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

COGNITION_MAX_DEPTH = 6
COGNITION_MAX_STRING_LEN = 256
COGNITION_MAX_LIST_LEN = 64

MAX_ARTIFACT_REFS = 16
MAX_STEPS_HARD = 16
MAX_BRANCHING_HARD = 4
MAX_DEPTH_HARD = 16

MODE_DRY_RUN = "DRY_RUN"
MODE_LIVE_REQUESTED = "LIVE_REQUESTED"

PLAN_STATUS_OK = "OK"
PLAN_STATUS_REFUSED = "REFUSED"

RESULT_STATUS_OK = "OK"
RESULT_STATUS_REFUSED = "REFUSED"
RESULT_STATUS_ERROR = "ERROR"

STEP_STATUS_OK = "OK"
STEP_STATUS_SKIPPED = "SKIPPED"

REFUSE_POLICY = "REFUSE_POLICY"
REFUSE_BOUNDS = "REFUSE_BOUNDS"
REFUSE_SCHEMA = "REFUSE_SCHEMA"
REFUSE_EXTERNAL_UNAVAILABLE = "REFUSE_EXTERNAL_UNAVAILABLE"
REFUSE_ILLEGAL_REFERENCE = "REFUSE_ILLEGAL_REFERENCE"


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


def _require_bool(payload: Dict[str, Any], field: str) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise SchemaValidationError(f"{field} must be a boolean")
    return value


def _zero_hash() -> str:
    return "0" * 64


class CognitiveRequestSchema(BaseSchema):
    SCHEMA_ID = "cognition.request"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "request_id",
        "runtime_registry_hash",
        "mode",
        "input_hash",
        "max_steps",
        "max_branching",
        "max_depth",
        "artifact_refs",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 20
    MAX_BYTES = 8192
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CognitiveRequest")
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

        validate_hex_64(payload, "input_hash")

        _require_int_range(payload, "max_steps", lo=1, hi=MAX_STEPS_HARD)
        _require_int_range(payload, "max_branching", lo=1, hi=MAX_BRANCHING_HARD)
        _require_int_range(payload, "max_depth", lo=1, hi=MAX_DEPTH_HARD)

        refs_value = payload.get("artifact_refs")
        if not isinstance(refs_value, list):
            raise SchemaValidationError("artifact_refs must be a list")
        if len(refs_value) > MAX_ARTIFACT_REFS:
            raise SchemaValidationError("artifact_refs exceeds max refs (fail-closed)")

        for item in refs_value:
            ref = require_dict(item, name="artifact_ref")
            allowed = {"artifact_id", "artifact_hash", "schema_id", "schema_version_hash"}
            reject_unknown_keys(ref, allowed=allowed)
            require_keys(ref, required={"artifact_id", "artifact_hash"})
            validate_short_string(ref, "artifact_id", max_len=cls.MAX_ID_LEN)
            validate_hex_64(ref, "artifact_hash")
            schema_id = ref.get("schema_id")
            if schema_id is not None:
                validate_short_string(ref, "schema_id", max_len=cls.MAX_ID_LEN)
            schema_version_hash = ref.get("schema_version_hash")
            if schema_version_hash is not None:
                validate_hex_64(ref, "schema_version_hash")

        validate_bounded_json_value(
            payload,
            max_depth=COGNITION_MAX_DEPTH,
            max_string_len=COGNITION_MAX_STRING_LEN,
            max_list_len=COGNITION_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_request_hash(cls, payload: Dict[str, Any]) -> str:
        refs = payload.get("artifact_refs")
        refs_sorted = (
            sorted(
                [require_dict(r, name="artifact_ref") for r in refs],
                key=lambda r: f"{r.get('artifact_id','')}:{r.get('artifact_hash','')}",
            )
            if isinstance(refs, list)
            else []
        )

        obj = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "request_id": payload["request_id"],
            "runtime_registry_hash": payload["runtime_registry_hash"],
            "mode": payload["mode"],
            "input_hash": payload["input_hash"],
            "max_steps": payload["max_steps"],
            "max_branching": payload["max_branching"],
            "max_depth": payload["max_depth"],
            "artifact_refs": refs_sorted,
        }
        return sha256_json(obj)


class CognitivePlanSchema(BaseSchema):
    SCHEMA_ID = "cognition.plan"
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
        "steps",
        "plan_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"refusal_code"}

    MAX_FIELDS = 24
    MAX_BYTES = 16 * 1024
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CognitivePlan")
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

        steps_value = payload.get("steps")
        if not isinstance(steps_value, list):
            raise SchemaValidationError("steps must be a list")
        if len(steps_value) > MAX_STEPS_HARD:
            raise SchemaValidationError("steps exceeds max steps (fail-closed)")
        for s in steps_value:
            step = require_dict(s, name="step")
            allowed = {"step_index", "step_type", "step_hash"}
            reject_unknown_keys(step, allowed=allowed)
            require_keys(step, required=set(allowed))
            _require_int_range(step, "step_index", lo=0, hi=MAX_STEPS_HARD - 1)
            validate_short_string(step, "step_type", max_len=32)
            validate_hex_64(step, "step_hash")

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
            max_depth=COGNITION_MAX_DEPTH,
            max_string_len=COGNITION_MAX_STRING_LEN,
            max_list_len=COGNITION_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_plan_hash(cls, payload: Dict[str, Any]) -> str:
        steps_value = payload.get("steps")
        steps_sorted = (
            sorted(
                [require_dict(s, name="step") for s in steps_value],
                key=lambda s: int(s.get("step_index", 0)),
            )
            if isinstance(steps_value, list)
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
            "steps": steps_sorted,
            "refusal_code": payload.get("refusal_code"),
        }
        return sha256_json(obj)


class CognitiveStepResultSchema(BaseSchema):
    SCHEMA_ID = "cognition.step_result"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "step_index",
        "step_type",
        "status",
        "score_0_100",
        "step_result_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 16
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CognitiveStepResult")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        _require_int_range(payload, "step_index", lo=0, hi=MAX_STEPS_HARD - 1)
        validate_short_string(payload, "step_type", max_len=32)
        _require_enum(payload, "status", allowed={STEP_STATUS_OK, STEP_STATUS_SKIPPED})
        _require_int_range(payload, "score_0_100", lo=0, hi=100)
        validate_hex_64(payload, "step_result_hash")

        expected = cls.compute_step_result_hash(payload)
        if payload["step_result_hash"] != expected:
            raise SchemaValidationError("step_result_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=COGNITION_MAX_DEPTH,
            max_string_len=COGNITION_MAX_STRING_LEN,
            max_list_len=COGNITION_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_step_result_hash(cls, payload: Dict[str, Any]) -> str:
        obj = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "step_index": payload.get("step_index"),
            "step_type": payload.get("step_type"),
            "status": payload.get("status"),
            "score_0_100": payload.get("score_0_100"),
        }
        return sha256_json(obj)


class CognitiveResultSchema(BaseSchema):
    SCHEMA_ID = "cognition.result"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "status",
        "plan_hash",
        "steps",
        "result_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"refusal_code", "error_code"}

    MAX_FIELDS = 24
    MAX_BYTES = 16 * 1024
    MAX_ID_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CognitiveResult")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=cls.MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        status = _require_enum(payload, "status", allowed={RESULT_STATUS_OK, RESULT_STATUS_REFUSED, RESULT_STATUS_ERROR})
        validate_hex_64(payload, "plan_hash")

        steps_value = payload.get("steps")
        if not isinstance(steps_value, list):
            raise SchemaValidationError("steps must be a list")
        if len(steps_value) > MAX_STEPS_HARD:
            raise SchemaValidationError("steps exceeds max steps (fail-closed)")
        for s in steps_value:
            step = require_dict(s, name="step_result")
            CognitiveStepResultSchema.validate(step)

        refusal_code = payload.get("refusal_code")
        error_code = payload.get("error_code")
        if status == RESULT_STATUS_REFUSED:
            if not isinstance(refusal_code, str) or not refusal_code:
                raise SchemaValidationError("refusal_code required when status=REFUSED (fail-closed)")
        else:
            if refusal_code is not None:
                raise SchemaValidationError("refusal_code forbidden unless status=REFUSED (fail-closed)")

        if status == RESULT_STATUS_ERROR:
            if not isinstance(error_code, str) or not error_code:
                raise SchemaValidationError("error_code required when status=ERROR (fail-closed)")
        else:
            if error_code is not None:
                raise SchemaValidationError("error_code forbidden unless status=ERROR (fail-closed)")

        validate_hex_64(payload, "result_hash")
        expected = cls.compute_result_hash(payload)
        if payload["result_hash"] != expected:
            raise SchemaValidationError("result_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=COGNITION_MAX_DEPTH,
            max_string_len=COGNITION_MAX_STRING_LEN,
            max_list_len=COGNITION_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_result_hash(cls, payload: Dict[str, Any]) -> str:
        steps_value = payload.get("steps")
        steps_sorted = (
            sorted(
                [require_dict(s, name="step_result") for s in steps_value],
                key=lambda s: int(s.get("step_index", 0)),
            )
            if isinstance(steps_value, list)
            else []
        )
        obj: Dict[str, Any] = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "status": payload.get("status"),
            "plan_hash": payload.get("plan_hash"),
            "steps": steps_sorted,
            "refusal_code": payload.get("refusal_code"),
            "error_code": payload.get("error_code"),
        }
        return sha256_json(obj)


def _compute_cognitive_request_schema_version_hash() -> str:
    spec = {
        "schema_id": CognitiveRequestSchema.SCHEMA_ID,
        "schema_version": CognitiveRequestSchema.SCHEMA_VERSION,
        "required_fields": list(CognitiveRequestSchema._REQUIRED_FIELDS_ORDER),
        "limits": {
            "max_fields": CognitiveRequestSchema.MAX_FIELDS,
            "max_bytes": CognitiveRequestSchema.MAX_BYTES,
            "max_artifact_refs": MAX_ARTIFACT_REFS,
            "max_steps_hard": MAX_STEPS_HARD,
            "max_branching_hard": MAX_BRANCHING_HARD,
            "max_depth_hard": MAX_DEPTH_HARD,
        },
    }
    return sha256_json(spec)


def _compute_cognitive_plan_schema_version_hash() -> str:
    spec = {
        "schema_id": CognitivePlanSchema.SCHEMA_ID,
        "schema_version": CognitivePlanSchema.SCHEMA_VERSION,
        "required_fields": list(CognitivePlanSchema._REQUIRED_FIELDS_ORDER),
        "limits": {"max_fields": CognitivePlanSchema.MAX_FIELDS, "max_bytes": CognitivePlanSchema.MAX_BYTES},
    }
    return sha256_json(spec)


def _compute_cognitive_step_result_schema_version_hash() -> str:
    spec = {
        "schema_id": CognitiveStepResultSchema.SCHEMA_ID,
        "schema_version": CognitiveStepResultSchema.SCHEMA_VERSION,
        "required_fields": list(CognitiveStepResultSchema._REQUIRED_FIELDS_ORDER),
        "limits": {"max_fields": CognitiveStepResultSchema.MAX_FIELDS, "max_bytes": CognitiveStepResultSchema.MAX_BYTES},
    }
    return sha256_json(spec)


def _compute_cognitive_result_schema_version_hash() -> str:
    spec = {
        "schema_id": CognitiveResultSchema.SCHEMA_ID,
        "schema_version": CognitiveResultSchema.SCHEMA_VERSION,
        "required_fields": list(CognitiveResultSchema._REQUIRED_FIELDS_ORDER),
        "limits": {"max_fields": CognitiveResultSchema.MAX_FIELDS, "max_bytes": CognitiveResultSchema.MAX_BYTES},
    }
    return sha256_json(spec)


setattr(CognitiveRequestSchema, "SCHEMA_VERSION_HASH", _compute_cognitive_request_schema_version_hash())
setattr(CognitivePlanSchema, "SCHEMA_VERSION_HASH", _compute_cognitive_plan_schema_version_hash())
setattr(CognitiveStepResultSchema, "SCHEMA_VERSION_HASH", _compute_cognitive_step_result_schema_version_hash())
setattr(CognitiveResultSchema, "SCHEMA_VERSION_HASH", _compute_cognitive_result_schema_version_hash())

