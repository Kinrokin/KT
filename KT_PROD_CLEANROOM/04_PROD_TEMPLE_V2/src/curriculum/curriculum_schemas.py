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

CURRICULUM_MAX_DEPTH = 4
CURRICULUM_MAX_STRING_LEN = 128
CURRICULUM_MAX_LIST_LEN = 16

MAX_REFS = 16
MAX_ID_LEN = 64

STATUS_OK = "OK"
STATUS_REFUSED = "REFUSED"
STATUS_ERROR = "ERROR"

REFUSE_SCHEMA = "REFUSE_SCHEMA"
REFUSE_OVERSIZE = "REFUSE_OVERSIZE"
REFUSE_ILLEGAL_FIELD = "REFUSE_ILLEGAL_FIELD"
REFUSE_EXECUTABLE_CONTENT = "REFUSE_EXECUTABLE_CONTENT"
REFUSE_STUDENT_TO_TEACHER_FLOW = "REFUSE_STUDENT_TO_TEACHER_FLOW"
REFUSE_POLICY_OVERRIDE = "REFUSE_POLICY_OVERRIDE"
REFUSE_FORBIDDEN_IMPORT = "REFUSE_FORBIDDEN_IMPORT"


@dataclass(frozen=True)
class CurriculumRefusalError(ValueError):
    refusal_code: str
    message: str

    def __str__(self) -> str:
        return f"{self.refusal_code}: {self.message}"


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


def _refuse_for_unknown_keys(extra_keys: Set[str]) -> CurriculumRefusalError:
    lowered = " ".join(sorted(k.lower() for k in extra_keys))
    if any(tok in lowered for tok in ("script", "code", "exec", "macro", "shell", "bash", "powershell", "python")):
        return CurriculumRefusalError(REFUSE_EXECUTABLE_CONTENT, "Executable-content field present (fail-closed)")
    if any(tok in lowered for tok in ("policy", "override", "rule_id", "allow", "deny", "veto")):
        return CurriculumRefusalError(REFUSE_POLICY_OVERRIDE, "Policy-override field present (fail-closed)")
    if any(tok in lowered for tok in ("receipt", "vault", "trace", "log", "output", "runtime")):
        return CurriculumRefusalError(REFUSE_STUDENT_TO_TEACHER_FLOW, "Student→Teacher field present (fail-closed)")
    return CurriculumRefusalError(REFUSE_ILLEGAL_FIELD, "Forbidden field present (fail-closed)")


def _require_list_of_hex64(payload: Dict[str, Any], field: str, *, max_len: int) -> None:
    value = payload.get(field)
    if not isinstance(value, list):
        raise SchemaValidationError(f"{field} must be a list")
    if len(value) > max_len:
        raise CurriculumRefusalError(REFUSE_OVERSIZE, f"{field} exceeds max length (fail-closed)")
    for item in value:
        if not isinstance(item, str):
            raise SchemaValidationError(f"{field} must contain strings only")
        if len(item) != 64:
            raise SchemaValidationError(f"{field} entries must be 64 lowercase hex chars")
        # validate_hex_64 expects mapping; do minimal inline check by reusing regex via validate_hex_64 on temp.
        validate_hex_64({field: item}, field)


class CurriculumPackageSchema(BaseSchema):
    SCHEMA_ID = "curriculum.package"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "package_id",
        "runtime_registry_hash",
        "examples",
        "instructions",
        "constraints",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 16
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CurriculumPackage")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)

        extra = set(payload.keys()) - cls._ALLOWED_FIELDS
        if extra:
            raise _refuse_for_unknown_keys(extra)

        validate_short_string(payload, "schema_id", max_len=MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        validate_short_string(payload, "package_id", max_len=MAX_ID_LEN)
        validate_hex_64(payload, "runtime_registry_hash")

        _require_list_of_hex64(payload, "examples", max_len=MAX_REFS)
        _require_list_of_hex64(payload, "instructions", max_len=MAX_REFS)
        _require_list_of_hex64(payload, "constraints", max_len=MAX_REFS)

        validate_bounded_json_value(
            payload,
            max_depth=CURRICULUM_MAX_DEPTH,
            max_string_len=CURRICULUM_MAX_STRING_LEN,
            max_list_len=CURRICULUM_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_package_hash(cls, payload: Dict[str, Any]) -> str:
        # Deterministic, hash-only binding. No wall-clock fields.
        obj = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "package_id": payload.get("package_id"),
            "runtime_registry_hash": payload.get("runtime_registry_hash"),
            "examples": sorted([str(x) for x in payload.get("examples") or []]),
            "instructions": sorted([str(x) for x in payload.get("instructions") or []]),
            "constraints": sorted([str(x) for x in payload.get("constraints") or []]),
        }
        return sha256_json(obj)


class CurriculumReceiptSchema(BaseSchema):
    SCHEMA_ID = "curriculum.receipt"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "status",
        "runtime_registry_hash",
        "package_hash",
        "receipt_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER) | {"refusal_code"}

    MAX_FIELDS = 12
    MAX_BYTES = 2048

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="CurriculumReceipt")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=MAX_ID_LEN)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")

        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        status = payload.get("status")
        if status not in {STATUS_OK, STATUS_REFUSED, STATUS_ERROR}:
            raise SchemaValidationError("status must be OK/REFUSED/ERROR")

        validate_hex_64(payload, "runtime_registry_hash")
        validate_hex_64(payload, "package_hash")
        validate_hex_64(payload, "receipt_hash")

        rc = payload.get("refusal_code")
        if rc is not None:
            validate_short_string(payload, "refusal_code", max_len=64)

        expected = cls.compute_receipt_hash(payload)
        if payload["receipt_hash"] != expected:
            raise SchemaValidationError("receipt_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=CURRICULUM_MAX_DEPTH,
            max_string_len=CURRICULUM_MAX_STRING_LEN,
            max_list_len=CURRICULUM_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_receipt_hash(cls, payload: Dict[str, Any]) -> str:
        obj = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version_hash": cls.SCHEMA_VERSION_HASH,
            "status": payload.get("status"),
            "runtime_registry_hash": payload.get("runtime_registry_hash"),
            "package_hash": payload.get("package_hash"),
            "refusal_code": payload.get("refusal_code"),
        }
        return sha256_json(obj)


def _compute_package_schema_version_hash() -> str:
    spec = {
        "schema_id": CurriculumPackageSchema.SCHEMA_ID,
        "schema_version": CurriculumPackageSchema.SCHEMA_VERSION,
        "required_fields": list(CurriculumPackageSchema._REQUIRED_FIELDS_ORDER),
        "limits": {"max_fields": CurriculumPackageSchema.MAX_FIELDS, "max_bytes": CurriculumPackageSchema.MAX_BYTES},
        "payload_bounds": {
            "max_depth": CURRICULUM_MAX_DEPTH,
            "max_string_len": CURRICULUM_MAX_STRING_LEN,
            "max_list_len": CURRICULUM_MAX_LIST_LEN,
            "max_refs": MAX_REFS,
        },
    }
    return sha256_json(spec)


def _compute_receipt_schema_version_hash() -> str:
    spec = {
        "schema_id": CurriculumReceiptSchema.SCHEMA_ID,
        "schema_version": CurriculumReceiptSchema.SCHEMA_VERSION,
        "required_fields": list(CurriculumReceiptSchema._REQUIRED_FIELDS_ORDER),
        "limits": {"max_fields": CurriculumReceiptSchema.MAX_FIELDS, "max_bytes": CurriculumReceiptSchema.MAX_BYTES},
        "refusal_codes": [
            REFUSE_SCHEMA,
            REFUSE_OVERSIZE,
            REFUSE_ILLEGAL_FIELD,
            REFUSE_EXECUTABLE_CONTENT,
            REFUSE_STUDENT_TO_TEACHER_FLOW,
            REFUSE_POLICY_OVERRIDE,
            REFUSE_FORBIDDEN_IMPORT,
        ],
    }
    return sha256_json(spec)


setattr(CurriculumPackageSchema, "SCHEMA_VERSION_HASH", _compute_package_schema_version_hash())
setattr(CurriculumReceiptSchema, "SCHEMA_VERSION_HASH", _compute_receipt_schema_version_hash())

