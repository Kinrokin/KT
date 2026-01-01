from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


class TeacherSchemaError(ValueError):
    pass


# Shared refusal codes (aligned with C016 curriculum ingestion).
REFUSE_SCHEMA = "REFUSE_SCHEMA"
REFUSE_OVERSIZE = "REFUSE_OVERSIZE"
REFUSE_ILLEGAL_FIELD = "REFUSE_ILLEGAL_FIELD"
REFUSE_EXECUTABLE_CONTENT = "REFUSE_EXECUTABLE_CONTENT"
REFUSE_STUDENT_TO_TEACHER_FLOW = "REFUSE_STUDENT_TO_TEACHER_FLOW"
REFUSE_POLICY_OVERRIDE = "REFUSE_POLICY_OVERRIDE"
REFUSE_FORBIDDEN_IMPORT = "REFUSE_FORBIDDEN_IMPORT"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(_canonical_json(obj))


def _enforce_max_canonical_json_bytes(payload: Dict[str, Any], *, max_bytes: int) -> None:
    encoded = _canonical_json(payload).encode("utf-8")
    if len(encoded) > max_bytes:
        raise TeacherSchemaError(f"{REFUSE_OVERSIZE}: payload exceeds max bytes (fail-closed)")


def _validate_bounded_json_value(value: Any, *, max_depth: int, max_string_len: int, max_list_len: int, _depth: int = 0) -> None:
    if _depth > max_depth:
        raise TeacherSchemaError(f"{REFUSE_OVERSIZE}: payload exceeds max depth (fail-closed)")
    if isinstance(value, str):
        if len(value) > max_string_len:
            raise TeacherSchemaError(f"{REFUSE_OVERSIZE}: string exceeds max length (fail-closed)")
    elif isinstance(value, list):
        if len(value) > max_list_len:
            raise TeacherSchemaError(f"{REFUSE_OVERSIZE}: list exceeds max length (fail-closed)")
        for item in value:
            _validate_bounded_json_value(item, max_depth=max_depth, max_string_len=max_string_len, max_list_len=max_list_len, _depth=_depth + 1)
    elif isinstance(value, dict):
        for item in value.values():
            _validate_bounded_json_value(item, max_depth=max_depth, max_string_len=max_string_len, max_list_len=max_list_len, _depth=_depth + 1)
    else:
        return

def _reject_unknown_keys(payload: Mapping[str, Any], *, allowed: Iterable[str], name: str) -> None:
    unknown = set(payload.keys()) - set(allowed)
    if unknown:
        raise TeacherSchemaError(f"{name} contains unknown keys: {sorted(unknown)} (fail-closed)")


def _require_dict(value: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise TeacherSchemaError(f"{name} must be an object (fail-closed)")
    return dict(value)


def _require_list(value: Any, *, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise TeacherSchemaError(f"{name} must be a list (fail-closed)")
    return list(value)


def _require_str(value: Any, *, name: str, min_len: int = 1, max_len: int = 256) -> str:
    if not isinstance(value, str):
        raise TeacherSchemaError(f"{name} must be a string (fail-closed)")
    if not (min_len <= len(value) <= max_len):
        raise TeacherSchemaError(f"{name} length out of bounds (fail-closed)")
    return value


def _require_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(value, int):
        raise TeacherSchemaError(f"{name} must be an integer (fail-closed)")
    if not (lo <= value <= hi):
        raise TeacherSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _validate_hex64(value: str, *, name: str) -> None:
    if len(value) != 64:
        raise TeacherSchemaError(f"{name} must be 64 hex chars (fail-closed)")
    try:
        int(value, 16)
    except Exception:
        raise TeacherSchemaError(f"{name} must be hex (fail-closed)")


def _refuse_for_unknown_keys(extra_keys: Set[str]) -> TeacherSchemaError:
    lowered = " ".join(sorted(k.lower() for k in extra_keys))
    if any(tok in lowered for tok in ("script", "code", "exec", "macro", "shell", "bash", "powershell", "python")):
        return TeacherSchemaError(f"{REFUSE_EXECUTABLE_CONTENT}: executable field present (fail-closed)")
    if any(tok in lowered for tok in ("policy", "override", "rule_id", "allow", "deny", "veto")):
        return TeacherSchemaError(f"{REFUSE_POLICY_OVERRIDE}: policy override field present (fail-closed)")
    if any(tok in lowered for tok in ("receipt", "vault", "trace", "log", "output", "runtime", "stdout", "stderr")):
        return TeacherSchemaError(f"{REFUSE_STUDENT_TO_TEACHER_FLOW}: runtime-derived field present (fail-closed)")
    return TeacherSchemaError(f"{REFUSE_ILLEGAL_FIELD}: forbidden field present (fail-closed)")


def _require_list_of_hex64(payload: Dict[str, Any], field: str, *, max_len: int) -> List[str]:
    value = payload.get(field)
    if not isinstance(value, list):
        raise TeacherSchemaError(f"{field} must be a list (fail-closed)")
    if len(value) > max_len:
        raise TeacherSchemaError(f"{REFUSE_OVERSIZE}: {field} exceeds max length (fail-closed)")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TeacherSchemaError(f"{field} must contain strings only (fail-closed)")
        _validate_hex64(item, name=field)
        out.append(item)
    return out


def _reject_raw_paths(paths: Iterable[str]) -> None:
    for p in paths:
        lowered = p.lower()
        if any(tok in lowered for tok in ("stdout", "stderr", "trace", "prompt", "chain-of-thought", "cot")):
            raise TeacherSchemaError(f"{REFUSE_STUDENT_TO_TEACHER_FLOW}: raw runtime content referenced (fail-closed)")


@dataclass(frozen=True)
class BaseSchema:
    data: Dict[str, Any]

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "BaseSchema":
        payload = _require_dict(payload, name="schema payload")
        cls.validate(payload)
        return cls(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


@dataclass(frozen=True)
class TeacherInputBundleSchema(BaseSchema):
    SCHEMA_ID = "teacher.bundle"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    MAX_FIELDS = 16
    MAX_LIST_LEN = 64

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        allowed = {
            "schema_id",
            "schema_version_hash",
            "runtime_registry_path",
            "epoch_manifest_paths",
            "run_record_paths",
            "extract_types",
            "bounds",
        }
        _reject_unknown_keys(payload, allowed=allowed, name="TeacherInputBundle")

        schema_id = _require_str(payload.get("schema_id"), name="schema_id", max_len=64)
        if schema_id != cls.SCHEMA_ID:
            raise TeacherSchemaError("schema_id mismatch (fail-closed)")
        schema_version_hash = _require_str(payload.get("schema_version_hash"), name="schema_version_hash", min_len=64, max_len=64)
        _validate_hex64(schema_version_hash, name="schema_version_hash")
        if schema_version_hash != cls.SCHEMA_VERSION_HASH:
            raise TeacherSchemaError("schema_version_hash mismatch (fail-closed)")

        runtime_registry_path = _require_str(payload.get("runtime_registry_path"), name="runtime_registry_path", max_len=512)
        _reject_raw_paths([runtime_registry_path])

        epoch_paths = _require_list(payload.get("epoch_manifest_paths"), name="epoch_manifest_paths")
        run_paths = _require_list(payload.get("run_record_paths"), name="run_record_paths")
        if len(epoch_paths) > cls.MAX_LIST_LEN or len(run_paths) > cls.MAX_LIST_LEN:
            raise TeacherSchemaError(f"{REFUSE_OVERSIZE}: path lists exceed bounds (fail-closed)")
        _reject_raw_paths([str(p) for p in epoch_paths + run_paths])

        extract_types = _require_list(payload.get("extract_types"), name="extract_types")
        allowed_types = {"EPOCH_MANIFEST", "RUN_RECORD", "GOVERNANCE_SUMMARY", "BUDGET_SUMMARY"}
        for idx, t in enumerate(extract_types):
            t = _require_str(t, name=f"extract_types[{idx}]", max_len=64)
            if t not in allowed_types:
                raise TeacherSchemaError(f"extract_types contains invalid value: {t} (fail-closed)")

        bounds = _require_dict(payload.get("bounds"), name="bounds")
        _reject_unknown_keys(bounds, allowed={"max_examples", "max_instructions", "max_constraints"}, name="bounds")
        _require_int(bounds.get("max_examples", 16), name="bounds.max_examples", lo=0, hi=16)
        _require_int(bounds.get("max_instructions", 16), name="bounds.max_instructions", lo=0, hi=16)
        _require_int(bounds.get("max_constraints", 16), name="bounds.max_constraints", lo=0, hi=16)

    @classmethod
    def compute_schema_version_hash(cls) -> str:
        spec = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version": cls.SCHEMA_VERSION,
            "required_fields": [
                "schema_id",
                "schema_version_hash",
                "runtime_registry_path",
                "epoch_manifest_paths",
                "run_record_paths",
                "extract_types",
                "bounds",
            ],
            "limits": {"max_fields": cls.MAX_FIELDS, "max_list_len": cls.MAX_LIST_LEN},
        }
        return sha256_json(spec)


class CurriculumDraftSchema(BaseSchema):
    SCHEMA_ID = "curriculum.draft"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        allowed = {"schema_id", "schema_version_hash", "examples", "instructions", "constraints"}
        _reject_unknown_keys(payload, allowed=allowed, name="CurriculumDraft")

        schema_id = _require_str(payload.get("schema_id"), name="schema_id", max_len=64)
        if schema_id != cls.SCHEMA_ID:
            raise TeacherSchemaError("draft schema_id mismatch (fail-closed)")
        schema_version_hash = _require_str(payload.get("schema_version_hash"), name="schema_version_hash", min_len=64, max_len=64)
        _validate_hex64(schema_version_hash, name="schema_version_hash")
        if schema_version_hash != cls.SCHEMA_VERSION_HASH:
            raise TeacherSchemaError("draft schema_version_hash mismatch (fail-closed)")

        _require_list_of_hex64(payload, "examples", max_len=16)
        _require_list_of_hex64(payload, "instructions", max_len=16)
        _require_list_of_hex64(payload, "constraints", max_len=16)

    @classmethod
    def compute_schema_version_hash(cls) -> str:
        spec = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version": cls.SCHEMA_VERSION,
            "required_fields": ["schema_id", "schema_version_hash", "examples", "instructions", "constraints"],
        }
        return sha256_json(spec)


class CurriculumPackageSchema(BaseSchema):
    # Must match V2 runtime schema exactly.
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
    MAX_REFS = 16
    MAX_DEPTH = 4
    MAX_STRING_LEN = 128
    MAX_LIST_LEN = 16

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        payload = _require_dict(payload, name="CurriculumPackage")
        if len(payload) > cls.MAX_FIELDS:
            raise TeacherSchemaError(f"{REFUSE_OVERSIZE}: CurriculumPackage exceeds max fields (fail-closed)")

        missing = cls._REQUIRED_FIELDS - set(payload.keys())
        if missing:
            raise TeacherSchemaError(f"{REFUSE_SCHEMA}: missing fields {sorted(missing)} (fail-closed)")

        extra = set(payload.keys()) - cls._ALLOWED_FIELDS
        if extra:
            raise _refuse_for_unknown_keys(extra)

        schema_id = _require_str(payload.get("schema_id"), name="schema_id", max_len=64)
        if schema_id != cls.SCHEMA_ID:
            raise TeacherSchemaError("schema_id mismatch (fail-closed)")

        schema_version_hash = _require_str(payload.get("schema_version_hash"), name="schema_version_hash", min_len=64, max_len=64)
        _validate_hex64(schema_version_hash, name="schema_version_hash")
        if schema_version_hash != cls.SCHEMA_VERSION_HASH:
            raise TeacherSchemaError("schema_version_hash mismatch (fail-closed)")

        _require_str(payload.get("package_id"), name="package_id", max_len=64)
        runtime_registry_hash = _require_str(payload.get("runtime_registry_hash"), name="runtime_registry_hash", min_len=64, max_len=64)
        _validate_hex64(runtime_registry_hash, name="runtime_registry_hash")

        _require_list_of_hex64(payload, "examples", max_len=cls.MAX_REFS)
        _require_list_of_hex64(payload, "instructions", max_len=cls.MAX_REFS)
        _require_list_of_hex64(payload, "constraints", max_len=cls.MAX_REFS)
        _validate_bounded_json_value(
            payload,
            max_depth=cls.MAX_DEPTH,
            max_string_len=cls.MAX_STRING_LEN,
            max_list_len=cls.MAX_LIST_LEN,
        )
        _enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)

    @classmethod
    def compute_package_hash(cls, payload: Dict[str, Any]) -> str:
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

    @classmethod
    def compute_schema_version_hash(cls) -> str:
        spec = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version": cls.SCHEMA_VERSION,
            "required_fields": list(cls._REQUIRED_FIELDS_ORDER),
            "limits": {"max_fields": cls.MAX_FIELDS, "max_bytes": cls.MAX_BYTES},
            "payload_bounds": {
                "max_depth": cls.MAX_DEPTH,
                "max_string_len": cls.MAX_STRING_LEN,
                "max_list_len": cls.MAX_LIST_LEN,
                "max_refs": cls.MAX_REFS,
            },
        }
        return sha256_json(spec)


class CurriculumSignatureSchema(BaseSchema):
    SCHEMA_ID = "curriculum.signature"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        allowed = {"schema_id", "schema_version_hash", "key_id", "package_hash", "signature"}
        _reject_unknown_keys(payload, allowed=allowed, name="CurriculumSignature")
        schema_id = _require_str(payload.get("schema_id"), name="schema_id", max_len=64)
        if schema_id != cls.SCHEMA_ID:
            raise TeacherSchemaError("signature schema_id mismatch (fail-closed)")
        schema_version_hash = _require_str(payload.get("schema_version_hash"), name="schema_version_hash", min_len=64, max_len=64)
        _validate_hex64(schema_version_hash, name="schema_version_hash")
        if schema_version_hash != cls.SCHEMA_VERSION_HASH:
            raise TeacherSchemaError("signature schema_version_hash mismatch (fail-closed)")
        _require_str(payload.get("key_id"), name="key_id", max_len=64)
        package_hash = _require_str(payload.get("package_hash"), name="package_hash", min_len=64, max_len=64)
        _validate_hex64(package_hash, name="package_hash")
        signature = _require_str(payload.get("signature"), name="signature", min_len=1, max_len=128)
        # Signature may be a hex digest or explicit "NONE".
        if signature != "NONE":
            _validate_hex64(signature, name="signature")

    @classmethod
    def compute_schema_version_hash(cls) -> str:
        spec = {
            "schema_id": cls.SCHEMA_ID,
            "schema_version": cls.SCHEMA_VERSION,
            "required_fields": ["schema_id", "schema_version_hash", "key_id", "package_hash", "signature"],
        }
        return sha256_json(spec)


# Bind schema version hashes deterministically (match runtime pattern).
setattr(TeacherInputBundleSchema, "SCHEMA_VERSION_HASH", TeacherInputBundleSchema.compute_schema_version_hash())
setattr(CurriculumDraftSchema, "SCHEMA_VERSION_HASH", CurriculumDraftSchema.compute_schema_version_hash())
setattr(CurriculumPackageSchema, "SCHEMA_VERSION_HASH", CurriculumPackageSchema.compute_schema_version_hash())
setattr(CurriculumSignatureSchema, "SCHEMA_VERSION_HASH", CurriculumSignatureSchema.compute_schema_version_hash())
