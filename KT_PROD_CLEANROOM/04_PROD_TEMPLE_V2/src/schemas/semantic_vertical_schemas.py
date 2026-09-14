from __future__ import annotations

import hashlib
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


MODE_OFFLINE_PROOF = "OFFLINE_PROOF"
MODE_LIVE_REQUESTED = "LIVE_REQUESTED"
SEMANTIC_DECISIONS = {"PASS", "FAIL"}
SEMANTIC_REASON_CODES = {"ACCEPT", "REJECT"}
MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024
MAX_SEMANTIC_CONTENT_BYTES = 2048
MAX_SEMANTIC_SUBJECT_BYTES = 4096


class SemanticVerticalError(RuntimeError):
    """Fail-closed error for the bounded PR-B semantic chain."""


def _canonical_spec_hash(schema_id: str, version: str, fields: tuple[str, ...], limits: Dict[str, Any]) -> str:
    return sha256_json(
        {
            "schema_id": schema_id,
            "schema_version": version,
            "required_fields": list(fields),
            "limits": limits,
        }
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_int(payload: Dict[str, Any], field: str, *, low: int, high: int) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise SchemaValidationError(f"{field} must be integer in {low}..{high} (fail-closed)")
    return value


def _require_bool(payload: Dict[str, Any], field: str) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise SchemaValidationError(f"{field} must be boolean (fail-closed)")
    return value


def _require_exact_enum(payload: Dict[str, Any], field: str, allowed: Set[str]) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or value not in allowed:
        raise SchemaValidationError(f"{field} must be one of {sorted(allowed)} (fail-closed)")
    return value


@dataclass(frozen=True)
class SemanticCouncilRequestSchema:
    SCHEMA_ID = "council.semantic_request.v1"
    SCHEMA_VERSION = "1.0"
    _FIELDS = (
        "schema_id",
        "schema_version_hash",
        "request_id",
        "runtime_registry_hash",
        "mode",
        "provider_id",
        "adapter_id",
        "request_type",
        "model",
        "instruction",
        "subject",
        "subject_hash",
        "nonce",
        "max_output_tokens",
        "timeout_ms",
        "probe_enabled",
    )
    SCHEMA_VERSION_HASH = _canonical_spec_hash(
        SCHEMA_ID,
        SCHEMA_VERSION,
        _FIELDS,
        {
            "provider_id": "openai",
            "adapter_id": "council.openai.live_semantic.v1",
            "request_type": "analysis",
            "max_output_tokens": 512,
            "max_timeout_ms": 20000,
            "max_instruction_bytes": 2048,
            "subject_schema": "kt.semantic_subject.v1",
            "max_subject_bytes": MAX_SEMANTIC_SUBJECT_BYTES,
            "probe_non_steering": True,
            "authorized_modes_in_this_source_change": [MODE_OFFLINE_PROOF],
        },
    )

    data: Dict[str, Any]

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="SemanticCouncilRequest")
        enforce_max_fields(payload, max_fields=len(cls._FIELDS))
        require_keys(payload, required=set(cls._FIELDS))
        reject_unknown_keys(payload, allowed=set(cls._FIELDS))
        if payload.get("schema_id") != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")
        if payload.get("schema_version_hash") != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
        validate_hex_64(payload, "request_id")
        validate_hex_64(payload, "runtime_registry_hash")
        _require_exact_enum(payload, "mode", {MODE_OFFLINE_PROOF, MODE_LIVE_REQUESTED})
        if payload["mode"] != MODE_OFFLINE_PROOF:
            raise SchemaValidationError("LIVE_REQUESTED not authorized by offline microfix (fail-closed)")
        if payload.get("provider_id") != "openai":
            raise SchemaValidationError("only the frozen openai provider is authorized (fail-closed)")
        if payload.get("adapter_id") != "council.openai.live_semantic.v1":
            raise SchemaValidationError("semantic adapter binding mismatch (fail-closed)")
        if payload.get("request_type") != "analysis":
            raise SchemaValidationError("request_type must be analysis (fail-closed)")
        validate_short_string(payload, "model", max_len=128)
        validate_short_string(payload, "instruction", max_len=2048)
        if not payload["model"].strip() or not payload["instruction"].strip():
            raise SchemaValidationError("model and instruction must be non-empty (fail-closed)")
        if len(payload["instruction"].encode("utf-8")) > 2048:
            raise SchemaValidationError("instruction exceeds byte ceiling (fail-closed)")
        subject = require_dict(payload.get("subject"), name="SemanticCouncilRequest.subject")
        require_keys(subject, required={"schema_id", "claim", "evidence"})
        reject_unknown_keys(subject, allowed={"schema_id", "claim", "evidence"})
        if subject.get("schema_id") != "kt.semantic_subject.v1":
            raise SchemaValidationError("semantic subject schema mismatch (fail-closed)")
        validate_short_string(subject, "claim", max_len=1024)
        validate_short_string(subject, "evidence", max_len=2048)
        if not subject["claim"].strip() or not subject["evidence"].strip():
            raise SchemaValidationError("semantic subject claim/evidence must be non-empty (fail-closed)")
        enforce_max_canonical_json_bytes(subject, max_bytes=MAX_SEMANTIC_SUBJECT_BYTES)
        validate_hex_64(payload, "subject_hash")
        if payload["subject_hash"] != sha256_json(subject):
            raise SchemaValidationError("semantic subject hash mismatch (fail-closed)")
        validate_hex_64(payload, "nonce")
        _require_int(payload, "max_output_tokens", low=1, high=512)
        _require_int(payload, "timeout_ms", low=1, high=20_000)
        _require_bool(payload, "probe_enabled")
        validate_bounded_json_value(payload, max_depth=3, max_string_len=2048, max_list_len=4)
        enforce_max_canonical_json_bytes(payload, max_bytes=12288)
        if payload["request_id"] != cls.compute_request_id(payload):
            raise SchemaValidationError("request_id mismatch (fail-closed)")

    @classmethod
    def compute_request_id(cls, payload: Dict[str, Any]) -> str:
        # probe_enabled is deliberately excluded: observation cannot alter functional identity.
        return sha256_json(
            {
                "schema_id": cls.SCHEMA_ID,
                "schema_version_hash": cls.SCHEMA_VERSION_HASH,
                "runtime_registry_hash": payload.get("runtime_registry_hash"),
                "mode": payload.get("mode"),
                "provider_id": payload.get("provider_id"),
                "adapter_id": payload.get("adapter_id"),
                "request_type": payload.get("request_type"),
                "model": payload.get("model"),
                "instruction": payload.get("instruction"),
                "subject": payload.get("subject"),
                "subject_hash": payload.get("subject_hash"),
                "nonce": payload.get("nonce"),
                "max_output_tokens": payload.get("max_output_tokens"),
                "timeout_ms": payload.get("timeout_ms"),
            }
        )

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SemanticCouncilRequestSchema":
        cls.validate(payload)
        return cls(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


@dataclass(frozen=True)
class TypedProviderMessageSchema:
    SCHEMA_ID = "provider.typed_message.v1"
    SCHEMA_VERSION = "1.0"
    _FIELDS = (
        "schema_id",
        "schema_version_hash",
        "request_id",
        "provider_id",
        "model",
        "role",
        "finish_reason",
        "content",
        "content_hash",
        "raw_response_hash",
        "raw_response_bytes",
        "provider_response_id_hash",
        "usage",
        "message_hash",
    )
    SCHEMA_VERSION_HASH = _canonical_spec_hash(
        SCHEMA_ID,
        SCHEMA_VERSION,
        _FIELDS,
        {
            "role": "assistant",
            "finish_reason": "stop",
            "max_content_bytes": MAX_SEMANTIC_CONTENT_BYTES,
            "max_raw_response_bytes": MAX_PROVIDER_RESPONSE_BYTES,
        },
    )
    data: Dict[str, Any]

    @classmethod
    def compute_message_hash(cls, payload: Dict[str, Any]) -> str:
        return sha256_json({key: payload.get(key) for key in cls._FIELDS if key != "message_hash"})

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="TypedProviderMessage")
        require_keys(payload, required=set(cls._FIELDS))
        reject_unknown_keys(payload, allowed=set(cls._FIELDS))
        if payload.get("schema_id") != cls.SCHEMA_ID or payload.get("schema_version_hash") != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("typed message schema binding mismatch (fail-closed)")
        for field in ("request_id", "content_hash", "raw_response_hash", "provider_response_id_hash", "message_hash"):
            validate_hex_64(payload, field)
        if payload.get("provider_id") != "openai":
            raise SchemaValidationError("typed message provider mismatch (fail-closed)")
        validate_short_string(payload, "model", max_len=128)
        if payload.get("role") != "assistant" or payload.get("finish_reason") != "stop":
            raise SchemaValidationError("typed message role/finish_reason invalid (fail-closed)")
        content = payload.get("content")
        if not isinstance(content, str) or not content or len(content.encode("utf-8")) > MAX_SEMANTIC_CONTENT_BYTES:
            raise SchemaValidationError("typed message content invalid or oversized (fail-closed)")
        if _sha256_text(content) != payload["content_hash"]:
            raise SchemaValidationError("typed message content hash mismatch (fail-closed)")
        _require_int(payload, "raw_response_bytes", low=1, high=MAX_PROVIDER_RESPONSE_BYTES)
        usage = require_dict(payload.get("usage"), name="TypedProviderMessage.usage")
        require_keys(usage, required={"prompt_tokens", "completion_tokens", "total_tokens"})
        reject_unknown_keys(usage, allowed={"prompt_tokens", "completion_tokens", "total_tokens"})
        for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
            _require_int(usage, field, low=0, high=1_000_000)
        if usage["prompt_tokens"] + usage["completion_tokens"] != usage["total_tokens"]:
            raise SchemaValidationError("usage totals mismatch (fail-closed)")
        if payload["message_hash"] != cls.compute_message_hash(payload):
            raise SchemaValidationError("typed message hash mismatch (fail-closed)")
        enforce_max_canonical_json_bytes(payload, max_bytes=MAX_PROVIDER_RESPONSE_BYTES + 8192)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "TypedProviderMessageSchema":
        cls.validate(payload)
        return cls(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


@dataclass(frozen=True)
class AdmittedMeaningSchema:
    SCHEMA_ID = "council.admitted_meaning.v1"
    SCHEMA_VERSION = "1.0"
    PARSER_ID = "kt.strict.semantic_json.v1"
    _FIELDS = (
        "schema_id",
        "schema_version_hash",
        "parser_id",
        "parser_hash",
        "request_id",
        "message_hash",
        "content_hash",
        "subject_hash",
        "nonce",
        "decision",
        "reason_code",
        "meaning_hash",
        "decision_hash",
    )
    SCHEMA_VERSION_HASH = _canonical_spec_hash(
        SCHEMA_ID,
        SCHEMA_VERSION,
        _FIELDS,
        {"decision": sorted(SEMANTIC_DECISIONS), "reason_code": sorted(SEMANTIC_REASON_CODES)},
    )
    PARSER_HASH = sha256_json(
        {
            "parser_id": PARSER_ID,
            "input_schema": "kt.semantic_meaning.v1",
            "required_fields": ["schema_id", "decision", "reason_code", "subject_hash", "nonce"],
            "unknown_fields": "REJECT",
            "coercion": "REJECT",
            "code_fences": "REJECT",
            "whitespace": "RFC8259_JSON_WHITESPACE_ONLY",
            "duplicate_keys": "REJECT_AT_ALL_OBJECT_DEPTHS",
            "nonfinite_constants": "REJECT",
            "top_level": "EXACTLY_ONE_OBJECT",
            "trailing_content": "REJECT",
            "decision_reason_pairs": [["FAIL", "REJECT"], ["PASS", "ACCEPT"]],
        }
    )
    data: Dict[str, Any]

    @classmethod
    def compute_meaning_hash(cls, payload: Dict[str, Any]) -> str:
        return sha256_json(
            {
                "schema_id": "kt.semantic_meaning.v1",
                "decision": payload.get("decision"),
                "reason_code": payload.get("reason_code"),
                "subject_hash": payload.get("subject_hash"),
                "nonce": payload.get("nonce"),
            }
        )

    @classmethod
    def compute_decision_hash(cls, payload: Dict[str, Any]) -> str:
        return sha256_json(
            {
                "decision": payload.get("decision"),
                "reason_code": payload.get("reason_code"),
                "subject_hash": payload.get("subject_hash"),
                "nonce": payload.get("nonce"),
            }
        )

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="AdmittedMeaning")
        require_keys(payload, required=set(cls._FIELDS))
        reject_unknown_keys(payload, allowed=set(cls._FIELDS))
        if payload.get("schema_id") != cls.SCHEMA_ID or payload.get("schema_version_hash") != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("admitted meaning schema binding mismatch (fail-closed)")
        if payload.get("parser_id") != cls.PARSER_ID or payload.get("parser_hash") != cls.PARSER_HASH:
            raise SchemaValidationError("semantic parser binding mismatch (fail-closed)")
        for field in (
            "parser_hash",
            "request_id",
            "message_hash",
            "content_hash",
            "subject_hash",
            "nonce",
            "meaning_hash",
            "decision_hash",
        ):
            validate_hex_64(payload, field)
        _require_exact_enum(payload, "decision", SEMANTIC_DECISIONS)
        _require_exact_enum(payload, "reason_code", SEMANTIC_REASON_CODES)
        if (payload["decision"], payload["reason_code"]) not in {("PASS", "ACCEPT"), ("FAIL", "REJECT")}:
            raise SchemaValidationError("decision/reason_code pairing invalid (fail-closed)")
        if payload["meaning_hash"] != cls.compute_meaning_hash(payload):
            raise SchemaValidationError("meaning hash mismatch (fail-closed)")
        if payload["decision_hash"] != cls.compute_decision_hash(payload):
            raise SchemaValidationError("decision hash mismatch (fail-closed)")

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "AdmittedMeaningSchema":
        cls.validate(payload)
        return cls(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


__all__ = [
    "AdmittedMeaningSchema",
    "MAX_PROVIDER_RESPONSE_BYTES",
    "MAX_SEMANTIC_CONTENT_BYTES",
    "MAX_SEMANTIC_SUBJECT_BYTES",
    "MODE_LIVE_REQUESTED",
    "MODE_OFFLINE_PROOF",
    "SemanticCouncilRequestSchema",
    "SemanticVerticalError",
    "TypedProviderMessageSchema",
]
