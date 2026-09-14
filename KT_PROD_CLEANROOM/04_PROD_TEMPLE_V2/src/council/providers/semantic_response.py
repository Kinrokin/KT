from __future__ import annotations

import hashlib
import json
from typing import Dict

from schemas.base_schema import SchemaValidationError
from schemas.semantic_vertical_schemas import (
    AdmittedMeaningSchema,
    MAX_PROVIDER_RESPONSE_BYTES,
    MAX_SEMANTIC_CONTENT_BYTES,
    SEMANTIC_DECISIONS,
    SEMANTIC_REASON_CODES,
    SemanticVerticalError,
    TypedProviderMessageSchema,
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> Dict[str, object]:
    value: Dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SemanticVerticalError("duplicate JSON object key forbidden (fail-closed)")
        value[key] = item
    return value


def _reject_nonfinite_constant(value: str) -> object:
    raise SemanticVerticalError(f"non-finite JSON constant {value} forbidden (fail-closed)")


def _strict_json_loads(text: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite_constant,
        )
    except SemanticVerticalError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("strict JSON parse failed (fail-closed)") from exc


def typed_message_from_provider_response(
    *,
    raw: bytes,
    expected_model: str,
    provider_id: str,
    request_id: str,
    provider_request_id: str | None = None,
) -> TypedProviderMessageSchema:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
        raise SemanticVerticalError("provider response bytes missing or oversized (fail-closed)")
    try:
        text = raw.decode("utf-8", errors="strict")
        payload = _strict_json_loads(text)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("provider response must be strict UTF-8 JSON (fail-closed)") from exc
    if not isinstance(payload, dict):
        raise SemanticVerticalError("provider response must be an object (fail-closed)")
    required_top = {"id", "model", "choices", "usage"}
    if not required_top.issubset(payload):
        raise SemanticVerticalError("provider response missing required semantic fields (fail-closed)")
    response_id = payload.get("id")
    if not isinstance(response_id, str) or not response_id.strip() or len(response_id) > 128:
        raise SemanticVerticalError("provider response id invalid (fail-closed)")
    if provider_request_id is not None and response_id != provider_request_id:
        raise SemanticVerticalError("provider request id mismatch (fail-closed)")
    model = payload.get("model")
    if not isinstance(model, str) or model != expected_model:
        raise SemanticVerticalError("provider model mismatch (fail-closed)")
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise SemanticVerticalError("exactly one provider choice is required (fail-closed)")
    choice = choices[0]
    if not isinstance(choice, dict):
        raise SemanticVerticalError("provider choice must be an object (fail-closed)")
    if set(choice) - {"index", "message", "finish_reason", "logprobs"}:
        raise SemanticVerticalError("provider choice contains unknown fields (fail-closed)")
    if choice.get("index") != 0 or choice.get("finish_reason") != "stop":
        raise SemanticVerticalError("provider choice index/finish_reason invalid (fail-closed)")
    message = choice.get("message")
    if not isinstance(message, dict):
        raise SemanticVerticalError("provider message missing (fail-closed)")
    if set(message) - {"role", "content", "refusal"}:
        raise SemanticVerticalError("provider message contains unknown fields (fail-closed)")
    refusal = message.get("refusal")
    if refusal is not None and refusal != "":
        raise SemanticVerticalError("provider refusal cannot be admitted (fail-closed)")
    if message.get("role") != "assistant":
        raise SemanticVerticalError("provider role must be assistant (fail-closed)")
    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise SemanticVerticalError("provider content must be non-empty string (fail-closed)")
    if content.lstrip().startswith("```"):
        raise SemanticVerticalError("provider content fences forbidden (fail-closed)")
    if len(content.encode("utf-8")) > MAX_SEMANTIC_CONTENT_BYTES:
        raise SemanticVerticalError("provider content exceeds semantic ceiling (fail-closed)")
    usage_raw = payload.get("usage")
    if not isinstance(usage_raw, dict):
        raise SemanticVerticalError("provider usage missing (fail-closed)")
    usage: Dict[str, int] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = usage_raw.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise SemanticVerticalError("provider usage invalid (fail-closed)")
        usage[key] = value
    if usage["prompt_tokens"] + usage["completion_tokens"] != usage["total_tokens"]:
        raise SemanticVerticalError("provider usage totals mismatch (fail-closed)")

    typed: Dict[str, Any] = {
        "schema_id": TypedProviderMessageSchema.SCHEMA_ID,
        "schema_version_hash": TypedProviderMessageSchema.SCHEMA_VERSION_HASH,
        "request_id": request_id,
        "provider_id": provider_id,
        "model": model,
        "role": "assistant",
        "finish_reason": "stop",
        "content": content,
        "content_hash": _sha256_text(content),
        "raw_response_hash": _sha256_bytes(raw),
        "raw_response_bytes": len(raw),
        "provider_response_id_hash": _sha256_text(response_id),
        "usage": usage,
        "message_hash": "",
    }
    typed["message_hash"] = TypedProviderMessageSchema.compute_message_hash(typed)
    try:
        return TypedProviderMessageSchema.from_dict(typed)
    except SchemaValidationError as exc:
        raise SemanticVerticalError(f"typed provider message invalid (fail-closed): {exc}") from exc


def admit_typed_message(
    *,
    message: TypedProviderMessageSchema,
    expected_subject_hash: str,
    expected_nonce: str,
) -> AdmittedMeaningSchema:
    msg = message.to_dict()
    content = msg["content"]
    try:
        candidate = _strict_json_loads(content)
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, SemanticVerticalError):
            raise
        raise SemanticVerticalError("semantic content is not strict JSON (fail-closed)") from exc
    if not isinstance(candidate, dict):
        raise SemanticVerticalError("semantic content must be an object (fail-closed)")
    required = {"schema_id", "decision", "reason_code", "subject_hash", "nonce"}
    if set(candidate) != required:
        raise SemanticVerticalError("semantic content keys mismatch (fail-closed)")
    if candidate.get("schema_id") != "kt.semantic_meaning.v1":
        raise SemanticVerticalError("semantic meaning schema mismatch (fail-closed)")
    if candidate.get("decision") not in SEMANTIC_DECISIONS:
        raise SemanticVerticalError("semantic decision invalid (fail-closed)")
    if candidate.get("reason_code") not in SEMANTIC_REASON_CODES:
        raise SemanticVerticalError("semantic reason code invalid (fail-closed)")
    if candidate.get("subject_hash") != expected_subject_hash:
        raise SemanticVerticalError("semantic subject binding mismatch (fail-closed)")
    if candidate.get("nonce") != expected_nonce:
        raise SemanticVerticalError("semantic nonce binding mismatch (fail-closed)")

    admitted: Dict[str, Any] = {
        "schema_id": AdmittedMeaningSchema.SCHEMA_ID,
        "schema_version_hash": AdmittedMeaningSchema.SCHEMA_VERSION_HASH,
        "parser_id": AdmittedMeaningSchema.PARSER_ID,
        "parser_hash": AdmittedMeaningSchema.PARSER_HASH,
        "request_id": msg["request_id"],
        "message_hash": msg["message_hash"],
        "content_hash": msg["content_hash"],
        "subject_hash": candidate["subject_hash"],
        "nonce": candidate["nonce"],
        "decision": candidate["decision"],
        "reason_code": candidate["reason_code"],
        "meaning_hash": "",
        "decision_hash": "",
    }
    admitted["meaning_hash"] = AdmittedMeaningSchema.compute_meaning_hash(admitted)
    admitted["decision_hash"] = AdmittedMeaningSchema.compute_decision_hash(admitted)
    try:
        return AdmittedMeaningSchema.from_dict(admitted)
    except SchemaValidationError as exc:
        raise SemanticVerticalError(f"admitted meaning invalid (fail-closed): {exc}") from exc


__all__ = ["admit_typed_message", "typed_message_from_provider_response"]
