from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def sha256_json(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TokenBoundaryRecord:
    raw_generated_token_ids: list[int]
    authoritative_preserved_token_ids: list[int]
    delivered_visible_text: str
    boundary_generated_token_index_exclusive: int
    trigger_token_start_index: int | None
    raw_generated_token_count: int
    preserved_generated_token_count: int
    dropped_trigger_token_count: int
    raw_token_sha256: str
    preserved_token_sha256: str
    raw_text_sha256: str
    visible_text_sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "raw_generated_token_ids": self.raw_generated_token_ids,
            "authoritative_preserved_token_ids": self.authoritative_preserved_token_ids,
            "delivered_visible_text": self.delivered_visible_text,
            "boundary_generated_token_index_exclusive": self.boundary_generated_token_index_exclusive,
            "trigger_token_start_index": self.trigger_token_start_index,
            "raw_generated_token_count": self.raw_generated_token_count,
            "preserved_generated_token_count": self.preserved_generated_token_count,
            "dropped_trigger_token_count": self.dropped_trigger_token_count,
            "raw_token_sha256": self.raw_token_sha256,
            "preserved_token_sha256": self.preserved_token_sha256,
            "raw_text_sha256": self.raw_text_sha256,
            "visible_text_sha256": self.visible_text_sha256,
        }


def build_token_boundary_record(
    *,
    tokenizer,
    raw_generated_token_ids: list[int],
    raw_generated_text: str,
    boundary_generated_token_index_exclusive: int | None,
    trigger_token_start_index: int | None,
    skip_special_tokens: bool = True,
) -> TokenBoundaryRecord:
    raw_count = len(raw_generated_token_ids)
    boundary = raw_count if boundary_generated_token_index_exclusive is None else int(boundary_generated_token_index_exclusive)
    boundary = max(0, min(boundary, raw_count))
    preserved = list(raw_generated_token_ids[:boundary])
    visible = tokenizer.decode(preserved, skip_special_tokens=skip_special_tokens)
    return TokenBoundaryRecord(
        raw_generated_token_ids=list(raw_generated_token_ids),
        authoritative_preserved_token_ids=preserved,
        delivered_visible_text=visible,
        boundary_generated_token_index_exclusive=boundary,
        trigger_token_start_index=trigger_token_start_index,
        raw_generated_token_count=raw_count,
        preserved_generated_token_count=len(preserved),
        dropped_trigger_token_count=raw_count - len(preserved),
        raw_token_sha256=sha256_json(list(raw_generated_token_ids)),
        preserved_token_sha256=sha256_json(preserved),
        raw_text_sha256=sha256_text(raw_generated_text),
        visible_text_sha256=sha256_text(visible),
    )


def validate_token_boundary_record(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    raw = list(record.get("raw_generated_token_ids", []))
    preserved = list(record.get("authoritative_preserved_token_ids", []))
    boundary = int(record.get("boundary_generated_token_index_exclusive", -1))
    if preserved != raw[:boundary]:
        errors.append("preserved_ids_not_original_prefix")
    if int(record.get("preserved_generated_token_count", -1)) != len(preserved):
        errors.append("preserved_count_mismatch")
    if int(record.get("dropped_trigger_token_count", -1)) != len(raw) - len(preserved):
        errors.append("dropped_trigger_count_mismatch")
    if record.get("raw_token_sha256") != sha256_json(raw):
        errors.append("raw_token_hash_mismatch")
    if record.get("preserved_token_sha256") != sha256_json(preserved):
        errors.append("preserved_token_hash_mismatch")
    return errors
