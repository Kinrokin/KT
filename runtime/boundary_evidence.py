from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


def sha256_json(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PhysicalTokenLedger:
    prompt_token_ids: list[int]
    raw_generated_token_ids: list[int]
    physical_stopped_generated_token_ids: list[int]
    semantic_visible_text: str
    canonical_extracted_answer: str
    boundary_char_index: int | None
    boundary_token_index_floor: int | None
    boundary_token_index_ceil: int | None
    trigger_token_start_index: int | None
    trigger_char_offset_within_token_if_any: int | None
    generator_termination_source: str
    prompt_token_count: int
    raw_generated_token_count: int
    physical_stopped_generated_token_count: int
    semantic_visible_token_count: int
    raw_token_sha256: str
    prefix_token_sha256: str
    visible_text_sha256: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def build_physical_token_ledger(
    *,
    prompt_token_ids: list[int],
    raw_generated_token_ids: list[int],
    semantic_visible_text: str,
    canonical_extracted_answer: str,
    generator_termination_source: str,
    boundary_token_index_floor: int | None,
    boundary_token_index_ceil: int | None,
    boundary_char_index: int | None = None,
    trigger_token_start_index: int | None = None,
    trigger_char_offset_within_token_if_any: int | None = None,
    semantic_visible_token_ids: list[int] | None = None,
) -> PhysicalTokenLedger:
    """Separate physical generation cost from visible output hygiene.

    `raw_generated_token_ids` is the compute denominator. The stopped prefix is
    the physical prefix the runtime would keep for deterministic replay, while
    `semantic_visible_text` may remove trigger text that was already generated.
    """

    raw_count = len(raw_generated_token_ids)
    if boundary_token_index_ceil is None:
        stop_index = raw_count
    else:
        stop_index = max(0, min(raw_count, int(boundary_token_index_ceil)))
    stopped = list(raw_generated_token_ids[:stop_index])
    visible_ids = semantic_visible_token_ids if semantic_visible_token_ids is not None else stopped
    return PhysicalTokenLedger(
        prompt_token_ids=list(prompt_token_ids),
        raw_generated_token_ids=list(raw_generated_token_ids),
        physical_stopped_generated_token_ids=stopped,
        semantic_visible_text=semantic_visible_text,
        canonical_extracted_answer=canonical_extracted_answer,
        boundary_char_index=boundary_char_index,
        boundary_token_index_floor=boundary_token_index_floor,
        boundary_token_index_ceil=boundary_token_index_ceil,
        trigger_token_start_index=trigger_token_start_index,
        trigger_char_offset_within_token_if_any=trigger_char_offset_within_token_if_any,
        generator_termination_source=generator_termination_source,
        prompt_token_count=len(prompt_token_ids),
        raw_generated_token_count=raw_count,
        physical_stopped_generated_token_count=len(stopped),
        semantic_visible_token_count=len(visible_ids),
        raw_token_sha256=sha256_json(list(raw_generated_token_ids)),
        prefix_token_sha256=sha256_json(stopped),
        visible_text_sha256=sha256_text(semantic_visible_text),
    )


def validate_physical_token_ledger(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    prompt = list(record.get("prompt_token_ids", []))
    raw = list(record.get("raw_generated_token_ids", []))
    prefix = list(record.get("physical_stopped_generated_token_ids", []))
    ceil = record.get("boundary_token_index_ceil")
    expected_stop = len(raw) if ceil is None else max(0, min(len(raw), int(ceil)))
    if prefix != raw[:expected_stop]:
        errors.append("physical_stopped_ids_not_raw_prefix")
    if record.get("prompt_token_count") != len(prompt):
        errors.append("prompt_token_count_mismatch")
    if record.get("raw_generated_token_count") != len(raw):
        errors.append("raw_generated_token_count_mismatch")
    if record.get("physical_stopped_generated_token_count") != len(prefix):
        errors.append("physical_stopped_token_count_mismatch")
    if record.get("raw_token_sha256") != sha256_json(raw):
        errors.append("raw_token_hash_mismatch")
    if record.get("prefix_token_sha256") != sha256_json(prefix):
        errors.append("prefix_token_hash_mismatch")
    if record.get("visible_text_sha256") != sha256_text(str(record.get("semantic_visible_text", ""))):
        errors.append("visible_text_hash_mismatch")
    return errors
