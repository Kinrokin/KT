from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Optional


FINAL_MARKER = "FINAL_ANSWER:"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_numeric_candidate(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().replace(",", "")
    if text.startswith("$"):
        text = text[1:].strip()
    if not text:
        return None
    return text


def extract_numeric_candidate(text: str) -> Optional[str]:
    fractions = re.findall(r"[-+]?\d[\d,]*\s*/\s*\d[\d,]*", text)
    if fractions:
        return normalize_numeric_candidate(fractions[-1].replace(" ", ""))
    numbers = re.findall(r"[-+]?(?:\$?\d[\d,]*)(?:\.\d+)?(?:[eE][-+]?\d+)?", text)
    if not numbers:
        return None
    return normalize_numeric_candidate(numbers[-1])


def extract_final_answer_lines(raw_output: str, marker: str = FINAL_MARKER) -> list[str]:
    pattern = re.escape(marker) + r"\s*([^\r\n]*)"
    return [match.strip() for match in re.findall(pattern, raw_output)]


def extract_answer(raw_output: str) -> Optional[str]:
    lines = extract_final_answer_lines(raw_output)
    if lines:
        return extract_numeric_candidate(lines[-1])
    numbers = re.findall(r"[-+]?\$?\d[\d,]*(?:\.\d+)?", raw_output)
    return normalize_numeric_candidate(numbers[-1]) if numbers else None


def answer_matches_hash(candidate: Optional[str], expected_answer_hash: str) -> bool:
    if candidate is None:
        return False
    return sha256_text(candidate) == expected_answer_hash


@dataclass(frozen=True)
class SemanticTrailerMetrics:
    final_marker_present: bool
    answer_line_text: str
    answer_suffix_text: str
    semantic_post_final_line_text: str
    semantic_trailer_present: bool
    repeated_final_answer_count: int
    repeated_marker_before_close: bool
    max_new_tokens_hit: bool
    tokens_after_complete_final_line: Optional[int]
    chars_after_complete_final_line: int

    def to_json(self) -> dict:
        return asdict(self)


def compute_semantic_trailer(
    raw_output: str,
    *,
    marker: str = FINAL_MARKER,
    output_tokens_if_available: Optional[int] = None,
    max_new_tokens: int = 512,
) -> SemanticTrailerMetrics:
    marker_index = raw_output.find(marker)
    if marker_index < 0:
        return SemanticTrailerMetrics(
            final_marker_present=False,
            answer_line_text="",
            answer_suffix_text="",
            semantic_post_final_line_text="",
            semantic_trailer_present=False,
            repeated_final_answer_count=0,
            repeated_marker_before_close=False,
            max_new_tokens_hit=output_tokens_if_available == max_new_tokens,
            tokens_after_complete_final_line=None,
            chars_after_complete_final_line=0,
        )

    suffix = raw_output[marker_index:]
    line_match = re.match(r"[^\r\n]*(?:\r\n|\n|\r)", suffix)
    if line_match:
        answer_line = line_match.group(0).rstrip("\r\n")
        answer_suffix = suffix[line_match.end() :]
    else:
        answer_line = suffix
        answer_suffix = ""

    semantic_post = answer_suffix.strip()
    repeated_count = max(0, raw_output.count(marker) - 1)
    return SemanticTrailerMetrics(
        final_marker_present=True,
        answer_line_text=answer_line,
        answer_suffix_text=answer_suffix,
        semantic_post_final_line_text=semantic_post,
        semantic_trailer_present=bool(semantic_post),
        repeated_final_answer_count=repeated_count,
        repeated_marker_before_close=False,
        max_new_tokens_hit=output_tokens_if_available == max_new_tokens,
        tokens_after_complete_final_line=None,
        chars_after_complete_final_line=len(answer_suffix),
    )


def first_complete_final_line(raw_output: str, marker: str = FINAL_MARKER) -> str:
    marker_index = raw_output.find(marker)
    if marker_index < 0:
        return raw_output
    suffix = raw_output[marker_index:]
    line_match = re.match(r"[^\r\n]*(?:\r\n|\n|\r)", suffix)
    if not line_match:
        return raw_output[: marker_index + len(suffix)]
    return raw_output[: marker_index + line_match.end()]


def audit_first_last(raw_output: str, expected_answer_hash: str) -> dict:
    lines = extract_final_answer_lines(raw_output)
    candidates = [extract_numeric_candidate(line) for line in lines]
    matches = [answer_matches_hash(candidate, expected_answer_hash) for candidate in candidates]
    if not candidates:
        classification = "NO_FINAL_MARKER"
    elif (not matches[0]) and any(matches[1:]):
        classification = "FIRST_FINAL_WRONG_LATER_CORRECTED"
    elif matches[0] and any(candidate is not None and candidate != candidates[0] for candidate in candidates[1:]):
        classification = "FIRST_FINAL_CORRECT_LATER_DAMAGED"
    elif len(candidates) == 1:
        classification = "FIRST_FINAL_STABLE"
    elif len({candidate for candidate in candidates if candidate is not None}) <= 1:
        classification = "MULTIPLE_FINAL_SAME"
    else:
        classification = "MULTIPLE_FINAL_CONFLICT"
    return {
        "final_answer_candidates": lines,
        "canonical_numeric_candidates": candidates,
        "candidate_matches_expected_hash": matches,
        "first_final_answer": candidates[0] if candidates else None,
        "last_final_answer": candidates[-1] if candidates else None,
        "first_matches_expected": matches[0] if matches else False,
        "last_matches_expected": matches[-1] if matches else False,
        "classification": classification,
    }
