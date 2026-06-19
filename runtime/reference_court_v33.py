from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ReferenceCourtFinding:
    semantic_boundary_type: str
    visible_text: str
    lawful: bool
    correction_present: bool
    unsafe_reason: str | None
    raw_generated_text_hash: str
    delivered_visible_text_hash: str

    def to_json(self) -> dict:
        return asdict(self)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def adjudicate_reference_court_v33(
    raw_generated_text: str,
    *,
    ended_on_eos: bool = False,
    ended_on_max_new_tokens: bool = False,
    marker: str = "FINAL_ANSWER:",
) -> ReferenceCourtFinding:
    """Independent slow court. Deliberately imports no runtime FSM helpers."""

    raw_hash = _sha(raw_generated_text)
    marker_match = re.search(r"(?m)^[ \t]*" + re.escape(marker), raw_generated_text)
    if marker_match is None:
        return ReferenceCourtFinding("NO_VALID_BOUNDARY", raw_generated_text, False, False, "NO_LINE_ANCHORED_MARKER", raw_hash, _sha(raw_generated_text))
    tail = raw_generated_text[marker_match.end() :]
    payload_start = re.search(r"\S", tail)
    if payload_start is None:
        return ReferenceCourtFinding("MALFORMED_FINAL", raw_generated_text, False, False, "EMPTY_PAYLOAD", raw_hash, _sha(raw_generated_text))
    answer_start = marker_match.end() + payload_start.start()
    rest = raw_generated_text[answer_start:]
    newline = re.search(r"\r\n|\n|\r", rest)
    second_marker = rest.find(marker)
    correction = bool(re.search(r"\b(correction|actually|instead|retract|wrong|wait)\b", rest, re.I))
    if second_marker >= 0 and (newline is None or second_marker < newline.start()):
        visible = raw_generated_text[: answer_start + second_marker].rstrip()
        lawful = bool(rest[:second_marker].strip()) and not correction
        return ReferenceCourtFinding("SECOND_MARKER_CLOSE", visible, lawful, correction, None if lawful else "EMPTY_OR_CORRECTIVE_FIRST_SEGMENT", raw_hash, _sha(visible))
    if newline is not None:
        visible = raw_generated_text[: answer_start + newline.end()]
        return ReferenceCourtFinding("FINAL_LINE_CLOSE", visible, True, correction, None, raw_hash, _sha(visible))
    if ended_on_eos and not ended_on_max_new_tokens:
        visible = raw_generated_text.rstrip()
        return ReferenceCourtFinding("SAFE_EOS_CLOSURE", visible, True, correction, None, raw_hash, _sha(visible))
    if ended_on_max_new_tokens:
        return ReferenceCourtFinding("NO_VALID_BOUNDARY", raw_generated_text, False, correction, "MAX_NEW_TOKENS_NOT_EOS", raw_hash, _sha(raw_generated_text))
    return ReferenceCourtFinding("NO_VALID_BOUNDARY", raw_generated_text, False, correction, "NO_CLOSE", raw_hash, _sha(raw_generated_text))
