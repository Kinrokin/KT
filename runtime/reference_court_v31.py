from __future__ import annotations

import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ReferenceCourtFinding:
    semantic_boundary_type: str
    visible_text: str
    lawful: bool
    correction_present: bool
    unsafe_reason: str | None = None

    def to_json(self) -> dict:
        return asdict(self)


def adjudicate_reference_court_v31(
    raw_generated_text: str,
    *,
    ended_on_eos: bool = False,
    ended_on_max_new_tokens: bool = False,
    marker: str = "FINAL_ANSWER:",
) -> ReferenceCourtFinding:
    """Slow independent STOP300 court.

    This module deliberately does not import runtime.stop_fsm_v31. It is the
    offline reconstruction court for immutable raw text/token evidence.
    """

    marker_match = re.search(r"(?m)^[ \t]*" + re.escape(marker), raw_generated_text)
    if marker_match is None:
        return ReferenceCourtFinding("NO_VALID_BOUNDARY", raw_generated_text, False, False, "NO_LINE_ANCHORED_MARKER")

    tail = raw_generated_text[marker_match.end() :]
    content = re.search(r"\S", tail)
    if content is None:
        return ReferenceCourtFinding("MALFORMED_FINAL", raw_generated_text, False, False, "EMPTY_PAYLOAD")

    answer_start = marker_match.end() + content.start()
    rest = raw_generated_text[answer_start:]
    newline = re.search(r"\r\n|\n|\r", rest)
    second_marker = rest.find(marker)
    correction = bool(re.search(r"\b(correction|actually|instead|retract|wrong)\b", rest, re.I))

    if second_marker >= 0 and (newline is None or second_marker < newline.start()):
        first_segment = rest[:second_marker].rstrip()
        lawful = bool(first_segment) and not correction
        return ReferenceCourtFinding(
            "SECOND_MARKER_CLOSE",
            raw_generated_text[: answer_start + second_marker].rstrip(),
            lawful,
            correction,
            None if lawful else "EMPTY_OR_CORRECTIVE_FIRST_SEGMENT",
        )
    if newline is not None:
        return ReferenceCourtFinding(
            "FINAL_LINE_CLOSE",
            raw_generated_text[: answer_start + newline.end()],
            True,
            correction,
        )
    if ended_on_eos and not ended_on_max_new_tokens:
        return ReferenceCourtFinding(
            "EOS_AFTER_NONEMPTY_FINAL",
            raw_generated_text.rstrip(),
            True,
            correction,
        )
    if ended_on_max_new_tokens:
        return ReferenceCourtFinding("NO_VALID_BOUNDARY", raw_generated_text, False, correction, "MAX_NEW_TOKENS_NOT_EOS")
    return ReferenceCourtFinding("NO_VALID_BOUNDARY", raw_generated_text, False, correction, "NO_CLOSE")
