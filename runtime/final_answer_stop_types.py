from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional


class StopState(str, Enum):
    SEARCH_MARKER = "SEARCH_MARKER"
    WAIT_FOR_ANSWER_CONTENT = "WAIT_FOR_ANSWER_CONTENT"
    IN_FINAL_ANSWER_LINE = "IN_FINAL_ANSWER_LINE"
    COMPLETE_STOP = "COMPLETE_STOP"
    NO_FINAL_MARKER = "NO_FINAL_MARKER"
    EMPTY_FINAL_ANSWER = "EMPTY_FINAL_ANSWER"
    ANSWER_TAIL_LIMIT = "ANSWER_TAIL_LIMIT"
    REPEATED_MARKER_BEFORE_CLOSE = "REPEATED_MARKER_BEFORE_CLOSE"
    MAX_NEW_TOKENS = "MAX_NEW_TOKENS"
    EOS_BEFORE_MARKER = "EOS_BEFORE_MARKER"


class StopReason(str, Enum):
    CONTINUE = "CONTINUE"
    FINAL_ANSWER_LINE_COMPLETE = "FINAL_ANSWER_LINE_COMPLETE"
    EOS = "EOS"
    NO_FINAL_MARKER = "NO_FINAL_MARKER"
    EMPTY_FINAL_ANSWER = "EMPTY_FINAL_ANSWER"
    ANSWER_TAIL_LIMIT = "ANSWER_TAIL_LIMIT"
    REPEATED_MARKER_BEFORE_CLOSE = "REPEATED_MARKER_BEFORE_CLOSE"
    MAX_NEW_TOKENS = "MAX_NEW_TOKENS"
    EOS_BEFORE_MARKER = "EOS_BEFORE_MARKER"


@dataclass(frozen=True)
class StopDecision:
    should_stop: bool
    state: StopState
    reason: StopReason
    marker_start_char: Optional[int] = None
    marker_end_char: Optional[int] = None
    answer_content_start_char: Optional[int] = None
    line_close_end_char: Optional[int] = None
    preserved_text: Optional[str] = None

    def to_json(self) -> dict:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["reason"] = self.reason.value
        return payload
