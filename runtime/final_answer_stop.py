from __future__ import annotations

import re
from typing import Optional

from runtime.final_answer_stop_types import StopDecision, StopReason, StopState


def evaluate_generated_text(
    generated_text: str,
    *,
    marker: str = "FINAL_ANSWER:",
    eos: bool = False,
    max_answer_tail_chars: int = 160,
) -> StopDecision:
    """Evaluate generated text only. Prompt text must be sliced away by caller."""
    marker_start = generated_text.find(marker)
    if marker_start < 0:
        if eos:
            return StopDecision(True, StopState.EOS_BEFORE_MARKER, StopReason.EOS_BEFORE_MARKER)
        return StopDecision(False, StopState.SEARCH_MARKER, StopReason.CONTINUE)

    marker_end = marker_start + len(marker)
    tail = generated_text[marker_end:]
    non_ws = re.search(r"\S", tail)
    if not non_ws:
        if eos:
            return StopDecision(True, StopState.EMPTY_FINAL_ANSWER, StopReason.EMPTY_FINAL_ANSWER, marker_start, marker_end)
        return StopDecision(False, StopState.WAIT_FOR_ANSWER_CONTENT, StopReason.CONTINUE, marker_start, marker_end)

    answer_start = marker_end + non_ws.start()
    after_answer_start = generated_text[answer_start:]
    newline_match = re.search(r"\r\n|\n|\r", after_answer_start)
    repeated_marker = after_answer_start.find(marker)
    if repeated_marker >= 0 and (newline_match is None or repeated_marker < newline_match.start()):
        close = answer_start + repeated_marker
        return StopDecision(
            True,
            StopState.REPEATED_MARKER_BEFORE_CLOSE,
            StopReason.REPEATED_MARKER_BEFORE_CLOSE,
            marker_start,
            marker_end,
            answer_start,
            close,
            generated_text[:close].rstrip(),
        )

    if newline_match is not None:
        close = answer_start + newline_match.end()
        return StopDecision(
            True,
            StopState.COMPLETE_STOP,
            StopReason.FINAL_ANSWER_LINE_COMPLETE,
            marker_start,
            marker_end,
            answer_start,
            close,
            generated_text[:close],
        )

    if eos:
        return StopDecision(
            True,
            StopState.COMPLETE_STOP,
            StopReason.EOS,
            marker_start,
            marker_end,
            answer_start,
            len(generated_text),
            generated_text.rstrip(),
        )

    if len(after_answer_start) > max_answer_tail_chars:
        close = answer_start + max_answer_tail_chars
        return StopDecision(
            True,
            StopState.ANSWER_TAIL_LIMIT,
            StopReason.ANSWER_TAIL_LIMIT,
            marker_start,
            marker_end,
            answer_start,
            close,
            generated_text[:close].rstrip(),
        )

    return StopDecision(
        False,
        StopState.IN_FINAL_ANSWER_LINE,
        StopReason.CONTINUE,
        marker_start,
        marker_end,
        answer_start,
    )


class GeneratedOnlyBatchOneAdapter:
    def __init__(self, tokenizer, prompt_token_count: int, eos_token_id: Optional[int] = None):
        self.tokenizer = tokenizer
        self.prompt_token_count = prompt_token_count
        self.eos_token_id = eos_token_id
        self.last_decision: Optional[StopDecision] = None

    def evaluate_ids(self, full_input_ids) -> StopDecision:
        ids = full_input_ids.tolist() if hasattr(full_input_ids, "tolist") else list(full_input_ids)
        if len(ids) < self.prompt_token_count:
            raise ValueError("full_input_ids shorter than prompt boundary")
        generated_ids = ids[self.prompt_token_count :]
        generated_text = self.tokenizer.decode(generated_ids, skip_special_tokens=False)
        eos = bool(generated_ids and self.eos_token_id is not None and generated_ids[-1] == self.eos_token_id)
        self.last_decision = evaluate_generated_text(generated_text, eos=eos)
        return self.last_decision


class FirstCompleteFinalAnswerLineStoppingCriteria:
    """Transformers-compatible stopping criteria with generated-token-only slicing."""

    def __init__(self, tokenizer, prompt_token_count: int, eos_token_id: Optional[int] = None):
        self.adapter = GeneratedOnlyBatchOneAdapter(tokenizer, prompt_token_count, eos_token_id)
        self.prompt_token_count = prompt_token_count
        self.last_decision: Optional[StopDecision] = None

    def __call__(self, input_ids, scores=None, **kwargs) -> bool:
        if getattr(input_ids, "shape", [1])[0] != 1:
            raise ValueError("FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP is batch-size-one only")
        row = input_ids[0]
        self.last_decision = self.adapter.evaluate_ids(row)
        return self.last_decision.should_stop
