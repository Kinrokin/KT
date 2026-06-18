from __future__ import annotations

from runtime.final_answer_stop import evaluate_generated_text
from runtime.final_answer_stop_types import StopReason


def test_inline_marker_is_not_counted_as_complete_answer_line() -> None:
    decision = evaluate_generated_text("Reasoning says FINAL_ANSWER: 42 inside a sentence.")
    assert decision.should_stop is False
    assert decision.reason == StopReason.CONTINUE


def test_eos_after_answer_content_has_specific_reason() -> None:
    decision = evaluate_generated_text("FINAL_ANSWER: 42", eos=True)
    assert decision.should_stop is True
    assert decision.reason == StopReason.EOS_AFTER_FINAL_ANSWER_LINE
