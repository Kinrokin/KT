from __future__ import annotations

from runtime.final_answer_stop import evaluate_generated_text


def test_marker_across_token_boundary_equivalent_text_is_detected() -> None:
    text = "Work\nFINAL_" + "ANSWER: 42\nExtra"
    decision = evaluate_generated_text(text)
    assert decision.should_stop is True
    assert decision.reason == "FINAL_ANSWER_LINE_COMPLETE"
    assert decision.preserved_text == "Work\nFINAL_ANSWER: 42\n"
