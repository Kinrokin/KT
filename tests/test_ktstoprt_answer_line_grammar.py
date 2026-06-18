from __future__ import annotations

from runtime.final_answer_stop import evaluate_generated_text


def test_answer_line_preserves_units_currency_percent_and_decimal() -> None:
    text = "Steps\nFINAL_ANSWER: -$1,234.50 dollars, 20%\nDo not keep me"
    decision = evaluate_generated_text(text)
    assert decision.should_stop is True
    assert decision.preserved_text == "Steps\nFINAL_ANSWER: -$1,234.50 dollars, 20%\n"
