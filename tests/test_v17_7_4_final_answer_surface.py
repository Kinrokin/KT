from __future__ import annotations

from scripts.extract_v17_7_4_final_answer_surface import extract_final_answer_surface
from scripts.score_v17_7_4_final_answer_surface import score_final_answer_surface


def test_final_answer_extractor_uses_last_final_marker_not_early_scratch_number() -> None:
    output = "Scratch: I first guessed 7.\nThen compute 2 * 3 = 6.\nFinal: 6"
    assert extract_final_answer_surface(output, "numeric_final_answer") == "6"
    result = score_final_answer_surface(output, "6", "numeric_final_answer")
    assert result["correct"] is True
    assert result["early_scratch_number_used"] is False


def test_final_answer_extractor_handles_mcq_letter_surface() -> None:
    output = "Reasoning says option C is best.\nFinal: C"
    assert extract_final_answer_surface(output, "multiple_choice_letter") == "C"


def test_final_answer_scoring_does_not_need_expected_answer_in_prompt() -> None:
    result = score_final_answer_surface("Final: Paris", "Paris", "short_answer")
    assert result["correct"] is True
    assert result["expected_answer_visible_to_model"] is False
