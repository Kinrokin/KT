from __future__ import annotations

from scripts import ktbud100_common as bud


def test_final_marker_detector_covers_required_forms() -> None:
    assert bud.final_marker_detected("#### 42")
    assert bud.final_marker_detected("Final answer: 42")
    assert bud.final_marker_detected("Answer: 42")
    assert not bud.final_marker_detected("The result is unknown")


def test_extract_numeric_answer_prefers_final_marker() -> None:
    assert bud.extract_numeric_answer("work 1 2 3\nFinal answer: 1,234") == "1234"
