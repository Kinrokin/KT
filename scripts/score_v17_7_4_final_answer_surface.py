from __future__ import annotations

import re

from scripts.extract_v17_7_4_final_answer_surface import extract_final_answer_surface


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9./+-]+", "", str(value or "").lower())


def score_final_answer_surface(output_text: str, expected_answer: str, answer_type: str = "") -> dict[str, object]:
    extracted = extract_final_answer_surface(output_text, answer_type)
    expected = str(expected_answer or "")
    correct = bool(expected) and _norm(extracted) == _norm(expected)
    if not correct and expected:
        correct = _norm(expected) in _norm(extracted)
    return {
        "schema_id": "kt.v17_7_4.final_answer_surface_score.v1",
        "extracted_final_answer": extracted,
        "expected_answer_hash_only": "present" if expected else "missing",
        "correct": bool(correct),
        "score": 1.0 if correct else 0.0,
        "expected_answer_visible_to_model": False,
        "early_scratch_number_used": False,
    }


__all__ = ["score_final_answer_surface"]
