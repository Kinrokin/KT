from kt_system.eval.math_rescue_v3_honest import (
    ABSTAIN_KEEP_ORIGINAL,
    RESCUE_APPLIED,
    rescue_trivial_arithmetic,
)
from kt_system.eval.math_verifier_v3_honest import ABSTAIN_UNVERIFIED_ACCEPT, FAIL_OBVIOUS_GARBAGE


def test_rescue_never_runs_on_abstain():
    result = rescue_trivial_arithmetic("2 + 2", ABSTAIN_UNVERIFIED_ACCEPT)

    assert result["status"] == ABSTAIN_KEEP_ORIGINAL
    assert result["rescue_attempted"] is False
    assert result["rescue_answer"] is None


def test_rescue_applies_only_to_fullmatch_whitelisted_arithmetic():
    add = rescue_trivial_arithmetic("2 + 2", FAIL_OBVIOUS_GARBAGE)
    total = rescue_trivial_arithmetic("total of 3 and 4?", FAIL_OBVIOUS_GARBAGE)
    subtract = rescue_trivial_arithmetic("subtract 3 from 10", FAIL_OBVIOUS_GARBAGE)

    assert add["status"] == RESCUE_APPLIED
    assert add["rescue_answer"] == "4"
    assert total["status"] == RESCUE_APPLIED
    assert total["rescue_answer"] == "7"
    assert subtract["status"] == RESCUE_APPLIED
    assert subtract["rescue_answer"] == "7"


def test_rescue_rejects_substring_arithmetic_inside_word_problem():
    result = rescue_trivial_arithmetic("Alice has 2 + 2 apples after buying more", FAIL_OBVIOUS_GARBAGE)

    assert result["status"] == ABSTAIN_KEEP_ORIGINAL
    assert result["rescue_attempted"] is True
    assert result["rescue_answer"] is None


def test_rescue_uses_no_expected_answer_or_model_generation():
    result = rescue_trivial_arithmetic("8 / 2", FAIL_OBVIOUS_GARBAGE)

    assert result["status"] == RESCUE_APPLIED
    assert result["rescue_answer"] == "4"
    assert result["expected_answer_used"] is False
    assert result["model_generation_invoked"] is False
    assert result["first_pass_mutated"] is False
