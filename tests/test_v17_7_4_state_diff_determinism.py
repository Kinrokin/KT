from __future__ import annotations

from eval.agent_diff_sandbox import evaluate_state_diff, state_hash


def test_state_diff_hash_is_deterministic() -> None:
    assert state_hash({"b": 2, "a": 1}) == state_hash({"a": 1, "b": 2})


def test_state_diff_passes_only_exact_expected_delta() -> None:
    before = {"count": 1, "flag": False}
    after = {"count": 2, "flag": False}

    passed = evaluate_state_diff(before, after, {"count": 2})
    failed = evaluate_state_diff(before, after, {"count": 3})

    assert passed["status"] == "PASS"
    assert passed["score"] == 1.0
    assert failed["status"] == "HARD_ZERO_STATE_MISMATCH"
    assert failed["score"] == 0.0
