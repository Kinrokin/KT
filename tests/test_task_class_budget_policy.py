from __future__ import annotations

from scripts import ktbud100_common as bud


def test_task_complexity_maps_gsm8k_to_multi_step_math() -> None:
    question = "If 4 boxes each contain 7 apples, how many apples are there?"
    assert bud.classify_task_complexity(question) == "multi_step_math"


def test_budget_policy_has_required_math_ceiling() -> None:
    policy = bud.apply_budget_policy("multi_step_math")
    assert policy["initial_tokens"] == 256
    assert policy["extension_size"] == 128
    assert policy["max_extensions"] == 2
    assert policy["hard_ceiling"] == 512
