from __future__ import annotations

from scripts import ktbud100_common as bud


def test_replay_budget_policy_emits_required_trace_fields() -> None:
    rows = [{"sample_id": "gsm8k:test:25", "question_text": "How many are 2 plus 3?"}]
    traces = bud.replay_budget_policy(rows)

    trace = traces[0]
    for key in [
        "sample_id",
        "task_class",
        "initial_budget",
        "extensions_used",
        "extension_size",
        "hard_ceiling",
        "stop_reason",
        "final_marker_detected",
        "budget_cap_hit",
        "prompt_tokens",
        "output_tokens",
        "total_tokens",
        "correct",
        "verifier_or_scorer_status",
    ]:
        assert key in trace
    assert trace["task_class"] == "multi_step_math"
