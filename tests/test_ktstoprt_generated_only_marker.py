from __future__ import annotations

from runtime.final_answer_stop import GeneratedOnlyBatchOneAdapter


class ToyTokenizer:
    def decode(self, ids, skip_special_tokens=False):
        return "".join(chr(i) for i in ids)


def test_generated_only_marker_ignores_prompt_marker() -> None:
    prompt = "FINAL_ANSWER: prompt poison\n"
    generated = "Reasoning first"
    ids = [ord(ch) for ch in prompt + generated]
    adapter = GeneratedOnlyBatchOneAdapter(ToyTokenizer(), len(prompt))
    decision = adapter.evaluate_ids(ids)
    assert decision.should_stop is False
    assert decision.reason == "CONTINUE"
