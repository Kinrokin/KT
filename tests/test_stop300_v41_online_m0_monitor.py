from runtime.final_answer_stopping_criteria_v41 import KTFinalAnswerStoppingCriteria


class FakeTokenizer:
    def decode(self, ids, skip_special_tokens=False):
        return "".join({1: "FINAL_ANSWER:", 2: " 42", 3: "\n", 4: " trailer"}[int(i)] for i in ids)


def test_m0_uses_same_online_detector_without_physical_stop():
    criterion = KTFinalAnswerStoppingCriteria(tokenizer=FakeTokenizer(), prompt_token_count=2, monitor_only=True)
    assert criterion.consume_new_token_ids([1, 2, 3]) is False
    assert criterion.first_boundary_decision.semantic_boundary_type.value == "FINAL_LINE_CLOSE"
