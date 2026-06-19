from runtime.final_answer_stopping_criteria_v41 import KTFinalAnswerStoppingCriteria


class FakeTokenizer:
    def decode(self, ids, skip_special_tokens=False):
        return "".join({1: "FINAL_ANSWER:", 2: " 42", 3: "\n", 4: " trailer"}[int(i)] for i in ids)


def test_s1_stops_at_first_complete_final_answer_line():
    criterion = KTFinalAnswerStoppingCriteria(tokenizer=FakeTokenizer(), prompt_token_count=2, monitor_only=False)
    assert criterion.consume_new_token_ids([1]) is False
    assert criterion.consume_new_token_ids([2]) is False
    assert criterion.consume_new_token_ids([3]) is True
    assert criterion.first_boundary_decision.semantic_boundary_type.value == "FINAL_LINE_CLOSE"
