import pytest

from runtime.final_answer_stopping_criteria_v41 import KTFinalAnswerStoppingCriteria


class FakeTokenizer:
    def decode(self, ids, skip_special_tokens=False):
        return ""


class BadInput:
    shape = (2, 3)


def test_batch_size_one_required():
    criterion = KTFinalAnswerStoppingCriteria(tokenizer=FakeTokenizer(), prompt_token_count=1, monitor_only=False)
    with pytest.raises(RuntimeError, match="KT_STOP300_BATCH_SIZE_ONE_REQUIRED"):
        criterion(BadInput(), None)
