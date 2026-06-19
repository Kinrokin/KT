from runtime.token_boundary_map import build_token_boundary_record, validate_token_boundary_record


class FakeTokenizer:
    def decode(self, ids, skip_special_tokens=True):
        return " ".join(map(str, ids))


def test_v3_exact_token_boundary_invariants():
    rec = build_token_boundary_record(
        tokenizer=FakeTokenizer(),
        raw_generated_token_ids=[10, 20, 30, 40],
        raw_generated_text="10 20 30 40",
        boundary_generated_token_index_exclusive=2,
        trigger_token_start_index=2,
    ).to_json()
    assert rec["authoritative_preserved_token_ids"] == [10, 20]
    assert rec["dropped_trigger_token_count"] == 2
    assert validate_token_boundary_record(rec) == []
