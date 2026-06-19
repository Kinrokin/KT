from runtime.pairwise_court_v41 import derive_pair


def test_pairwise_prefix_is_derived_from_raw_traces():
    l0 = {
        "row_id": "r1",
        "raw_generated_token_ids": [1, 2, 3, 4],
        "raw_generated_text": "FINAL_ANSWER: 42\nextra",
        "prompt_token_count": 10,
        "correct": True,
    }
    s1 = {
        "row_id": "r1",
        "raw_generated_token_ids": [1, 2],
        "raw_generated_text": "FINAL_ANSWER: 42",
        "prompt_token_count": 10,
        "correct": True,
        "runtime_first_boundary": {"semantic_boundary_type": "FINAL_LINE_CLOSE"},
        "reference_court": {"semantic_boundary_type": "FINAL_LINE_CLOSE", "lawful": True},
        "token_boundary_errors": [],
    }
    pair = derive_pair(l0, s1)
    assert pair["derivation_source"] == "IMMUTABLE_RAW_L0_S1_TRACES"
    assert pair["raw_token_prefix_equivalence"] is True
    assert pair["decoded_byte_prefix_equivalence"] is True
    assert pair["physical_output_token_savings"] == 2
