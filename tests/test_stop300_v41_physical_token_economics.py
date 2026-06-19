from runtime.pairwise_court_v41 import execute_core_result_court, _base_rows


def test_physical_token_economics_uses_raw_generated_tokens():
    result = execute_core_result_court(_base_rows(), {})
    vector = result["predicate_vector"]
    assert vector["aggregate_physical_output_token_reduction"] == 6000
    assert vector["aggregate_full_token_reduction"] == 6000
    assert result["status"] == "PASS_CORE_RESULT__PAIRWISE_RAW_TRACE_COURT"
