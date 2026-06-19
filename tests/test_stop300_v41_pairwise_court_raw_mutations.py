from runtime.pairwise_court_v41 import synthetic_mutation_suite


def test_raw_trace_mutation_suite_fails_closed():
    assert synthetic_mutation_suite()["status"] == "PASS_RAW_TRACE_FAIL_CLOSED_MUTATION_SUITE"
