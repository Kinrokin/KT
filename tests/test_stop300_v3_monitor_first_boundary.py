from runtime.stop_fsm_v33 import StopGrammarV33RuntimeFSM


def test_v3_monitor_preserves_immutable_first_boundary():
    fsm = StopGrammarV33RuntimeFSM(monitor_only=True)
    first = fsm.feed("FINAL_ANSWER: 42\n", token_start_index=0, token_end_index=1)
    second = fsm.feed("FINAL_ANSWER: 99\n", token_start_index=1, token_end_index=2)
    assert first.should_stop is False
    assert second.should_stop is False
    assert fsm.first_boundary_decision is not None
    assert fsm.first_boundary_decision.boundary_generated_token_index_exclusive == 1
    assert fsm.last_detector_decision is not None
