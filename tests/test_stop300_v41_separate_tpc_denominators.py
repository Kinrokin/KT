from runtime.pairwise_court_v41 import _base_rows, full_tpc


def test_tpc_uses_separate_arm_correct_denominators():
    rows = _base_rows()
    assert full_tpc(rows, "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE") < full_tpc(rows, "L0_LEGACY_NO_DETECTOR")
    rows[1]["correct"] = False
    assert full_tpc(rows, "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE") != full_tpc(rows, "L0_LEGACY_NO_DETECTOR")
