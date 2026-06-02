from tests.v17_7_3_authority_utils import authority_report


def test_per_band_arm_win_and_oracle_gap_matrices_exist() -> None:
    wins = authority_report("v17_7_3_per_band_arm_win_matrix.json")
    gaps = authority_report("v17_7_3_per_band_oracle_gap_matrix.json")
    assert wins["status"] == "PASS"
    assert gaps["status"] == "PASS"
    assert wins["matrix"]
    assert gaps["matrix"]
    for band, data in wins["matrix"].items():
        assert data["row_count"] > 0
        assert set(data["arms"]) == {
            "base_raw",
            "route_regret_policy_adapter_global",
            "formal_math_repair_adapter_global",
            "base_kt_hat_compact",
            "math_act_adapter_global",
        }
