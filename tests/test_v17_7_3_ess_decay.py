from tests.v17_7_3_authority_utils import authority_report


def test_ess_formula_is_computed_but_does_not_override_tier_limit() -> None:
    ess = authority_report("v17_7_3_ess_decay_matrix.json")
    assert ess["status"] == "PASS"
    assert ess["formula"] == "ESS=(sum_i w_i)^2/sum_i w_i^2"
    assert ess["ess"] == 400
    assert ess["replay_authority_gate_pass"] is False
