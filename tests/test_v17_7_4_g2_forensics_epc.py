from __future__ import annotations

from scripts import build_v17_7_4_g2_forensics_epc as builder


def test_g2_state_vector_is_hypothesis_until_exact_sources_bound() -> None:
    source_index = builder.build_g2_artifact_source_index()
    state = builder.build_g2_state_vector(source_index)

    assert state["status"] == "PARTIAL_BLOCKED"
    assert state["exact_state_vector_recovered"] is False
    assert state["g2_recovered_claim"] is False
    assert "raw_outputs" in state["missing_components"]


def test_token_accounting_keeps_visible_and_full_tpc_separate() -> None:
    report = builder.token_reconciliation(builder.current_scorecard())

    assert report["status"] == "BLOCKED_UNTIL_EXACT_G2_ACCOUNTING_METHOD_RECOVERED"
    assert report["visible_answer_compression_signal"] is True
    assert report["full_system_compression_recovered"] is False
    assert report["calling_visible_tpc_full_tpc_forbidden"] is True


def test_cheapest_correct_route_simulation_is_teacher_only_not_runtime() -> None:
    sim = builder.cheapest_correct_route_simulation()

    assert sim["status"] == "PASS_TEACHER_ONLY_NOT_RUNTIME"
    assert sim["oracle_correctness_used_as_runtime_feature"] is False
    assert sim["runtime_authority"] is False
    assert sim["promotion_authority"] is False
    assert sim["cheapest_correct_candidate_correct"] >= sim["stable_control_correct"]


def test_epc_vetoes_training_and_micro_furnace_when_forensics_missing() -> None:
    source_index = builder.build_g2_artifact_source_index()
    state = builder.build_g2_state_vector(source_index)
    token_report = builder.token_reconciliation(builder.current_scorecard())
    extraction = builder.offline_extraction_replay()
    route_sim = builder.cheapest_correct_route_simulation()
    epc = builder.experiment_policy_controller(state, extraction, route_sim, token_report)
    micro = builder.micro_furnace_design(epc)

    assert epc["status"] == "PASS"
    assert epc["training_authorized"] is False
    assert epc["promotion_authority"] is False
    assert epc["no_runtime_generation_until_forensics"] is True
    assert micro["status"] == "HELD_BY_EPC"
    assert micro["micro_furnace_packet_generated"] is False


def test_ope_authority_hardening_blocks_replay_claim_laundering() -> None:
    receipt = builder.ope_authority_hardening()

    assert receipt["replay_is_not_fresh_generation"] is True
    assert receipt["source_replay_cannot_authorize_training"] is True
    assert receipt["cheapest_correct_teacher_policy_cannot_be_runtime_policy"] is True
    assert receipt["g2_anchor_is_historical_hypothesis_not_recovered_claim"] is True
