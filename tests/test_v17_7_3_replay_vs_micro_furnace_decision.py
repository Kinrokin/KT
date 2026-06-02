from tests.v17_7_3_authority_utils import assert_no_authority, authority_report


def test_replay_vs_micro_furnace_decision_selects_true_generation() -> None:
    decision = authority_report("v17_7_3_replay_vs_micro_furnace_decision.json")
    final = authority_report("v17_7_3_final_decision_receipt.json")
    assert decision["status"] == "PASS"
    assert decision["decision"] == "TRUE_GENERATION_MINI_FURNACE_REQUIRED"
    assert decision["targeted_replay_permitted"] is False
    assert final["selected_decision"] == "TRUE_GENERATION_MINI_FURNACE_REQUIRED"
    assert final["next_lawful_move"] == "RUN_KTV1774_TRUEGEN_MINIFURNACE_PACKET"
    assert_no_authority(final)
