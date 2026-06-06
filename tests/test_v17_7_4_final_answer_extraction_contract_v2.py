from __future__ import annotations

from scripts import replay_v17_7_4_reprolock_oracle_offline_extraction as replay


def test_contract_uses_later_final_answer_over_early_scratch() -> None:
    raw = "Scratch: answer might be 5.\nCheck again.\nFinal answer: 9"

    extraction = replay.extract_final_answer_contract_v2(raw, "numeric")

    assert extraction["state"] == "EXTRACTED_EXPLICIT_FINAL"
    assert extraction["surface"] == "9"
    assert replay.expected_hash_match(extraction["surface"], replay.sha256_text("5")) is False


def test_contract_supports_mcq_without_gold_label() -> None:
    raw = "Option A is tempting. After checking, answer is C."

    extraction = replay.extract_final_answer_contract_v2(raw, "multiple_choice")

    assert extraction["surface"] == "C"
    assert extraction["extraction_surface"] == "explicit_final_marker"


def test_contract_reports_no_final_answer_state() -> None:
    extraction = replay.extract_final_answer_contract_v2("", "numeric")

    assert extraction["state"] == "NO_FINAL_ANSWER"
    assert replay.parser_failure_after(extraction) is True


def test_contract_receipt_is_post_generation_only() -> None:
    contract, receipt = replay.build_contract_v2({"status": "PASS"})

    assert contract["post_generation_only"] is True
    assert contract["mutates_prompt"] is False
    assert contract["mutates_generation"] is False
    assert contract["expected_answer_used_as_hint"] is False
    assert receipt["runtime_authority"] is False
