from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_historical_replay_blocks_first_wrong_later_correct_in_exact_protocol() -> None:
    replay = json.loads((ROOT / "reports/historical_first_vs_last_answer_counterfactual_replay.json").read_text(encoding="utf-8-sig"))
    scope = json.loads((ROOT / "reports/first_answer_safety_scope_decision.json").read_text(encoding="utf-8-sig"))
    assert replay["status"] == "PASS_EXACT_PROTOCOL_FIRST_WRONG_LATER_CORRECT_ZERO"
    assert scope["exact_protocol_first_wrong_later_correct"] == 0
    assert replay["exact_protocol_processed_traces"] > 0


def test_historical_coverage_ledger_names_processed_sources() -> None:
    coverage = json.loads((ROOT / "reports/historical_trace_source_coverage.json").read_text(encoding="utf-8-sig"))
    assert coverage["status"] == "PASS_WITH_NAMED_COVERAGE_LEDGER"
    assert any(source["status"] == "PROCESSED" for source in coverage["sources"])
