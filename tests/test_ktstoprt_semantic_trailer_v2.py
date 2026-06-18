from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_semantic_trailer_v2_measures_control_and_stop_arms_separately() -> None:
    receipt = json.loads((ROOT / "reports/ktstoprt_semantic_trailer_v2.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS_DETERMINISTIC_SEMANTIC_TRAILER_MEASUREMENT"
    arms = receipt["arm_summary"]
    assert arms["B0_CURRENT_PROMPT_LEGACY_GENERATION"]["semantic_trailer_count"] == 8
    assert arms["B1_CURRENT_PROMPT_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"]["semantic_trailer_count"] == 0
