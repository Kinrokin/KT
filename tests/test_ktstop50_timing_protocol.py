from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_stop50_timing_protocol_is_randomized_synchronized_and_paired() -> None:
    receipt = json.loads((ROOT / "reports/ktstop50_experiment_protocol.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS_RANDOMIZED_SYNCHRONIZED_PAIRED_TIMING_DEFINED"
    assert receipt["batch_size"] == 1
    assert receipt["randomized_synchronized_paired_timing"] is True
    assert receipt["same_model_instance"] is True
