from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_stop50_import_binds_expected_hashes_and_scorecard() -> None:
    receipt = read_json("reports/ktstop50_assessment_import_receipt.json")
    assert receipt["status"] == "PASS_STOP50_IMMUTABLE_ASSESSMENT_BOUND"
    assert receipt["assessment_sha256"] == "50d94b6b3688c5917547fb7ff12747defc9ba0ab7944c1231d4b218f74383ec9"
    assert receipt["unique_rows"] == 50
    assert receipt["baseline_correct"] == 45
    assert receipt["runtime_stop_correct"] == 45
    assert receipt["raw_original_token_prefix_equality"] == "150/150"


def test_stop50_hostile_synthesis_preserves_claim_boundary() -> None:
    receipt = read_json("reports/ktstop50_hostile_synthesis.json")
    assert receipt["status"] == "MECHANISM_SIGNAL_STRONG_POSITIVE"
    assert "GENERAL_RUNTIME_SAFETY_UNPROVEN" in receipt["scoped_findings"]
    assert receipt["runtime_authority"] is False
