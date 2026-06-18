from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_immutable_stoprt_assessment_imported_and_failed_receipt_preserved() -> None:
    receipt = read_json("reports/ktstoprt_assessment_import_receipt.json")
    preserved = read_json("reports/ktstoprt_official_receipt_preservation.json")
    assert receipt["status"] == "PASS_IMMUTABLE_ASSESSMENT_IMPORTED"
    assert receipt["assessment_sha256"] == "7a11037aa4ea0f45fad7d794c458d30b14ac77c9b1a51e06d1ea8f2af80a9ab6"
    assert receipt["official_pass_gate"] is False
    assert preserved["status"] == "PRESERVED_NOT_REWRITTEN"
    assert preserved["official_receipt_must_remain_failed"] is True
