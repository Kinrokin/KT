from __future__ import annotations

import json
from pathlib import Path


def test_bud100_assessment_import_receipt() -> None:
    receipt = json.loads(Path("reports/bud100_assessment_import_receipt.json").read_text(encoding="utf-8"))

    assert receipt["schema_id"] == "kt.bud100_assessment_import_receipt.v1"
    assert receipt["status"] == "PASS"
    assert receipt["assessment_sha256_matches_expected"] is True
    assert receipt["row_count"] == 100
    assert receipt["row_slice"] == "openai/gsm8k:test[25:125]"
    assert receipt["overlap_with_bud25"] is False
    assert receipt["oracle_diagnostic_score"] == 1.0
    assert receipt["training_authority"] is False
    assert receipt["claim_ceiling_preserved"] is True
