from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_generated_artifacts_are_registered_before_current_authority() -> None:
    report = json.loads((ROOT / "reports/repo_generated_artifact_index_v1.json").read_text(encoding="utf-8"))

    assert report["count"] > 0
    for row in report["rows"]:
        if row["primary_class"] in {"CANONICAL_PACKET_CURRENT", "CANONICAL_RECEIPT_CURRENT"}:
            assert row["registered_current_authority"] is True
