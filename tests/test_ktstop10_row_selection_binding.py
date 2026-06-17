from __future__ import annotations

import json
import zipfile
from pathlib import Path


def test_ktstop10_preserves_exact_lab_row_selection() -> None:
    selection = json.loads(Path("reports/ktstop10_row_selection_binding.json").read_text())
    assert selection["status"] == "PASS_EXACT_10_ROWS"
    assert selection["row_count"] == 10
    assert selection["bucket_counts"] == {
        "FIXED512_CORRECT_CONTROL": 2,
        "NO_CORRECT_OR_CANONICALIZER_RELEVANT": 4,
        "POST_FINAL_TRAILER_CONTAMINATION": 4,
    }
    with zipfile.ZipFile("packets/ktstop10_v1.zip") as zf:
        config = json.loads(zf.read("runtime/ktstop10_config.json"))
    assert [row["row_id"] for row in config["rows"]] == [row["row_id"] for row in selection["rows"]]
