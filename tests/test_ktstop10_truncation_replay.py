from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_first_complete_line_truncation_replay_preserves_answers() -> None:
    subprocess.run(["python", "scripts/replay_first_complete_final_line.py"], check=True)
    replay = json.loads(Path("reports/ktstop10_first_complete_line_truncation_replay.json").read_text())
    assert replay["status"] == "PASS_20_OF_20_EXTRACTIONS_AND_CORRECTNESS_PRESERVED_ZERO_DAMAGE"
    assert replay["extraction_preserved_count"] == 20
    assert replay["correctness_preserved_count"] == 20
    assert replay["semantic_trailer_after_truncation_count"] == 0
