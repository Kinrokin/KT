from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_replay_correlation_uses_replay_scores_but_decides_from_truegen_rows() -> None:
    core = _core()
    rows = json.loads((ROOT / "admission" / "v17_7_4_truegen_row_manifest.json").read_text())["rows"][:2]
    arm_rows = []
    for index, row in enumerate(rows):
        for arm in core.ARM_IDS:
            arm_rows.append(
                {
                    "schema_id": "kt.v17_7_4.truegen_arm_result.v1",
                    "sample_id": row["sample_id"],
                    "arm_id": arm,
                    "score": 1.0 if index == 0 else 0.0,
                    "measurement_source": core.FRESH_SOURCE,
                    "measurement_status": core.FRESH_STATUS,
                    "generation_artifacts_present": True,
                }
            )
    result = core.replay_correlation(arm_rows, rows)
    assert result["schema_id"] == "kt.v17_7_4.truegen_replay_correlation_scorecard.v1"
    assert result["compared_pairs"] > 0
    assert result["decision"] in {
        "TRUEGEN_VALIDATED__TARGETED_REPLAY_DESIGN_NEXT",
        "TRUEGEN_CONFLICTS_WITH_REPLAY__DIAGNOSTIC_REVIEW_NEXT",
        "TRUEGEN_INSUFFICIENT__LARGER_MINIFURNACE_NEXT",
    }
