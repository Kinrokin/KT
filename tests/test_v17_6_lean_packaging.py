from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_6_lean_packaging_blocks_bulky_defaults():
    lean = json.loads((ROOT / "reports/v17_6_lean_packaging_contract.json").read_text(encoding="utf-8"))
    disk = json.loads((ROOT / "reports/v17_6_disk_guard_contract.json").read_text(encoding="utf-8"))
    hf = json.loads((ROOT / "reports/v17_6_minimal_hf_upload_contract.json").read_text(encoding="utf-8"))
    assert lean["create_partial_measured_outputs_first"] is True
    assert lean["create_assessment_only_before_bulky_packaging"] is True
    excluded = " ".join(lean["excluded_by_default"])
    assert "model caches" in excluded
    assert "adapter safetensors" in excluded
    assert disk["low_disk_outcome"] == "KAGGLE_E2E_BLOCKED__LOW_DISK_AFTER_MEASURED_ROWS"
    assert hf["upload_safetensors_by_default"] is False
