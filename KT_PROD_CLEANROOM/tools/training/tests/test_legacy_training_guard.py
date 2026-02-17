from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_train_policy_c_head_refuses_without_allow_legacy(tmp_path: Path) -> None:
    ds = tmp_path / "kt_policy_c_dataset_v1.jsonl"
    ds.write_text(
        json.dumps(
            {
                "schema_id": "kt.policy_c.dataset_record.v1",
                "pressure_tensor_ref": {"path": str(tmp_path / "pressure_tensor.json"), "hash": "x"},
                "epoch_summary_ref": {"path": str(tmp_path / "policy_c_epoch_summary.json"), "hash": "y"},
                "drift_report_ref": {"path": str(tmp_path / "policy_c_drift_report.json"), "hash": "z"},
                "labels": {"status": "PASS", "reason_codes": []},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "tools.training.train_policy_c_head",
        "--dataset",
        str(ds),
        "--output-dir",
        str(out),
        "--steps",
        "1",
        "--batch-size",
        "1",
        "--device",
        "cpu",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0
    assert "FAIL_CLOSED" in (result.stderr or "") or "FAIL_CLOSED" in (result.stdout or "")

