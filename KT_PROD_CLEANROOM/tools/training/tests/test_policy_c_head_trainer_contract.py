from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys


def write_json(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def test_policy_c_head_trainer_creates_artifacts(tmp_path: Path) -> None:
    pressure = tmp_path / "pressure_tensor.json"
    epoch_sum = tmp_path / "policy_c_epoch_summary.json"
    drift = tmp_path / "policy_c_drift_report.json"

    write_json(pressure, {"axes": {"time": {"intensity": 0.0, "enabled": True}}})
    write_json(epoch_sum, {"signals": {"coverage_fatigue": 0.33, "domain_hop_rate": 0.5}})
    write_json(drift, {"status": "PASS", "metrics": {"drift_score": 0.01}})

    ds = tmp_path / "kt_policy_c_dataset_v1.jsonl"
    rec = {
        "schema_id": "kt.policy_c.dataset_record.v1",
        "pressure_tensor_ref": {"path": str(pressure), "hash": "x"},
        "epoch_summary_ref": {"path": str(epoch_sum), "hash": "y"},
        "drift_report_ref": {"path": str(drift), "hash": "z"},
        "labels": {"status": "PASS", "reason_codes": []},
    }
    ds.write_text(json.dumps(rec) + "\n", encoding="utf-8")

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
        "--seed",
        "1",
        "--steps",
        "5",
        "--batch-size",
        "1",
        "--device",
        "cpu",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    head = out / "policy_c_head.pt"
    manifest = out / "train_manifest.json"
    assert head.exists()
    assert manifest.exists()

    meta = json.loads(manifest.read_text(encoding="utf-8"))
    assert meta["dataset_hash"]
    assert meta["seed"] == 1

    weights_hash = hashlib.sha256(head.read_bytes()).hexdigest()
    assert meta["artifact"]["sha256"] == weights_hash
