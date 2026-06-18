from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path


def test_ktstoprt_packet_shape_and_runtime_stop_wiring() -> None:
    subprocess.run(["python", "scripts/validate_ktstoprt_packet.py"], check=True)
    packet = Path("packets/ktstoprt_v1.zip")
    assert packet.exists()
    with zipfile.ZipFile(packet) as zf:
        manifest = json.loads(zf.read("PACKET_MANIFEST.json"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode()
        config = json.loads(zf.read("runtime/ktstoprt_config.json"))
    assert manifest["run_mode"] == "RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1"
    assert manifest["kaggle_dataset_name"] == "ktstoprt-v1"
    assert manifest["sandbox_inference_authority"] is True
    assert "FirstCompleteFinalAnswerLineStoppingCriteria" in runner
    assert len(config["rows"]) == 10
