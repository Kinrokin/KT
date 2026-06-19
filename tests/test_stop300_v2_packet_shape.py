import json
import zipfile
from pathlib import Path


def test_v2_packet_shape_and_runtime_config():
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop300_v2_config.json").decode("utf-8-sig"))
    assert "runtime/KT_CANONICAL_RUNNER.py" in names
    assert "runtime/result_court.py" in names
    assert manifest["run_mode"] == "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V2"
    assert manifest["kaggle_dataset_name"] == "ktstop300-v2"
    assert len(config["natural_rows"]) == 300
    assert len(config["timing_panel_rows"]) == 60
    assert len(config["edge_regression_rows"]) == 12
