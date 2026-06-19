import json
import zipfile
from pathlib import Path


def test_v3_packet_shape():
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
    assert "runtime/token_boundary_map.py" in names
    assert "runtime/work_plan.py" in names
    assert "runtime/atomic_record_store.py" in names
    assert manifest["run_mode"] == "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V3"
    assert manifest["kaggle_dataset_name"] == "ktstop300-v3"
