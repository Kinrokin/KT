import json
import zipfile
from pathlib import Path


def test_v4_packet_shape():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
    for member in [
        "runtime/dependency_preflight.py",
        "runtime/stop_fsm_v34.py",
        "runtime/reference_court_v34.py",
        "runtime/boundary_evidence.py",
        "runtime/result_court.py",
    ]:
        assert member in names
    assert manifest["run_mode"] == "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4"
    assert manifest["kaggle_dataset_name"] == "ktstop300-v4"
