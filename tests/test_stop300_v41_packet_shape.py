import json
import zipfile
from pathlib import Path


def test_v41_packet_shape():
    with zipfile.ZipFile(Path("packets/ktstop300_v4_1.zip")) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
    for member in [
        "runtime/final_answer_stopping_criteria_v41.py",
        "runtime/pairwise_court_v41.py",
        "runtime/result_court.py",
        "runtime/stop_fsm_v34.py",
    ]:
        assert member in names
    assert manifest["run_mode"] == "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4_1"
    assert manifest["kaggle_dataset_name"] == "ktstop300-v4-1"
    assert "StoppingCriteriaList" in runner
    assert "stopping_criteria=criteria" in runner
