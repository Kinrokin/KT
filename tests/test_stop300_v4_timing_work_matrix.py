import importlib.util
import json
import sys
import zipfile
from pathlib import Path


def test_v4_work_matrix_counts(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        zf.extractall(tmp_path / "packet")
    sys.path.insert(0, str(tmp_path / "packet"))
    try:
        spec = importlib.util.spec_from_file_location("work", tmp_path / "packet" / "runtime" / "work_plan.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        config = json.loads((tmp_path / "packet" / "runtime" / "ktstop300_v4_config.json").read_text())
        receipt = mod.work_plan_receipt(config)
    finally:
        sys.path.remove(str(tmp_path / "packet"))
    assert receipt["measured_work_units"] == 1176
    assert receipt["warmup_units"] == 9
