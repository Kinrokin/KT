import json
import zipfile
from pathlib import Path


def test_v3_work_plan_counts():
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        config = json.loads(zf.read("runtime/ktstop300_v3_config.json").decode("utf-8-sig"))
    assert config["work_units"]["edge"] == 36
    assert config["work_units"]["natural"] == 600
    assert config["work_units"]["timing"] == 540
    assert config["work_units"]["total_measured_generations"] == 1176
