import zipfile
from pathlib import Path


def test_v3_warmups_are_executed_and_discarded():
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        work_plan = zf.read("runtime/work_plan.py").decode("utf-8-sig")
    assert "for warmup_index in range(3)" in work_plan
    assert '"phase": "warmup"' in work_plan
    assert '"evidence": False' in work_plan
