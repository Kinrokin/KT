import json
import zipfile
from pathlib import Path


def test_v3_three_arm_timing_contract():
    receipt = json.loads(Path("reports/stop300_v3_timing_contract.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS_60_X_3_X_3"
    assert "torch.cuda.Event" in runner
    assert "time.perf_counter_ns" in runner
    assert "build_work_plan(config)" in runner
