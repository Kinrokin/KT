import zipfile
from pathlib import Path


def test_v2_runner_contains_three_arm_execution_and_arm_order():
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        timing = zf.read("runtime/timing_protocol.py").decode("utf-8-sig")
    assert "M0_STREAMING_DETECTOR_MONITOR_ONLY" in runner
    assert "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE" in runner
    assert "L0_LEGACY_NO_DETECTOR" in runner
    assert "arm_order(" in runner
    assert "def arm_order" in timing
