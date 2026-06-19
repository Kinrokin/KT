import zipfile
from pathlib import Path


def test_v2_wall_time_partial_outputs_are_created():
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        checkpoint = zf.read("runtime/checkpoint_manager.py").decode("utf-8-sig")
    assert "KT_MAX_WALL_SECONDS" in runner
    assert "PARTIAL_WALL_TIME_CHECKPOINTED" in runner
    assert "PARTIAL_MEASURED_OUTPUTS.zip" in checkpoint
