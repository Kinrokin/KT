import zipfile
from pathlib import Path


def test_v3_exception_paths_package_blocker_and_partial():
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        checkpoint = zf.read("runtime/checkpoint_manager.py").decode("utf-8-sig")
    assert "BLOCKER_RECEIPT.json" in runner
    assert "PARTIAL_WALL_TIME_CHECKPOINTED" in runner
    assert "PARTIAL_MEASURED_OUTPUTS.zip" in checkpoint
    assert "KT_STOP300_V3_WRAPPER_COLLECTION.zip" in checkpoint
