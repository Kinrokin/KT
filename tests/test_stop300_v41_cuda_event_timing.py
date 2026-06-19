import zipfile
from pathlib import Path


def test_runner_executes_cuda_event_timing_source():
    with zipfile.ZipFile(Path("packets/ktstop300_v4_1.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
    assert "torch.cuda.Event" in runner
    assert "torch.cuda.synchronize()" in runner
    assert "cuda_event_timing_executed" in runner
