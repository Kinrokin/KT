import json
import zipfile
from pathlib import Path


def test_v2_timing_panel_executes_declared_repetitions_and_cuda_timers():
    timing_manifest = json.loads(Path("admission/stop300_v2_timing_panel_manifest.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
    assert timing_manifest["row_count"] == 60
    assert timing_manifest["stratum_counts"] == {"EASY": 20, "HARD": 20, "MEDIUM": 20}
    assert 'config["timing_panel_rows"]' in runner
    assert "torch.cuda.Event" in runner
    assert "time.perf_counter_ns" in runner
    assert "repetition in [0, 1, 2]" in runner
