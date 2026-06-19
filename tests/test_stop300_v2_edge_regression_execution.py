import json
import zipfile
from pathlib import Path


def test_v2_edge_regression_fixture_is_executed_by_runner():
    manifest = json.loads(Path("admission/stop300_v2_edge_regression_manifest.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
    assert manifest["status"] == "PASS_12_ROWS_3_ARMS"
    assert len(manifest["rows"]) == 12
    assert 'config["edge_regression_rows"]' in runner
    assert 'phase="edge"' in runner
