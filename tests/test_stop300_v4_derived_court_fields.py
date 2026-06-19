import zipfile
from pathlib import Path


def test_v4_runner_derives_court_fields_not_hardcoded_safe_booleans():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
    assert "derived_prefix_equivalence" in runner
    assert "derived_runtime_reference_agreement" in runner
    assert '"prefix_equivalence": True' not in runner
    assert '"unsafe_stop": False' not in runner
