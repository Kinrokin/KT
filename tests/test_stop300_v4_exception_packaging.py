import zipfile
from pathlib import Path


def test_v4_exception_packaging_contract():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8-sig")
    assert "BLOCKER_RECEIPT.json" in runner
    assert "PARTIAL_MEASURED_OUTPUTS.zip" in runner
    assert "KT_RAISE_ON_BLOCKER" in bootstrap
