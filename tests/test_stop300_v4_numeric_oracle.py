import importlib.util
import zipfile
from pathlib import Path


def test_v4_numeric_oracle_fixture_suite(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        zf.extract("runtime/numeric_normalizer.py", tmp_path)
    spec = importlib.util.spec_from_file_location("norm", tmp_path / "runtime" / "numeric_normalizer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.oracle_fixture_suite()["status"] == "PASS"
    assert mod.normalize_number("3/4") == "0.75"
