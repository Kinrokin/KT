import importlib.util
import zipfile
from pathlib import Path


def test_v4_result_court_mutation_suite_passes(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        zf.extract("runtime/result_court.py", tmp_path)
    spec = importlib.util.spec_from_file_location("court2", tmp_path / "runtime" / "result_court.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.synthetic_mutation_suite()["status"] == "PASS_CONJUNCTIVE_FAIL_CLOSED_MUTATION_SUITE"
