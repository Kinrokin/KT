import importlib.util
import zipfile
from pathlib import Path


def test_v3_result_court_blocks_late_correction(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        zf.extract("runtime/result_court.py", tmp_path)
    spec = importlib.util.spec_from_file_location("court_correction", tmp_path / "runtime" / "result_court.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite = mod.synthetic_mutation_suite()
    assert suite["cases"]["late_correction_cut"]["actual"] == "BLOCK_FIRST_ANSWER_CORRECTION_CUT"
