import importlib.util
import zipfile
from pathlib import Path


def load_court(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        zf.extract("runtime/result_court.py", tmp_path)
    spec = importlib.util.spec_from_file_location("court_damage", tmp_path / "runtime" / "result_court.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_v3_result_court_blocks_damage(tmp_path):
    suite = load_court(tmp_path).synthetic_mutation_suite()
    assert suite["cases"]["correctness_damage"]["actual"] == "BLOCK_CORRECTNESS_DAMAGE"
