import importlib.util
import sys
import zipfile
from pathlib import Path


def test_v4_reference_court_uses_terminal_eos_truth(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        zf.extract("runtime/reference_court_v34.py", tmp_path)
    spec = importlib.util.spec_from_file_location("ref", tmp_path / "runtime" / "reference_court_v34.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    finding = mod.adjudicate_reference_court_v34("FINAL_ANSWER: 42", terminal_token_id=2, effective_eos_token_ids={2})
    assert finding.semantic_boundary_type == "SAFE_EOS_CLOSURE"
    assert finding.ended_on_eos is True
