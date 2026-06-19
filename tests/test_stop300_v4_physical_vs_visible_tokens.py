import importlib.util
import sys
import zipfile
from pathlib import Path


def test_v4_physical_token_ledger_separates_raw_and_visible(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        zf.extract("runtime/boundary_evidence.py", tmp_path)
    spec = importlib.util.spec_from_file_location("boundary", tmp_path / "runtime" / "boundary_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    ledger = mod.build_physical_token_ledger(prompt_token_ids=[1], raw_generated_token_ids=[10, 11, 12, 13], semantic_visible_text="FINAL_ANSWER: 7", canonical_extracted_answer="7", generator_termination_source="CUSTOM_STOP_CRITERION", boundary_token_index_floor=2, boundary_token_index_ceil=3)
    assert ledger.raw_generated_token_count == 4
    assert ledger.physical_stopped_generated_token_count == 3
    assert mod.validate_physical_token_ledger(ledger.to_json()) == []
