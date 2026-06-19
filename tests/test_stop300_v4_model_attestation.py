import zipfile
from pathlib import Path


def test_v4_model_level_attestation_contract():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        src = zf.read("runtime/model_runtime_attestation.py").decode("utf-8-sig")
    assert "Linear4bit" in src
    assert "functional" in src
    assert "generation_warning_count" in src
    assert "effective_eos_token_ids" in src
