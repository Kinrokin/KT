import json
import zipfile
from pathlib import Path


def test_v3_model_attestation_is_model_level_not_linear_smoke():
    receipt = json.loads(Path("reports/stop300_v3_environment_contract.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        attestation = zf.read("runtime/model_runtime_attestation.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS_FUNCTIONAL_MODEL_4BIT_ATTESTED"
    assert "Linear4bit" in attestation
    assert "functional_one_token_generation" in attestation
    assert "model.generate" in attestation
