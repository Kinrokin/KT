import json
import zipfile
from pathlib import Path


def test_v2_environment_contract_requires_functional_four_bit_cuda_proof():
    receipt = json.loads(Path("reports/stop300_v2_environment_contract.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        env = zf.read("runtime/environment_preflight.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS_FUNCTIONAL_CONTRACT_DEFINED"
    assert receipt["bitsandbytes"] == "0.49.2"
    assert "functional_cuda_forward_smoke" in env
    assert "linear4bit_module_count_gt_zero_required" in env
    assert "pip\", \"check\"" in env
