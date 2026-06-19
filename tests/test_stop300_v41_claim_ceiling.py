import json
import zipfile
from pathlib import Path


def test_v41_claim_ceiling_and_authorities():
    with zipfile.ZipFile(Path("packets/ktstop300_v4_1.zip")) as zf:
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
    assert manifest["claim_ceiling_status"] == "PRESERVED"
    for key in [
        "runtime_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
        "production_math_mode_claim",
    ]:
        assert manifest[key] is False
