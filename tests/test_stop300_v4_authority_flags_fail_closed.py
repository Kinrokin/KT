import json
import zipfile
from pathlib import Path


def test_v4_authority_flags_present_exact_false():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
    for key in [
        "shadow_runtime_authority",
        "runtime_authority",
        "dataset_generation_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
        "production_math_mode_claim",
    ]:
        assert key in manifest
        assert type(manifest[key]) is bool
        assert manifest[key] is False
    assert manifest["sandbox_inference_authority"] is True
