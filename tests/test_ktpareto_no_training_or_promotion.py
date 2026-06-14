import json
import zipfile
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_repo_and_packet_authorities_are_false():
    ensure_ktpareto_built()
    decision = json.loads((ROOT / "reports" / "ktpareto_packet_decision.json").read_text())
    summary = json.loads((ROOT / "reports" / "ktpareto_builder_summary.json").read_text())
    for payload in [decision, summary]:
        assert payload["training_authority"] is False
        assert payload["promotion_authority"] is False
        assert payload["adapter_mutation_authority"] is False
        assert payload["production_prompt_mutation_authority"] is False

    with zipfile.ZipFile(ROOT / "packets" / "ktpareto_v1.zip") as zf:
        manifest = json.loads(zf.read("PACKET_MANIFEST.json"))
    assert manifest["training_authority"] is False
    assert manifest["promotion_authority"] is False
    assert manifest["runtime_selector_deployment"] is False
