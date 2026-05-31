import json
from pathlib import Path

ROOT = Path.cwd()


def test_shadow_route_policy_has_no_runtime_or_promotion_authority():
    obj = json.loads((ROOT / "admission/shadow_route_policy_spec.json").read_text(encoding="utf-8"))
    assert obj["runtime_authority"] is False
    assert obj["promotion_authority"] is False
    assert obj["adapter_promotion_authority"] is False
    assert obj["claim_authority"] == "NONE"
    assert obj["oracle_route_deployable"] is False
    assert "oracle_correct" in obj["forbidden_features"]
