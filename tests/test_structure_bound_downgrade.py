import importlib.util
import json
from pathlib import Path

ROOT = Path.cwd()


def load_script():
    spec = importlib.util.spec_from_file_location("downgrade_structure_bound_claims", ROOT / "scripts/downgrade_structure_bound_claims.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_structure_bound_language_is_downgraded_until_blind_features_pass():
    mod = load_script()
    assert mod.classify(True, False) == "STATIC_TASK_FAMILY_BOUND"
    assert mod.classify(True, True) == "HYBRID_LABEL_AND_STRUCTURE_BOUND"
    assert mod.classify(False, True) == "STRUCTURE_BOUND"
    receipt = json.loads((ROOT / "reports/v14_structure_bound_downgrade_receipt.json").read_text(encoding="utf-8"))
    assert receipt["previous_classification"] == "STRUCTURE_BOUND"
    assert receipt["current_classification"] == "STATIC_TASK_FAMILY_BOUND"
    assert receipt["structure_bound_routing_claim_authorized"] is False
    assert receipt["blind_feature_routing_required_for_structure_bound_claim"] is True
