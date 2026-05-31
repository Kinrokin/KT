import json
from pathlib import Path

ROOT = Path.cwd()


def test_emergency_repair_is_folded_into_truth_engine_not_new_ambulance():
    contract = json.loads((ROOT / "governance/truth_engine_contract.json").read_text(encoding="utf-8"))
    subprotocol = contract["emergency_repair_subprotocol"]
    assert subprotocol["enabled"] is True
    assert subprotocol["subsystem_created"] is False
    assert subprotocol["authority"] == "truth_engine_subprotocol"
    assert "adapter_identity_conflict" in subprotocol["triggers"]
    receipt = json.loads((ROOT / "reports/v14_emergency_repair_subprotocol_receipt.json").read_text(encoding="utf-8"))
    assert receipt["standalone_ambulance_subsystem_created"] is False
    assert receipt["truth_engine_contract_path"] == "governance/truth_engine_contract.json"
