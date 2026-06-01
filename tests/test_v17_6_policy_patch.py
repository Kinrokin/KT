from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_6_policy_patch_is_prep_only_and_no_training():
    policy = json.loads((ROOT / "admission/v17_6_oracle_autopsy_patched_policy.json").read_text(encoding="utf-8"))
    receipt = json.loads((ROOT / "reports/v17_6_policy_patch_receipt.json").read_text(encoding="utf-8"))
    do_not_train = json.loads((ROOT / "reports/v17_6_do_not_train_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert policy["runtime_authority"] is False
    assert policy["promotion_authority"] is False
    assert policy["adapter_training_authorized"] is False
    assert policy["learned_router_superiority_claim"] is False
    assert do_not_train["training_authorized"] is False
    assert do_not_train["adapter_training_authorized"] is False
    assert "use no oracle correctness" in " ".join(policy["policy_rules"])
