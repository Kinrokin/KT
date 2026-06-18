from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_restart_resume_contract_is_checkpoint_safe() -> None:
    receipt = read_json("reports/stop300_restart_resume_contract.json")
    assert receipt["status"] == "PASS_CONTRACT_DEFINED"
    assert receipt["atomic_jsonl_append_after_every_arm"] is True
    assert receipt["scope_mismatch_blocker"] is True
    assert receipt["partial_outputs_zip"] == "PARTIAL_MEASURED_OUTPUTS.zip"


def test_publication_order_avoids_self_hash_loop() -> None:
    receipt = read_json("reports/stop300_publication_order_receipt.json")
    assert receipt["status"] == "PASS_PUBLICATION_ORDER_DEFINED"
    assert receipt["order"][-1] == "keep HF_FINAL_ASSESSMENT_UPLOAD_RECEIPT.json in wrapper collection"


def test_stop300_claim_boundary_all_forbidden_authorities_false() -> None:
    receipt = read_json("reports/stop300_claim_boundary_receipt.json")
    assert receipt["status"] == "PASS_CLAIM_CEILING_PRESERVED"
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
        assert receipt[key] is False
