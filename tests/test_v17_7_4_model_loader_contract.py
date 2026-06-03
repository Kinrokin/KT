from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_model_loader_contract_schema_and_receipt_are_bound() -> None:
    schema = json.loads((ROOT / "schemas" / "kt.v17_7_4.model_loader_contract.schema.json").read_text(encoding="utf-8"))
    receipt = json.loads((ROOT / "reports" / "v17_7_4_model_loader_contract_receipt.json").read_text(encoding="utf-8"))
    assert schema["properties"]["qwen_constructor_path_used"]["const"] is False
    assert schema["properties"]["bad_load_in_4bit_kwarg_forwarded"]["const"] is False
    assert receipt["loader_contract"] == "AutoModelForCausalLM.from_pretrained"
    assert receipt["quantization_contract"] == "BitsAndBytesConfig via quantization_config when load_in_4bit=true"
    assert receipt["bad_load_in_4bit_kwarg_forwarded"] is False
    assert receipt["claim_ceiling_preserved"] is True
