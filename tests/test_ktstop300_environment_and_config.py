from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_stop300_environment_contract_requires_exact_functional_run() -> None:
    receipt = read_json("reports/stop300_environment_contract.json")
    assert receipt["status"] == "PASS_CONTRACT_DEFINED"
    assert receipt["functional_statement"] == "FUNCTIONAL_FOR_THIS_EXACT_RUN__NOT_GENERALLY_CLEAN"
    assert receipt["bitsandbytes_required"] == "0.49.2"
    assert receipt["cpu_offload_allowed"] is False
    assert receipt["disk_offload_allowed"] is False


def test_stop300_effective_config_authority_is_single_source() -> None:
    receipt = read_json("reports/stop300_effective_config_authority.json")
    assert receipt["status"] == "PASS"
    assert receipt["quantization_authority"] == "MODEL_EMBEDDED"
    assert receipt["runtime_bitsandbytes_config_allowed"] is False
    assert receipt["generation_config_warning_count_required"] == 0
