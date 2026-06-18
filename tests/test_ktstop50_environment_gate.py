from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_environment_contract_requires_cuda_and_fails_closed() -> None:
    receipt = json.loads((ROOT / "reports/ktstop50_environment_contract.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS_SPEC_BOUND_RUNTIME_PROOF_REQUIRED"
    assert receipt["cuda_required"] is True
    assert receipt["bitsandbytes_functional_required"] is True
    assert receipt["runtime_packet_fails_closed_if_unmet"] is True
