from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_next_runtime_wrapper_hygiene_requires_lane_identity_hard_fail() -> None:
    wrapper = read_json("reports/v17_7_4_next_runtime_wrapper_hygiene_contract.json")
    decision = read_json("reports/v17_7_4_next_kaggle_gate_decision.json")

    assert wrapper["status"] == "PASS"
    assert wrapper["lane_identity_hard_fail"] is True
    assert "parser canonicalizer packet invoking scratchpad wrapper" in wrapper["forbidden_mismatch_examples"]
    assert decision["packet_path_if_any"] is None


def test_no_parser_runtime_packet_is_materialized_when_gate_not_earned() -> None:
    forbidden_packets = [
        ROOT / "packets" / "ktv1774_parser_canonicalizer_microfurnace_v1.zip",
        ROOT / "packets" / "ktv1774_control_only_gsm8k_extension_v1.zip",
    ]
    for packet in forbidden_packets:
        assert not packet.exists(), packet
