from __future__ import annotations

import json
from pathlib import Path

from kt_system.eval.parser_canonicalizer_v17_7_4 import (
    canonicalize_surface,
    extract_answer_surfaces,
    select_frozen_candidate,
)


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_parser_canonicalizer_runtime_gate_blocks_when_damage_detected() -> None:
    simulation = read_json("reports/v17_7_4_parser_canonicalizer_offline_simulation.json")
    damage = read_json("reports/v17_7_4_parser_canonicalizer_damage_gate_receipt.json")
    split = read_json("reports/v17_7_4_parser_canonicalizer_split_validation_receipt.json")

    assert simulation["status"] == "PASS_NO_RUNTIME_PACKET"
    assert simulation["runtime_packet_warranted"] is False
    assert damage["runtime_packet_allowed"] is False
    assert damage["damage_to_control_correct"] == simulation["damage_to_control_correct"]
    assert split["status"] == "RUNTIME_BLOCKED_SPLIT_VALIDATION_NOT_EARNED"


def test_parser_canonicalizer_current_scorer_is_default_and_last_numeric_is_audit_only() -> None:
    output = "Scratch: numbers 1 2 3.\nFinal: 12"
    row = {"dataset": "gsm8k", "task_family": "formal_math", "parsed_answer": "3", "visible_answer": "12"}

    result = select_frozen_candidate(output, row)
    surfaces = extract_answer_surfaces(output, row)

    assert result["selected_surface"]["surface_id"] == "CURRENT_SCORER"
    assert result["selected_surface"]["canonical_surface"] == "3"
    last_numeric = [surface for surface in surfaces if surface["surface_id"] == "LAST_NUMERIC_AUDIT_ONLY"]
    assert last_numeric
    assert last_numeric[0]["audit_only"] is True
    assert last_numeric[0]["runtime_admissible"] is False


def test_parser_canonicalizer_only_narrow_numeric_cleanup() -> None:
    assert canonicalize_surface("$1,000.0", answer_kind="numeric") == (
        "1000",
        "currency_symbol_strip+comma_strip+decimal_zero_to_integer",
    )
    assert canonicalize_surface("two", answer_kind="numeric") == ("two", "identity")
