from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_answer_surface_audit_decides_kaggle_gate_without_runtime_packet() -> None:
    summary = read_json("reports/v17_7_4_answer_surface_audit_builder_summary.json")
    decision = read_json("reports/v17_7_4_next_kaggle_gate_decision.json")
    epc = read_json("reports/v17_7_4_epc_decision_after_parser_blindness_gate.json")

    assert summary["outcome"] == "KT_ANSWER_SURFACE_AUDIT_COMPLETE__NEXT_KAGGLE_GATE_DECIDED__CLAIM_CEILING_PRESERVED"
    assert summary["selected_next_lane"] == "NO_RUNTIME_PACKET_WARRANTED_BY_ANSWER_SURFACE_AUDIT"
    assert decision["packet_path_if_any"] is None
    assert decision["kaggle_dataset_name_if_any"] is None
    assert epc["parser_microfurnace_authorized"] is False
    assert epc["control_only_gsm8k_extension_authorized"] is False
    assert summary["runtime_authority"] is False
    assert summary["claim_ceiling_status"] == "PRESERVED"


def test_answer_surface_audit_has_required_advisory_and_freeze_receipts() -> None:
    external = read_json("reports/v17_7_4_external_eye_review_receipt.json")
    blind = read_json("reports/v17_7_4_reviewer_blindness_guard_receipt.json")
    order = read_json("reports/v17_7_4_candidate_extraction_order_freeze_receipt.json")
    toggles = read_json("reports/v17_7_4_canonicalizer_toggle_freeze_receipt.json")

    assert external["status"] == "PASS_ADVISORY_ONLY"
    assert external["external_validation_claim"] is False
    assert blind["candidate_selection_gold_blind"] is True
    assert order["frozen_before_scoring"] is True
    assert order["candidate_order"][0] == "CURRENT_SCORER"
    assert toggles["frozen_before_scoring"] is True
    assert toggles["canonicalizer_toggles"]["last_numeric_runtime_fallback"] is False


def test_answer_surface_provenance_rows_are_hash_bound_and_audit_only_for_last_numeric() -> None:
    rows = read_jsonl("reports/v17_7_4_answer_surface_provenance_table.jsonl")
    audit = read_json("reports/v17_7_4_answer_surface_audit.json")

    assert rows
    assert audit["last_numeric_runtime_authority"] is False
    assert all(row["span_sha256"] for row in rows)
    assert all(row["raw_surface_hash"] for row in rows)
    assert all(row["canonical_surface_hash"] for row in rows)
    assert all(row["expected_answer_used_for_candidate_selection"] is False for row in rows)
    assert all(row["expected_answer_model_visible"] is False for row in rows)
    for row in rows:
        if row["surface_id"] == "LAST_NUMERIC_AUDIT_ONLY":
            assert row["audit_only"] is True
            assert row["runtime_admissible"] is False


def test_answer_surface_row_table_preserves_offline_only_boundary() -> None:
    rows = read_jsonl("reports/v17_7_4_parser_canonicalizer_row_table.jsonl")
    sim = read_json("reports/v17_7_4_parser_canonicalizer_offline_simulation.json")

    assert len(rows) == sim["row_count"] == 25
    assert all(row["model_generation_invoked"] is False for row in rows)
    assert all(row["first_pass_mutated"] is False for row in rows)
    assert all(row["expected_answer_model_visible"] is False for row in rows)
    assert all(row["expected_answer_used_for_candidate_selection"] is False for row in rows)
    assert sim["model_generation_invoked"] is False
