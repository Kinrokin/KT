from __future__ import annotations

import json
import zipfile
from pathlib import Path

from scripts import bind_v17_7_4_g2_state_vector as binder


def _make_assessment_zip(path: Path) -> None:
    rows = [
        {
            "subject": "routed_13_lobe_kt_hat_compact",
            "dataset": "gsm8k",
            "item_id": "gsm8k-0",
            "correct": True,
            "new_tokens": 2,
            "raw_prediction": "answer is 1",
            "normalized_prediction": "1",
            "normalized_answer": "1",
        },
        {
            "subject": "routed_13_lobe_kt_hat_compact",
            "dataset": "gsm8k",
            "item_id": "gsm8k-1",
            "correct": False,
            "new_tokens": 4,
            "raw_prediction": "answer is 2",
            "normalized_prediction": "2",
            "normalized_answer": "3",
        },
        {
            "subject": "base_raw",
            "dataset": "arc_challenge",
            "item_id": "arc-0",
            "correct": True,
            "new_tokens": 8,
            "raw_prediction": "A",
            "normalized_prediction": "A",
            "normalized_answer": "A",
        },
    ]
    content = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(binder.G2_ASSESSMENT_MEMBER, content)


def test_assessment_zip_binds_raw_outputs_and_output_token_ledger(tmp_path: Path) -> None:
    zip_path = tmp_path / "assessment.zip"
    _make_assessment_zip(zip_path)

    inspection = binder.inspect_assessment_zip(zip_path)
    raw = binder.build_raw_output_binding(inspection)
    token = binder.build_token_ledger_binding(inspection)
    accounting = binder.build_accounting_classification(token)

    assert raw["status"] == "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED"
    assert raw["raw_output_rows"] == 3
    assert token["status"] == "BOUND_OUTPUT_NEW_TOKEN_LEDGER"
    assert token["subject_metrics"]["routed_13_lobe_kt_hat_compact"]["new_tokens_per_correct"] == 6.0
    assert accounting["status"] == "BOUND_OUTPUT_NEW_TOKENS_PER_CORRECT"
    assert accounting["g2_tokens_per_correct_formula"] == "sum(new_tokens) / correct_count"
    assert accounting["can_call_g2_full_system_compression"] is False


def test_full_g2_recovery_is_denied_without_prompt_runtime_and_scorer_state(tmp_path: Path) -> None:
    zip_path = tmp_path / "assessment.zip"
    _make_assessment_zip(zip_path)

    state = binder.build_state_vector_binding(binder.inspect_assessment_zip(zip_path))

    assert state["status"] == "IRRECOVERABLE_WITH_SEARCH_RECEIPT"
    assert state["exact_g2_state_vector_bound"] is False
    assert "g2_rendered_prompts" in state["irrecoverable_components"]
    assert "g2_scorer_parser_code" in state["irrecoverable_components"]
    assert state["g2_recovered_claim"] is False


def test_offline_replay_unlock_is_raw_output_only_not_runtime_generation(tmp_path: Path) -> None:
    zip_path = tmp_path / "assessment.zip"
    _make_assessment_zip(zip_path)

    inspection = binder.inspect_assessment_zip(zip_path)
    state = binder.build_state_vector_binding(inspection)
    raw = binder.build_raw_output_binding(inspection)
    unlock = binder.build_offline_unlock(raw, state)

    assert unlock["status"] == "UNLOCKED_FOR_BOUND_RAW_OUTPUTS_ONLY"
    assert unlock["offline_extraction_replay_allowed"] is True
    assert unlock["generation_allowed"] is False
    assert unlock["full_g2_recovery_allowed"] is False


def test_epc_selects_offline_replay_and_new_frontier_without_claim_expansion(tmp_path: Path) -> None:
    zip_path = tmp_path / "assessment.zip"
    _make_assessment_zip(zip_path)

    inspection = binder.inspect_assessment_zip(zip_path)
    state = binder.build_state_vector_binding(inspection)
    raw = binder.build_raw_output_binding(inspection)
    token = binder.build_token_ledger_binding(inspection)
    accounting = binder.build_accounting_classification(token)
    unlock = binder.build_offline_unlock(raw, state)
    epc = binder.build_epc_decision(state, raw, accounting, unlock)

    assert epc["status"] == "PASS"
    assert epc["next_lawful_move"] == "RUN_OFFLINE_G2_RAW_OUTPUT_EXTRACTION_REPLAY__DEFINE_NEW_STAGED_FRONTIER"
    assert epc["runtime_generation_authorized"] is False
    assert epc["training_authorized"] is False
    assert epc["promotion_authority"] is False
    assert epc["g2_recovered_claim"] is False
