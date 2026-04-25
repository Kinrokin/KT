from __future__ import annotations

from pathlib import Path

from tools.operator.c016b_live_provider_resilience_validate import build_c016b_live_provider_resilience_receipt


def test_c016b_receipt_passes_when_fault_matrix_is_repeatable(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "a" * 64)
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "b" * 64)

    def fake_load_c016a(root: Path) -> dict:
        return {
            "path_ref": "KT_PROD_CLEANROOM/reports/post_wave5_c016a_success_matrix.json",
            "status": "PASS",
            "successful_provider_ids": ["openai", "openrouter"],
        }

    def fake_run_matrix(root: Path) -> dict:
        row = {
            "scenario_id": "transient_timeout_retry_backoff_to_success",
            "status": "PASS",
            "provider_invocations": 2,
            "observed_backoff_ms": [15],
            "terminal_status": "OK",
        }
        return {
            "export_root_ref": "KT_PROD_CLEANROOM/exports/post_wave5_c016b_live_provider_resilience",
            "runtime_telemetry_ref": "KT_PROD_CLEANROOM/reports/post_wave5_c016b_runtime_telemetry.jsonl",
            "runs": [
                {"run_id": "run_a", "scenarios": [row]},
                {"run_id": "run_b", "scenarios": [dict(row)]},
            ],
            "repeatability_status": "PASS",
            "repeatability_reference": [row],
        }

    receipt = build_c016b_live_provider_resilience_receipt(
        root=tmp_path,
        load_c016a=fake_load_c016a,
        run_fault_matrix=fake_run_matrix,
    )
    assert receipt["status"] == "PASS"
    assert receipt["c016b_delta"] == "C016B_CLOSED_FOR_CANONICAL_LIVE_HASHED_RESILIENCE_PATH"
    assert receipt["scenario_failures"] == []
    assert len(receipt["signoffs"]) == 2


def test_c016b_receipt_fail_closes_when_c016a_precondition_is_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "a" * 64)
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "b" * 64)

    def fake_load_c016a(root: Path) -> dict:
        return {
            "path_ref": "KT_PROD_CLEANROOM/reports/post_wave5_c016a_success_matrix.json",
            "status": "FAIL",
            "successful_provider_ids": [],
        }

    receipt = build_c016b_live_provider_resilience_receipt(root=tmp_path, load_c016a=fake_load_c016a)
    assert receipt["status"] == "FAIL"
    assert receipt["c016b_delta"] == "C016B_NARROWED_TO_RESILIENCE_GAPS_WITH_RECEIPTED_FAULT_MATRIX"
    assert "C016A_SUCCESS_PRECONDITION_NOT_SATISFIED" in receipt["boundary_holds"]
