from __future__ import annotations

import json
from pathlib import Path

from tools.operator.c016a_live_provider_success_validate import build_c016a_live_provider_success_receipt


def _write_json(path: Path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, ensure_ascii=True), encoding="utf-8")
    return path.as_posix()


def test_c016a_receipt_passes_when_one_provider_succeeds(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-openrouter")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "a" * 64)
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "b" * 64)

    def fake_execute(payload: dict) -> dict:
        provider_id = payload["provider_id"]
        receipt_path = tmp_path / "exports" / provider_id / "provider_receipts" / f"{provider_id}.json"
        failure_path = tmp_path / "exports" / provider_id / "failure_artifacts" / f"{provider_id}.json"
        if provider_id == "openai":
            _write_json(
                receipt_path,
                {
                    "receipt_hash": "1" * 64,
                    "timing": {"latency_ms": 123},
                    "transport": {"http_status": 200},
                    "verdict": {"pass": True, "fail_reason": None},
                },
            )
            return {
                "adapter_id": "council.openai.live_hashed.v1",
                "provider_id": provider_id,
                "receipt_ref": receipt_path.as_posix(),
                "status": "OK",
            }
        _write_json(
            receipt_path,
            {
                "receipt_hash": "2" * 64,
                "timing": {"latency_ms": 222},
                "transport": {"http_status": 401},
                "verdict": {"pass": False, "fail_reason": "http_status=401"},
            },
        )
        _write_json(
            failure_path,
            {
                "failure_id": "3" * 64,
                "error_class": "ProviderVerdictFailClosed",
            },
        )
        return {
            "adapter_id": "council.openrouter.live_hashed.v1",
            "error": "http_status=401",
            "failure_artifact_ref": failure_path.as_posix(),
            "provider_id": provider_id,
            "receipt_ref": receipt_path.as_posix(),
            "status": "FAIL_CLOSED",
        }

    receipt = build_c016a_live_provider_success_receipt(root=tmp_path, execute_request=fake_execute)
    assert receipt["status"] == "PASS"
    assert receipt["successful_provider_count"] == 1
    assert receipt["c016a_delta"] == "C016A_CLOSED_FOR_CANONICAL_LIVE_HASHED_LANE"
    assert len(receipt["signoffs"]) == 2


def test_c016a_receipt_fail_closes_when_all_providers_fail(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "a" * 64)
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "b" * 64)

    def fake_execute(payload: dict) -> dict:
        provider_id = payload["provider_id"]
        receipt_path = tmp_path / "exports" / provider_id / "provider_receipts" / f"{provider_id}.json"
        failure_path = tmp_path / "exports" / provider_id / "failure_artifacts" / f"{provider_id}.json"
        _write_json(
            receipt_path,
            {
                "receipt_hash": "4" * 64,
                "timing": {"latency_ms": 321},
                "transport": {"http_status": 401},
                "verdict": {"pass": False, "fail_reason": "http_status=401"},
            },
        )
        _write_json(
            failure_path,
            {
                "failure_id": "5" * 64,
                "error_class": "ProviderVerdictFailClosed",
            },
        )
        return {
            "adapter_id": "council.openai.live_hashed.v1",
            "error": "http_status=401",
            "failure_artifact_ref": failure_path.as_posix(),
            "provider_id": provider_id,
            "receipt_ref": receipt_path.as_posix(),
            "status": "FAIL_CLOSED",
        }

    receipt = build_c016a_live_provider_success_receipt(root=tmp_path, execute_request=fake_execute)
    assert receipt["status"] == "FAIL"
    assert receipt["successful_provider_count"] == 0
    assert receipt["c016a_delta"] == "C016A_NARROWED_TO_UPSTREAM_AUTH_REJECTION_WITH_RECEIPTED_FAIL_CLOSED_ROWS"
    assert "AUTHENTICATED_LIVE_PROVIDER_SUCCESS_NOT_YET_PROVEN" in receipt["boundary_holds"]
