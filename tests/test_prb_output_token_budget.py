from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest


CAP_ERROR = "provider completion tokens exceed request cap (fail-closed)"


@pytest.fixture
def frozen_helpers(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Reuse the original canonical fixture helpers without changing their file."""
    temple = Path(__file__).resolve().parents[1] / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2"
    monkeypatch.syspath_prepend(str(temple / "src"))
    helper_path = temple / "tests" / "test_prb_semantic_vertical.py"
    spec = importlib.util.spec_from_file_location("prb_token_budget_frozen_helpers", helper_path)
    assert spec is not None and spec.loader is not None
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    return helpers


def _case(
    tmp_path: Path,
    helpers: Any,
    monkeypatch: pytest.MonkeyPatch,
    completion_tokens: int,
) -> tuple[Path, Path, dict[str, str], str]:
    runtime_root = tmp_path / "runtime"
    artifact_root = runtime_root / "evidence"
    artifact_root.mkdir(parents=True)
    subject = helpers._subject("output-token-budget")
    nonce = "a" * 64
    content = helpers._meaning(
        decision="PASS",
        reason_code="ACCEPT",
        subject_hash=helpers._subject_hash(subject),
        nonce=nonce,
    )
    fixture = json.loads(helpers._provider_fixture(content=content))
    fixture["usage"] = {
        "prompt_tokens": 20,
        "completion_tokens": completion_tokens,
        "total_tokens": 20 + completion_tokens,
    }
    fixture_path = artifact_root / "transport_fixture.json"
    fixture_path.write_text(helpers._canonical_json(fixture), encoding="utf-8")
    monkeypatch.setenv("KT_PRB_OFFLINE_PROOF", "1")
    monkeypatch.setenv("KT_PRB_SEMANTIC_FIXTURE_PATH", str(fixture_path.resolve()))
    return runtime_root, artifact_root, subject, nonce


@pytest.mark.parametrize("completion_tokens", [20, 256])
def test_reported_output_within_cap_keeps_effect_and_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frozen_helpers: Any,
    completion_tokens: int,
) -> None:
    helpers = frozen_helpers
    runtime_root, artifact_root, subject, nonce = _case(
        tmp_path, helpers, monkeypatch, completion_tokens
    )
    with helpers._isolated_runtime(runtime_root) as (registry, entry, spine):
        request = helpers._request(
            registry_hash=spine._runtime_registry_hash(registry),
            subject=subject,
            nonce=nonce,
            probe_enabled=True,
        )
        assert request["max_output_tokens"] == 256
        result = entry.invoke(helpers._context(request=request, artifact_root=artifact_root))
    assert result["status"] == "OK"
    council = result["council"]
    assert council["decision"] == "PASS"
    assert council["semantic_effects_applied"] == 1
    assert council["rollback_status"] == "RESTORED"
    assert council["provider_calls_total"] == 0
    occurrence = artifact_root / "semantic_vertical" / "runs" / council["execution_id"]
    assert not (occurrence / "semantic_vertical" / "advisory_state.json").exists()
    from core.semantic_probe import verify_semantic_run

    verified = verify_semantic_run(
        run_artifact_root=occurrence,
        expected_run_receipt_hash=council["run_receipt_hash"],
    )
    assert verified["run_receipt_hash"] == council["run_receipt_hash"]


@pytest.mark.parametrize("completion_tokens", [257, 300])
def test_reported_output_above_cap_rejects_before_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frozen_helpers: Any,
    completion_tokens: int,
) -> None:
    helpers = frozen_helpers
    runtime_root, artifact_root, subject, nonce = _case(
        tmp_path, helpers, monkeypatch, completion_tokens
    )
    from memory import semantic_effect

    effect_calls: list[str] = []

    def forbidden_effect(**kwargs: Any) -> Any:
        effect_calls.append(kwargs["execution_id"])
        raise AssertionError("over-budget response reached the effect consumer")

    with helpers._isolated_runtime(runtime_root) as (registry, entry, spine):
        monkeypatch.setattr(semantic_effect, "consume_and_apply_with_rollback", forbidden_effect)
        request = helpers._request(
            registry_hash=spine._runtime_registry_hash(registry),
            subject=subject,
            nonce=nonce,
            probe_enabled=True,
        )
        assert request["max_output_tokens"] == 256
        result = entry.invoke(helpers._context(request=request, artifact_root=artifact_root))
        assert result["status"] == "FAIL"
        assert result["where"] == "spine_fn(context)"
        assert result["error"] == CAP_ERROR
    assert effect_calls == []
    for name in ("advisory_state.json", "effect_receipts", "rollback_receipts", ".effect.lock"):
        assert not list(artifact_root.rglob(name))
    assert not list(artifact_root.rglob("effect_journal.*.json"))
