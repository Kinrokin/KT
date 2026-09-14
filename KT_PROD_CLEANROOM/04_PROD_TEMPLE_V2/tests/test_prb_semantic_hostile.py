from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from council.providers.provider_registry import ProviderRegistry
from council.providers.provider_resilience import LANE_LIVE_SEMANTIC, policy_for, reset_resilience_state_for_tests
from council.providers.provider_schemas import ProviderCallReceipt
from council.providers.semantic_response import admit_typed_message, typed_message_from_provider_response
from council.semantic_router import _prompt_for_request, _verify_compound_result
from core.semantic_probe import (
    EVENT_BINDING_KEYS,
    EVENT_ROOTS,
    PROBE_CONTRACT,
    REQUIRED_ARTIFACT_BINDINGS,
    SemanticProbeRecorder,
)
from memory.semantic_effect import consume_and_apply_with_rollback
from schemas.base_schema import SchemaValidationError
from schemas.semantic_vertical_schemas import (
    AdmittedMeaningSchema,
    MAX_PROVIDER_RESPONSE_BYTES,
    SemanticCouncilRequestSchema,
    SemanticVerticalError,
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _subject() -> dict[str, str]:
    return {
        "schema_id": "kt.semantic_subject.v1",
        "claim": "The bounded claim is supported.",
        "evidence": "Bounded evidence for the claim.",
    }


def _content(*, decision: str = "PASS", reason: str = "ACCEPT", subject: str = "a" * 64, nonce: str = "b" * 64) -> str:
    return _canonical_json(
        {
            "schema_id": "kt.semantic_meaning.v1",
            "decision": decision,
            "reason_code": reason,
            "subject_hash": subject,
            "nonce": nonce,
        }
    )


def _response(*, content: str | None = None, response_id: str = "provider-response-1") -> dict[str, Any]:
    return {
        "id": response_id,
        "model": "gpt-4.1-mini",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content if content is not None else _content()},
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
    }


def _typed(*, content: str | None = None, request_id: str = "c" * 64):
    raw = _canonical_json(_response(content=content)).encode("utf-8")
    return typed_message_from_provider_response(
        raw=raw,
        expected_model="gpt-4.1-mini",
        provider_id="openai",
        request_id=request_id,
        provider_request_id="provider-response-1",
    )


def _admitted(*, decision: str = "PASS", reason: str = "ACCEPT") -> AdmittedMeaningSchema:
    return admit_typed_message(
        message=_typed(content=_content(decision=decision, reason=reason)),
        expected_subject_hash="a" * 64,
        expected_nonce="b" * 64,
    )


def _valid_request() -> dict[str, Any]:
    subject = _subject()
    payload: dict[str, Any] = {
        "schema_id": SemanticCouncilRequestSchema.SCHEMA_ID,
        "schema_version_hash": SemanticCouncilRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "",
        "runtime_registry_hash": "1" * 64,
        "mode": "OFFLINE_PROOF",
        "provider_id": "openai",
        "adapter_id": "council.openai.live_semantic.v1",
        "request_type": "analysis",
        "model": "gpt-4.1-mini",
        "instruction": "Bounded semantic judgment.",
        "subject": subject,
        "subject_hash": hashlib.sha256(_canonical_json(subject).encode("utf-8")).hexdigest(),
        "nonce": "b" * 64,
        "max_output_tokens": 256,
        "timeout_ms": 2_000,
        "probe_enabled": True,
    }
    payload["request_id"] = SemanticCouncilRequestSchema.compute_request_id(payload)
    return payload


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.pop("id"),
        lambda p: p.update(id=""),
        lambda p: p.pop("usage"),
        lambda p: p["usage"].update(total_tokens=21),
        lambda p: p["choices"][0].update(finish_reason="length"),
        lambda p: p["choices"][0].update(unexpected=True),
        lambda p: p["choices"][0]["message"].update(refusal="denied"),
        lambda p: p.update(choices=[]),
        lambda p: p.update(choices="not-a-list"),
        lambda p: p.update(model=None),
    ],
)
def test_provider_transport_semantic_mutations_reject(mutation: Any) -> None:
    payload = _response()
    mutation(payload)
    with pytest.raises(SemanticVerticalError):
        typed_message_from_provider_response(
            raw=_canonical_json(payload).encode("utf-8"),
            expected_model="gpt-4.1-mini",
            provider_id="openai",
            request_id="c" * 64,
            provider_request_id="provider-response-1",
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff\xfe\xfd",
        b"[]",
        _canonical_json({"error": {"message": "bad"}}).encode("utf-8"),
        b"x" * (MAX_PROVIDER_RESPONSE_BYTES + 1),
    ],
)
def test_raw_response_boundary_mutations_reject(raw: bytes) -> None:
    with pytest.raises(SemanticVerticalError):
        typed_message_from_provider_response(
            raw=raw,
            expected_model="gpt-4.1-mini",
            provider_id="openai",
            request_id="c" * 64,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_id", "openrouter"),
        ("adapter_id", "council.openai.live_hashed.v1"),
        ("request_type", "healthcheck"),
        ("mode", "DRY_RUN"),
        ("probe_enabled", 1),
        ("max_output_tokens", 0),
        ("max_output_tokens", 513),
        ("timeout_ms", 0),
        ("timeout_ms", 20_001),
        ("subject_hash", "not-a-hash"),
        ("nonce", "0" * 63),
        ("model", ""),
    ],
)
def test_semantic_request_mutations_reject(field: str, value: Any) -> None:
    payload = _valid_request()
    payload[field] = value
    payload["request_id"] = SemanticCouncilRequestSchema.compute_request_id(payload)
    with pytest.raises(SchemaValidationError):
        SemanticCouncilRequestSchema.from_dict(payload)


def test_stale_request_hash_and_unknown_field_reject() -> None:
    stale = _valid_request()
    stale["instruction"] = "changed"
    with pytest.raises(SchemaValidationError):
        SemanticCouncilRequestSchema.from_dict(stale)
    unknown = _valid_request()
    unknown["effect_path"] = "/tmp/attacker"
    with pytest.raises(SchemaValidationError):
        SemanticCouncilRequestSchema.from_dict(unknown)


def test_subject_bytes_and_hash_are_cryptographically_bound() -> None:
    stale_subject = _valid_request()
    stale_subject["subject"]["evidence"] = "mutated evidence"
    stale_subject["request_id"] = SemanticCouncilRequestSchema.compute_request_id(stale_subject)
    with pytest.raises(SchemaValidationError, match="subject hash mismatch"):
        SemanticCouncilRequestSchema.from_dict(stale_subject)

    stale_hash = _valid_request()
    stale_hash["subject_hash"] = "0" * 64
    stale_hash["request_id"] = SemanticCouncilRequestSchema.compute_request_id(stale_hash)
    with pytest.raises(SchemaValidationError, match="subject hash mismatch"):
        SemanticCouncilRequestSchema.from_dict(stale_hash)


def test_prompt_contains_exact_subject_and_is_receipt_bound(tmp_path: Path) -> None:
    request, execution_id, receipt, _message, _raw = _offline_compound(tmp_path)
    prompt = _prompt_for_request(request)
    assert _canonical_json(request["subject"]) in prompt
    assert request["instruction"] in prompt
    assert receipt.to_dict()["trace_id"] == execution_id
    assert receipt.to_dict()["payload"]["prompt_sha256"] == "sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "extra_key",
    ["effect_path", "tool", "authority", "policy", "memory_action", "training_action", "claim"],
)
def test_model_cannot_name_effect_or_authority(extra_key: str) -> None:
    payload = json.loads(_content())
    payload[extra_key] = "attacker-controlled"
    message = _typed(content=_canonical_json(payload))
    with pytest.raises(SemanticVerticalError):
        admit_typed_message(message=message, expected_subject_hash="a" * 64, expected_nonce="b" * 64)


def test_json_whitespace_changes_content_identity_not_semantic_decision() -> None:
    compact = _admitted()
    spaced_content = json.dumps(json.loads(_content()), sort_keys=True, indent=2)
    spaced = admit_typed_message(
        message=_typed(content=spaced_content),
        expected_subject_hash="a" * 64,
        expected_nonce="b" * 64,
    )
    assert compact.to_dict()["content_hash"] != spaced.to_dict()["content_hash"]
    assert compact.to_dict()["meaning_hash"] == spaced.to_dict()["meaning_hash"]
    assert compact.to_dict()["decision_hash"] == spaced.to_dict()["decision_hash"]


@pytest.mark.parametrize(
    "content",
    [
        '{"schema_id":"kt.semantic_meaning.v1","decision":"FAIL","decision":"PASS","reason_code":"ACCEPT","subject_hash":"' + "a" * 64 + '","nonce":"' + "b" * 64 + '"}',
        '{"schema_id":"kt.semantic_meaning.v1","decision":"PASS","reason_code":"ACCEPT","subject_hash":"' + "a" * 64 + '","subject_hash":"' + "a" * 64 + '","nonce":"' + "b" * 64 + '"}',
        '{"schema_id":"kt.semantic_meaning.v1","decision":"PASS","reason_code":"ACCEPT","subject_hash":"' + "a" * 64 + '","nonce":"' + "b" * 64 + '","nonce":"' + "b" * 64 + '"}',
        '{"schema_id":"kt.semantic_meaning.v1","decision":"PASS","reason_code":"ACCEPT","subject_hash":"' + "a" * 64 + '","nonce":"' + "b" * 64 + '","x":NaN}',
    ],
)
def test_semantic_duplicate_keys_and_nonfinite_constants_reject(content: str) -> None:
    with pytest.raises(SemanticVerticalError):
        admit_typed_message(
            message=_typed(content=content),
            expected_subject_hash="a" * 64,
            expected_nonce="b" * 64,
        )


@pytest.mark.parametrize(
    "replacement",
    [
        ('"id":"provider-response-1"', '"id":"first","id":"provider-response-1"'),
        ('"model":"gpt-4.1-mini"', '"model":"wrong","model":"gpt-4.1-mini"'),
        ('"prompt_tokens":10', '"prompt_tokens":9,"prompt_tokens":10'),
        ('"total_tokens":20', '"total_tokens":NaN'),
    ],
)
def test_outer_provider_duplicate_keys_and_nonfinite_constants_reject(replacement: tuple[str, str]) -> None:
    raw = _canonical_json(_response()).replace(replacement[0], replacement[1], 1).encode("utf-8")
    with pytest.raises(SemanticVerticalError):
        typed_message_from_provider_response(
            raw=raw,
            expected_model="gpt-4.1-mini",
            provider_id="openai",
            request_id="c" * 64,
        )


def _offline_compound(tmp_path: Path):
    fixture = tmp_path / "response.json"
    raw = _canonical_json(_response()).encode("utf-8")
    fixture.write_bytes(raw)
    registry = ProviderRegistry.build_default()
    request = _valid_request()
    execution_id = "c" * 64
    receipt, message, returned_raw = registry.invoke_live_semantic(
        provider_id="openai",
        model="gpt-4.1-mini",
        prompt=_prompt_for_request(request),
        max_output_tokens=256,
        timeout_ms=2_000,
        temperature=0.0,
        kt_node_id="kt.prb.semantic.v1",
        trace_id=execution_id,
        offline_fixture_path=fixture,
    )
    return request, execution_id, receipt, message, returned_raw


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(receipt_hash="0" * 64),
        lambda r: r["payload"].update(response_bytes_sha256="sha256:" + "0" * 64),
        lambda r: r["payload"].update(response_bytes_len=1),
        lambda r: r["payload"].update(prompt_sha256="sha256:" + "0" * 64),
        lambda r: r["payload"].update(message_hash="0" * 64),
        lambda r: r["provider_attestation"].update(response_id_hash="sha256:" + "0" * 64),
        lambda r: r.update(usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}),
    ],
)
def test_compound_receipt_cross_link_mutations_reject(tmp_path: Path, mutation: Any) -> None:
    request, execution_id, receipt, message, raw = _offline_compound(tmp_path)
    payload = receipt.to_dict()
    mutation(payload)
    tampered = ProviderCallReceipt(data=payload)
    with pytest.raises(SemanticVerticalError):
        _verify_compound_result(
            request=request,
            execution_id=execution_id,
            receipt=tampered,
            message=message,
            raw_response=raw,
            offline=True,
        )


def test_semantic_effect_applies_once_restores_absence_and_rejects_reuse(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    first = consume_and_apply_with_rollback(
        artifact_root=root,
        admitted=_admitted(),
        semantic_request_id="d" * 64,
        execution_id="c" * 64,
    ).to_dict()
    target = root / "semantic_vertical" / "advisory_state.json"
    assert first["semantic_effects_applied"] == 1
    assert first["rollback_status"] == "RESTORED"
    assert not target.exists()
    assert first["receipt_hash"] == hashlib.sha256(
        _canonical_json({key: value for key, value in first.items() if key not in {"receipt_hash", "journal_hash", "result_envelope_hash"}}).encode("utf-8")
    ).hexdigest()
    with pytest.raises(SemanticVerticalError):
        consume_and_apply_with_rollback(
            artifact_root=root,
            admitted=_admitted(),
            semantic_request_id="d" * 64,
            execution_id="c" * 64,
        )


def test_effect_fault_after_apply_still_restores_absence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from memory import semantic_effect as module

    root = tmp_path / "fault-after-apply"
    root.mkdir()
    original = module._phase_journal

    def fail_applied(**kwargs: Any) -> str:
        if kwargs["phase"] == "APPLIED":
            raise OSError("injected journal failure")
        return original(**kwargs)

    monkeypatch.setattr(module, "_phase_journal", fail_applied)
    with pytest.raises(SemanticVerticalError, match="failed and was restored"):
        consume_and_apply_with_rollback(
            artifact_root=root,
            admitted=_admitted(),
            semantic_request_id="d" * 64,
            execution_id="c" * 64,
        )
    assert not (root / "semantic_vertical" / "advisory_state.json").exists()
    assert not list((root / "semantic_vertical" / "effect_receipts").glob("*.json"))


def test_effect_receipt_failure_after_rollback_cannot_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from memory import semantic_effect as module

    root = tmp_path / "receipt-failure"
    root.mkdir()
    original = module._atomic_write

    def fail_receipt(path: Path, data: bytes, *, transaction_id: str) -> None:
        if path.parent.name == "effect_receipts":
            raise OSError("injected receipt failure")
        original(path, data, transaction_id=transaction_id)

    monkeypatch.setattr(module, "_atomic_write", fail_receipt)
    with pytest.raises(OSError, match="injected receipt failure"):
        consume_and_apply_with_rollback(
            artifact_root=root,
            admitted=_admitted(),
            semantic_request_id="d" * 64,
            execution_id="c" * 64,
        )
    assert not (root / "semantic_vertical" / "advisory_state.json").exists()
    assert not list((root / "semantic_vertical" / "effect_receipts").glob("*.json"))


def test_tampered_effect_receipt_rejects_without_reapplying(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    first = consume_and_apply_with_rollback(
        artifact_root=root,
        admitted=_admitted(),
        semantic_request_id="d" * 64,
        execution_id="c" * 64,
    ).to_dict()
    receipt_path = root / "semantic_vertical" / "effect_receipts" / f"{first['effect_id']}.json"
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["post_state_hash"] = "0" * 64
    receipt_path.write_text(_canonical_json(payload), encoding="utf-8")
    with pytest.raises(SemanticVerticalError):
        consume_and_apply_with_rollback(
            artifact_root=root,
            admitted=_admitted(),
            semantic_request_id="d" * 64,
            execution_id="c" * 64,
        )
    assert not (root / "semantic_vertical" / "advisory_state.json").exists()


def test_symlink_artifact_root_and_target_reject(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(SemanticVerticalError):
        consume_and_apply_with_rollback(
            artifact_root=linked_root,
            admitted=_admitted(),
            semantic_request_id="d" * 64,
            execution_id="c" * 64,
        )

    semantic_root = real_root / "semantic_vertical"
    semantic_root.mkdir()
    external = tmp_path / "external.json"
    external.write_text("untouched", encoding="utf-8")
    (semantic_root / "advisory_state.json").symlink_to(external)
    with pytest.raises(SemanticVerticalError):
        consume_and_apply_with_rollback(
            artifact_root=real_root,
            admitted=_admitted(),
            semantic_request_id="d" * 64,
            execution_id="c" * 64,
        )
    assert external.read_text(encoding="utf-8") == "untouched"


def test_probe_missing_tampered_and_unknown_events_block_claim(tmp_path: Path) -> None:
    def bindings(request_id: str, execution_id: str, identity: str) -> dict[str, str]:
        result = {key: identity for key in REQUIRED_ARTIFACT_BINDINGS}
        result["semantic_request_id"] = request_id
        result["execution_id"] = execution_id
        return result

    root = tmp_path / "missing"
    root.mkdir()
    missing = SemanticProbeRecorder(
        artifact_root=root,
        request_id="d" * 64,
        execution_id="c" * 64,
        enabled=True,
    )
    missing.observe(PROBE_CONTRACT["required_events"][0], organ_root="kt", identity_hash="e" * 64)
    with pytest.raises(SemanticVerticalError):
        missing.finalize(runtime_roots=[
            "cognition", "core", "council", "curriculum", "governance", "kt", "memory",
            "multiverse", "paradox", "schemas", "temporal", "thermodynamics", "versioning",
        ], artifact_bindings=bindings("d" * 64, "c" * 64, "e" * 64), mode="OFFLINE_PROOF", provider_calls_total=0)
    with pytest.raises(SemanticVerticalError):
        missing.observe("unknown.event", organ_root="kt", identity_hash="e" * 64)

    tamper_root = tmp_path / "tamper"
    tamper_root.mkdir()
    recorder = SemanticProbeRecorder(
        artifact_root=tamper_root,
        request_id="f" * 64,
        execution_id="a" * 64,
        enabled=True,
    )
    for event in PROBE_CONTRACT["required_events"]:
        recorder.observe(event, organ_root=EVENT_ROOTS[event], identity_hash="1" * 64)
    ledger = recorder.run_artifact_root / "semantic_vertical" / "probe_ledger.jsonl"
    rows = ledger.read_text(encoding="utf-8").splitlines()
    rows[0] = rows[0].replace('"identity_hash":"1111', '"identity_hash":"2111', 1)
    ledger.write_text("\n".join(rows) + "\n", encoding="utf-8")
    with pytest.raises(SemanticVerticalError):
        recorder.finalize(runtime_roots=[
            "cognition", "core", "council", "curriculum", "governance", "kt", "memory",
            "multiverse", "paradox", "schemas", "temporal", "thermodynamics", "versioning",
        ], artifact_bindings=bindings("f" * 64, "a" * 64, "1" * 64), mode="OFFLINE_PROOF", provider_calls_total=0)


def test_probe_terminal_court_is_one_shot_and_cannot_overwrite_pass(tmp_path: Path) -> None:
    request_id = "d" * 64
    execution_id = "e" * 64
    root = tmp_path / "one-shot"
    root.mkdir()
    recorder = SemanticProbeRecorder(
        artifact_root=root,
        request_id=request_id,
        execution_id=execution_id,
        enabled=True,
    )
    bindings = {key: "1" * 64 for key in REQUIRED_ARTIFACT_BINDINGS}
    bindings["semantic_request_id"] = request_id
    bindings["execution_id"] = execution_id
    for event in PROBE_CONTRACT["required_events"]:
        recorder.observe(event, organ_root=EVENT_ROOTS[event], identity_hash=bindings[EVENT_BINDING_KEYS[event]])
    roots = [
        "cognition", "core", "council", "curriculum", "governance", "kt", "memory",
        "multiverse", "paradox", "schemas", "temporal", "thermodynamics", "versioning",
    ]
    first = recorder.finalize(
        runtime_roots=roots,
        artifact_bindings=bindings,
        mode="OFFLINE_PROOF",
        provider_calls_total=0,
    )
    receipt_path = recorder.run_artifact_root / "semantic_vertical" / "run_receipt.json"
    frozen = receipt_path.read_bytes()
    changed = dict(bindings)
    changed["manifest_hash"] = "2" * 64
    with pytest.raises(SemanticVerticalError, match="one-shot"):
        recorder.finalize(
            runtime_roots=roots,
            artifact_bindings=changed,
            mode="OFFLINE_PROOF",
            provider_calls_total=0,
        )
    assert receipt_path.read_bytes() == frozen
    assert first["run_receipt_hash"] == json.loads(frozen)["run_receipt_hash"]


def test_live_semantic_is_blocked_below_router_with_zero_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    from council.providers.live_provider_openai_hashed import LiveHashedOpenAIProvider

    reset_resilience_state_for_tests()
    assert policy_for(provider_id="openai", lane=LANE_LIVE_SEMANTIC).max_attempts == 1
    attempts = 0

    def fail_once(self: Any, **kwargs: Any):
        nonlocal attempts
        attempts += 1
        raise OSError("network fault")

    monkeypatch.setattr(LiveHashedOpenAIProvider, "invoke_semantic", fail_once)
    with pytest.raises(RuntimeError, match="NOT_AUTHORIZED"):
        ProviderRegistry.build_default().invoke_live_semantic(
            provider_id="openai",
            model="gpt-4.1-mini",
            prompt="bounded",
            max_output_tokens=256,
            timeout_ms=2_000,
            temperature=0.0,
            kt_node_id="kt.prb.semantic.v1",
            trace_id="9" * 64,
        )
    assert attempts == 0


def test_direct_live_provider_method_is_offline_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from council.providers.live_provider_openai_hashed import LiveHashedOpenAIProvider

    key_discoveries = 0

    def forbidden_keys(self: Any) -> list[str]:
        nonlocal key_discoveries
        key_discoveries += 1
        return ["secret"]

    monkeypatch.setattr(LiveHashedOpenAIProvider, "_discover_keys", forbidden_keys)
    with pytest.raises(RuntimeError, match="NOT_AUTHORIZED"):
        LiveHashedOpenAIProvider().invoke_semantic(
            model="gpt-4.1-mini",
            prompt="bounded",
            max_output_tokens=256,
            timeout_ms=2_000,
            temperature=0.0,
            kt_node_id="kt.prb.semantic.v1",
            trace_id="9" * 64,
            offline_fixture_path=None,
        )
    assert key_discoveries == 0
