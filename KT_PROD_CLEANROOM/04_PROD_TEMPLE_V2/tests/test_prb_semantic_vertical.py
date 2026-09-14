from __future__ import annotations

import importlib
import hashlib
import json
import os
import socket
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from core.import_truth_guard import ImportTruthGuard
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from core.runtime_registry import load_runtime_registry
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH


EXPECTED_APPLICABILITY = {
    "required": [
        "Entry Point",
        "Spine",
        "Schemas / Contracts",
        "Thermodynamics / Budget",
        "Council Router Engine",
        "Governance Kernel",
        "Receipts / Ledger",
    ],
    "expected_no_correlated_event": [
        "Crucible Engine",
        "Curriculum Boundary",
        "Multiverse Engine",
        "Paradox Engine",
        "Temporal Engine",
    ],
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _subject(label: str = "control") -> dict[str, str]:
    return {
        "schema_id": "kt.semantic_subject.v1",
        "claim": f"Claim {label} is supported.",
        "evidence": f"Bounded evidence for {label}.",
    }


def _subject_hash(subject: dict[str, str]) -> str:
    return hashlib.sha256(_canonical_json(subject).encode("utf-8")).hexdigest()


def _meaning(*, decision: str, reason_code: str, subject_hash: str, nonce: str) -> str:
    return _canonical_json(
        {
            "decision": decision,
            "nonce": nonce,
            "reason_code": reason_code,
            "schema_id": "kt.semantic_meaning.v1",
            "subject_hash": subject_hash,
        }
    )


def _provider_fixture(*, content: str, request_id: str = "fixture-request-1", model: str = "gpt-4.1-mini") -> bytes:
    return _canonical_json(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "index": 0,
                    "message": {"content": content, "role": "assistant"},
                }
            ],
            "created": 1,
            "id": request_id,
            "model": model,
            "object": "chat.completion",
            "usage": {"completion_tokens": 20, "prompt_tokens": 20, "total_tokens": 40},
        }
    ).encode("utf-8")


@contextmanager
def _isolated_runtime(temp_root: Path) -> Iterator[tuple[Any, Any, Any]]:
    from core import runtime_registry as rr

    registry = load_runtime_registry()
    original_repo_root = rr._v2_repo_root
    original_loader = rr.load_runtime_registry
    rr._v2_repo_root = lambda: temp_root  # type: ignore[assignment]
    rr.load_runtime_registry = lambda: registry  # type: ignore[assignment]

    entry = importlib.import_module("kt.entrypoint")
    spine = importlib.import_module("core.spine")
    original_entry_loader = entry.load_runtime_registry
    original_spine_loader = spine.load_runtime_registry
    entry.load_runtime_registry = lambda: registry  # type: ignore[assignment]
    spine.load_runtime_registry = lambda: registry  # type: ignore[assignment]
    try:
        yield registry, entry, spine
    finally:
        entry.load_runtime_registry = original_entry_loader  # type: ignore[assignment]
        spine.load_runtime_registry = original_spine_loader  # type: ignore[assignment]
        rr.load_runtime_registry = original_loader  # type: ignore[assignment]
        rr._v2_repo_root = original_repo_root  # type: ignore[assignment]
        ImportTruthGuard.uninstall_for_tests()


def _request(*, registry_hash: str, subject: dict[str, str], nonce: str, probe_enabled: bool) -> dict[str, Any]:
    from schemas.semantic_vertical_schemas import SemanticCouncilRequestSchema

    payload = {
        "adapter_id": "council.openai.live_semantic.v1",
        "instruction": "Judge only whether the supplied bounded subject is supported.",
        "max_output_tokens": 256,
        "mode": "OFFLINE_PROOF",
        "model": "gpt-4.1-mini",
        "nonce": nonce,
        "probe_enabled": probe_enabled,
        "provider_id": "openai",
        "request_id": "",
        "request_type": "analysis",
        "runtime_registry_hash": registry_hash,
        "schema_id": SemanticCouncilRequestSchema.SCHEMA_ID,
        "schema_version_hash": SemanticCouncilRequestSchema.SCHEMA_VERSION_HASH,
        "subject": subject,
        "subject_hash": _subject_hash(subject),
        "timeout_ms": 2_000,
    }
    payload["request_id"] = SemanticCouncilRequestSchema.compute_request_id(payload)
    return payload


def _context(*, request: dict[str, Any], artifact_root: Path) -> dict[str, Any]:
    return {
        "artifact_root": str(artifact_root.resolve()),
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": _canonical_json(request)},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _run_offline(
    *,
    temp_root: Path,
    content: str,
    subject: dict[str, str],
    nonce: str,
    probe_enabled: bool = True,
    provider_request_id: str = "fixture-request-1",
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    artifact_root = temp_root / "evidence"
    artifact_root.mkdir(parents=True, exist_ok=True)
    fixture_path = artifact_root / "transport_fixture.json"
    fixture_path.write_bytes(_provider_fixture(content=content, request_id=provider_request_id))
    os.environ["KT_PRB_OFFLINE_PROOF"] = "1"
    os.environ["KT_PRB_SEMANTIC_FIXTURE_PATH"] = str(fixture_path.resolve())
    try:
        with _isolated_runtime(temp_root) as (registry, entry, spine):
            request = _request(
                registry_hash=spine._runtime_registry_hash(registry),
                subject=subject,
                nonce=nonce,
                probe_enabled=probe_enabled,
            )
            result = entry.invoke(_context(request=request, artifact_root=artifact_root))
    finally:
        os.environ.pop("KT_PRB_OFFLINE_PROOF", None)
        os.environ.pop("KT_PRB_SEMANTIC_FIXTURE_PATH", None)
    return result, artifact_root, request


def _functional_projection(result: dict[str, Any]) -> dict[str, Any]:
    council = result["council"]
    return {
        "status": council["status"],
        "decision": council["decision"],
        "reason_code": council["reason_code"],
        "decision_hash": council["decision_hash"],
        "post_state_hash": council["post_state_hash"],
        "rollback_status": council["rollback_status"],
    }


def test_offline_paired_meaning_changes_real_decision_and_reversible_effect(tmp_path: Path) -> None:
    subject = _subject("paired")
    subject_hash = _subject_hash(subject)
    nonce = "b" * 64
    allow, allow_root, _ = _run_offline(
        temp_root=tmp_path / "allow",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    deny, deny_root, _ = _run_offline(
        temp_root=tmp_path / "deny",
        content=_meaning(decision="FAIL", reason_code="REJECT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )

    assert allow["status"] == deny["status"] == "OK"
    assert allow["council"]["decision"] == "PASS"
    assert deny["council"]["decision"] == "FAIL"
    assert allow["council"]["decision_hash"] != deny["council"]["decision_hash"]
    assert allow["council"]["post_state_hash"] != deny["council"]["post_state_hash"]
    assert allow["council"]["semantic_effects_applied"] == 1
    assert deny["council"]["semantic_effects_applied"] == 1
    assert allow["council"]["rollback_status"] == deny["council"]["rollback_status"] == "RESTORED"
    assert allow["council"]["provider_calls_total"] == deny["council"]["provider_calls_total"] == 0
    allow_occurrence_root = allow_root / "semantic_vertical" / "runs" / allow["council"]["execution_id"]
    deny_occurrence_root = deny_root / "semantic_vertical" / "runs" / deny["council"]["execution_id"]
    allow_run = allow_occurrence_root / "semantic_vertical"
    deny_run = deny_occurrence_root / "semantic_vertical"
    assert (allow_run / "effect_receipts").is_dir()
    assert (deny_run / "effect_receipts").is_dir()
    from core.semantic_probe import verify_semantic_run

    assert verify_semantic_run(
        run_artifact_root=allow_occurrence_root,
        expected_run_receipt_hash=allow["council"]["run_receipt_hash"],
    )["run_receipt_hash"] == allow["council"]["run_receipt_hash"]
    assert verify_semantic_run(
        run_artifact_root=deny_occurrence_root,
        expected_run_receipt_hash=deny["council"]["run_receipt_hash"],
    )["run_receipt_hash"] == deny["council"]["run_receipt_hash"]
    assert "kt.semantic_meaning.v1" not in _canonical_json(allow)
    assert "kt.semantic_meaning.v1" not in _canonical_json(deny)


def test_irrelevant_transport_metadata_does_not_change_decision_or_effect(tmp_path: Path) -> None:
    subject = _subject("metadata")
    subject_hash = _subject_hash(subject)
    nonce = "d" * 64
    content = _meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce)
    first, _, _ = _run_offline(
        temp_root=tmp_path / "first",
        content=content,
        subject=subject,
        nonce=nonce,
        provider_request_id="transport-a",
    )
    second, _, _ = _run_offline(
        temp_root=tmp_path / "second",
        content=content,
        subject=subject,
        nonce=nonce,
        provider_request_id="transport-b",
    )
    assert _functional_projection(first) == _functional_projection(second)


def test_probe_on_off_is_functionally_identical_and_coverage_is_frozen(tmp_path: Path) -> None:
    subject = _subject("probe")
    subject_hash = _subject_hash(subject)
    nonce = "f" * 64
    content = _meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce)
    enabled, enabled_root, _ = _run_offline(
        temp_root=tmp_path / "enabled",
        content=content,
        subject=subject,
        nonce=nonce,
        probe_enabled=True,
    )
    disabled, disabled_root, _ = _run_offline(
        temp_root=tmp_path / "disabled",
        content=content,
        subject=subject,
        nonce=nonce,
        probe_enabled=False,
    )
    assert _functional_projection(enabled) == _functional_projection(disabled)
    enabled_run = enabled_root / "semantic_vertical" / "runs" / enabled["council"]["execution_id"] / "semantic_vertical"
    disabled_run = disabled_root / "semantic_vertical" / "runs" / disabled["council"]["execution_id"] / "semantic_vertical"
    assert (enabled_run / "probe_ledger.jsonl").is_file()
    assert not (disabled_run / "probe_ledger.jsonl").exists()
    coverage = json.loads((enabled_run / "coverage.json").read_text(encoding="utf-8"))
    assert coverage["applicability"] == EXPECTED_APPLICABILITY
    assert coverage["missing_required"] == []
    assert coverage["unexpected_correlated"] == []
    assert coverage["unknown_correlated"] == []
    assert enabled["council"]["proof_status"] == "PASS_OFFLINE_CORRELATED_PROBE"
    assert disabled["council"]["proof_status"] == "FUNCTIONAL_ONLY_NO_PROBE_CLAIM"


def test_external_run_verifier_rejects_tampered_terminal_artifact(tmp_path: Path) -> None:
    from core.semantic_probe import verify_semantic_run
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    subject = _subject("verifier-tamper")
    subject_hash = _subject_hash(subject)
    nonce = "0" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "verifier-tamper",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    verify_semantic_run(
        run_artifact_root=run_root,
        expected_run_receipt_hash=result["council"]["run_receipt_hash"],
    )
    terminal_path = run_root / "semantic_vertical" / "terminal_evidence.json"
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    terminal["primary_bindings"]["routing_record_hash"] = "0" * 64
    terminal_path.write_text(_canonical_json(terminal), encoding="utf-8")
    with pytest.raises(SemanticVerticalError):
        verify_semantic_run(
            run_artifact_root=run_root,
            expected_run_receipt_hash=result["council"]["run_receipt_hash"],
        )


def test_external_run_verifier_rejects_relative_first_component_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.semantic_probe import verify_semantic_run
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    subject = _subject("relative-symlink")
    subject_hash = _subject_hash(subject)
    nonce = "0" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "relative-symlink",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    link_parent = tmp_path / "link-parent"
    link_parent.mkdir()
    (link_parent / "hostile-link").symlink_to(run_root, target_is_directory=True)
    monkeypatch.chdir(link_parent)
    with pytest.raises(SemanticVerticalError, match="must be absolute"):
        verify_semantic_run(
            run_artifact_root=Path("hostile-link"),
            expected_run_receipt_hash=result["council"]["run_receipt_hash"],
        )


def test_external_run_verifier_rejects_evidence_file_symlink(tmp_path: Path) -> None:
    from core.semantic_probe import verify_semantic_run
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    subject = _subject("evidence-file-symlink")
    subject_hash = _subject_hash(subject)
    nonce = "6" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "evidence-file-symlink",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    receipt_path = run_root / "semantic_vertical" / "run_receipt.json"
    moved_receipt = tmp_path / "moved-run-receipt.json"
    receipt_path.replace(moved_receipt)
    receipt_path.symlink_to(moved_receipt)
    with pytest.raises(SemanticVerticalError, match="link/reparse"):
        verify_semantic_run(
            run_artifact_root=run_root,
            expected_run_receipt_hash=result["council"]["run_receipt_hash"],
        )


def test_external_run_verifier_rejects_rehashed_claim_escalation(tmp_path: Path) -> None:
    from core.semantic_probe import verify_semantic_run
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    subject = _subject("claim-escalation")
    subject_hash = _subject_hash(subject)
    nonce = "1" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "claim-escalation",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    receipt_path = run_root / "semantic_vertical" / "run_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["claim_ceiling"] = "WHOLE_KT_LIVE_AND_SUBJECT_TRUTH_PROVEN"
    receipt["run_receipt_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in receipt.items() if key != "run_receipt_hash"}).encode("utf-8")
    ).hexdigest()
    receipt_path.write_text(_canonical_json(receipt), encoding="utf-8")
    with pytest.raises(SemanticVerticalError, match="authority/status/ceiling"):
        verify_semantic_run(
            run_artifact_root=run_root,
            expected_run_receipt_hash=receipt["run_receipt_hash"],
        )


def test_external_run_verifier_rejects_false_for_zero_provider_calls(tmp_path: Path) -> None:
    from core.semantic_probe import verify_semantic_run
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    subject = _subject("bool-zero")
    subject_hash = _subject_hash(subject)
    nonce = "9" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "bool-zero",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    receipt_path = run_root / "semantic_vertical" / "run_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["provider_calls_total"] = False
    receipt["run_receipt_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in receipt.items() if key != "run_receipt_hash"}).encode("utf-8")
    ).hexdigest()
    receipt_path.write_text(_canonical_json(receipt), encoding="utf-8")
    with pytest.raises(SemanticVerticalError, match="authority/status/ceiling"):
        verify_semantic_run(
            run_artifact_root=run_root,
            expected_run_receipt_hash=receipt["run_receipt_hash"],
        )


def test_external_run_verifier_rejects_true_for_one_semantic_effect(tmp_path: Path) -> None:
    from core.semantic_probe import verify_semantic_run
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    subject = _subject("bool-one")
    subject_hash = _subject_hash(subject)
    nonce = "a" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "bool-one",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    semantic_root = run_root / "semantic_vertical"
    run_path = semantic_root / "run_receipt.json"
    run_receipt = json.loads(run_path.read_text(encoding="utf-8"))
    effect_id = run_receipt["artifact_bindings"]["effect_id"]

    effect_path = semantic_root / "effect_receipts" / f"{effect_id}.json"
    effect = json.loads(effect_path.read_text(encoding="utf-8"))
    effect["semantic_effects_applied"] = True
    effect["receipt_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in effect.items() if key != "receipt_hash"}).encode("utf-8")
    ).hexdigest()
    effect_path.write_text(_canonical_json(effect), encoding="utf-8")

    journal_path = semantic_root / f"effect_journal.{effect_id}.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["effect_receipt_hash"] = effect["receipt_hash"]
    journal["journal_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in journal.items() if key != "journal_hash"}).encode("utf-8")
    ).hexdigest()
    journal_path.write_text(_canonical_json(journal), encoding="utf-8")

    terminal_path = semantic_root / "terminal_evidence.json"
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    terminal["primary_bindings"]["effect_receipt_hash"] = effect["receipt_hash"]
    terminal["primary_bindings"]["effect_journal_hash"] = journal["journal_hash"]
    terminal["terminal_evidence_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in terminal.items() if key != "terminal_evidence_hash"}).encode("utf-8")
    ).hexdigest()
    terminal_path.write_text(_canonical_json(terminal), encoding="utf-8")

    run_receipt["artifact_bindings"]["effect_receipt_hash"] = effect["receipt_hash"]
    run_receipt["artifact_bindings"]["effect_journal_hash"] = journal["journal_hash"]
    run_receipt["artifact_bindings"]["terminal_evidence_hash"] = terminal["terminal_evidence_hash"]
    run_receipt["run_receipt_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in run_receipt.items() if key != "run_receipt_hash"}).encode("utf-8")
    ).hexdigest()
    run_path.write_text(_canonical_json(run_receipt), encoding="utf-8")
    with pytest.raises(SemanticVerticalError, match="effect/rollback"):
        verify_semantic_run(
            run_artifact_root=run_root,
            expected_run_receipt_hash=run_receipt["run_receipt_hash"],
        )


def test_external_run_verifier_rejects_rehashed_terminal_ceiling_escalation(tmp_path: Path) -> None:
    from core.semantic_probe import verify_semantic_run
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    subject = _subject("terminal-escalation")
    subject_hash = _subject_hash(subject)
    nonce = "3" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "terminal-escalation",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    semantic_root = run_root / "semantic_vertical"
    terminal_path = semantic_root / "terminal_evidence.json"
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    terminal["semantic_truth_ceiling"] = "SUBJECT_TRUTH_AND_MODEL_ACCURACY_PROVEN"
    terminal["terminal_evidence_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in terminal.items() if key != "terminal_evidence_hash"}).encode("utf-8")
    ).hexdigest()
    terminal_path.write_text(_canonical_json(terminal), encoding="utf-8")

    receipt_path = semantic_root / "run_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["artifact_bindings"]["terminal_evidence_hash"] = terminal["terminal_evidence_hash"]
    receipt["run_receipt_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in receipt.items() if key != "run_receipt_hash"}).encode("utf-8")
    ).hexdigest()
    receipt_path.write_text(_canonical_json(receipt), encoding="utf-8")
    with pytest.raises(SemanticVerticalError, match="status/ceiling"):
        verify_semantic_run(
            run_artifact_root=run_root,
            expected_run_receipt_hash=receipt["run_receipt_hash"],
        )


def test_external_run_verifier_rejects_rehashed_raw_typed_splice(tmp_path: Path) -> None:
    from core.semantic_probe import verify_semantic_run
    from council.providers.semantic_response import admit_typed_message
    from schemas.semantic_vertical_schemas import (
        SemanticVerticalError,
        TypedProviderMessageSchema,
    )

    subject = _subject("raw-typed-splice")
    subject_hash = _subject_hash(subject)
    nonce = "5" * 64
    result, artifact_root, _ = _run_offline(
        temp_root=tmp_path / "raw-typed-splice",
        content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce),
        subject=subject,
        nonce=nonce,
    )
    run_root = artifact_root / "semantic_vertical" / "runs" / result["council"]["execution_id"]
    semantic_root = run_root / "semantic_vertical"
    transcript_path = semantic_root / "transcript.json"
    transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    typed = dict(transcript["typed_message"])
    typed["content"] = _meaning(
        decision="FAIL",
        reason_code="REJECT",
        subject_hash=subject_hash,
        nonce=nonce,
    )
    typed["content_hash"] = hashlib.sha256(typed["content"].encode("utf-8")).hexdigest()
    typed["message_hash"] = TypedProviderMessageSchema.compute_message_hash(typed)
    typed_schema = TypedProviderMessageSchema.from_dict(typed)
    admitted = admit_typed_message(
        message=typed_schema,
        expected_subject_hash=subject_hash,
        expected_nonce=nonce,
    ).to_dict()
    transcript["typed_message"] = typed
    transcript["admitted_meaning"] = admitted
    transcript["output_identities"].update(
        delivered=typed["message_hash"],
        scored=admitted["meaning_hash"],
        consumed=admitted["decision_hash"],
    )
    transcript["transcript_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in transcript.items() if key != "transcript_hash"}).encode("utf-8")
    ).hexdigest()
    transcript_path.write_text(_canonical_json(transcript), encoding="utf-8")

    terminal_path = semantic_root / "terminal_evidence.json"
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    terminal["primary_bindings"]["transcript_hash"] = transcript["transcript_hash"]
    terminal["terminal_evidence_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in terminal.items() if key != "terminal_evidence_hash"}).encode("utf-8")
    ).hexdigest()
    terminal_path.write_text(_canonical_json(terminal), encoding="utf-8")

    receipt_path = semantic_root / "run_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["artifact_bindings"]["transcript_hash"] = transcript["transcript_hash"]
    receipt["artifact_bindings"]["terminal_evidence_hash"] = terminal["terminal_evidence_hash"]
    receipt["run_receipt_hash"] = hashlib.sha256(
        _canonical_json({key: value for key, value in receipt.items() if key != "run_receipt_hash"}).encode("utf-8")
    ).hexdigest()
    receipt_path.write_text(_canonical_json(receipt), encoding="utf-8")
    with pytest.raises(SemanticVerticalError, match="splice"):
        verify_semantic_run(
            run_artifact_root=run_root,
            expected_run_receipt_hash=receipt["run_receipt_hash"],
        )


def test_repeated_logical_request_gets_exclusive_execution_roots(tmp_path: Path) -> None:
    subject = _subject("repeat")
    subject_hash = _subject_hash(subject)
    nonce = "2" * 64
    content = _meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce)
    root = tmp_path / "duplicate"
    first, _, _ = _run_offline(temp_root=root, content=content, subject=subject, nonce=nonce)
    second, _, _ = _run_offline(temp_root=root, content=content, subject=subject, nonce=nonce)
    assert first["council"]["semantic_effects_applied"] == 1
    assert second["council"]["semantic_effects_applied"] == 1
    assert first["council"]["execution_id"] != second["council"]["execution_id"]
    assert first["council"]["occurrence_hash"] != second["council"]["occurrence_hash"]
    assert first["council"]["routing_record_hash"] != second["council"]["routing_record_hash"]


def test_probe_sink_failure_holds_before_semantic_effect(tmp_path: Path) -> None:
    subject = _subject("probe-failure")
    subject_hash = _subject_hash(subject)
    nonce = "4" * 64
    artifact_root = tmp_path / "probe-failure" / "evidence"
    artifact_root.mkdir(parents=True)
    (artifact_root / "semantic_vertical").write_text("not-a-directory", encoding="utf-8")
    fixture_path = artifact_root / "transport_fixture.json"
    fixture_path.write_bytes(
        _provider_fixture(content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce))
    )
    os.environ["KT_PRB_OFFLINE_PROOF"] = "1"
    os.environ["KT_PRB_SEMANTIC_FIXTURE_PATH"] = str(fixture_path.resolve())
    try:
        with _isolated_runtime(tmp_path / "probe-failure") as (registry, entry, spine):
            request = _request(
                registry_hash=spine._runtime_registry_hash(registry),
                subject=subject,
                nonce=nonce,
                probe_enabled=True,
            )
            result = entry.invoke(_context(request=request, artifact_root=artifact_root))
    finally:
        os.environ.pop("KT_PRB_OFFLINE_PROOF", None)
        os.environ.pop("KT_PRB_SEMANTIC_FIXTURE_PATH", None)
    assert result["status"] == "FAIL"
    assert not (artifact_root / "governance_verdict.json").exists()


@pytest.mark.parametrize(
    "mutator",
    [
        lambda obj: {k: v for k, v in obj.items() if k != "choices"},
        lambda obj: {**obj, "choices": obj["choices"] * 2},
        lambda obj: {**obj, "choices": [{**obj["choices"][0], "message": {"role": "user", "content": "{}"}}]},
        lambda obj: {**obj, "choices": [{**obj["choices"][0], "message": {"role": "assistant", "content": ""}}]},
        lambda obj: {**obj, "choices": [{**obj["choices"][0], "message": {"role": "assistant", "tool_calls": []}}]},
        lambda obj: {**obj, "choices": [{**obj["choices"][0], "message": {"role": "assistant", "content": "```json\n{}\n```"}}]},
        lambda obj: {**obj, "model": "unexpected-model"},
    ],
)
def test_provider_message_shape_mutations_fail_closed(mutator: Any) -> None:
    from council.semantic_router import typed_message_from_provider_response
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    content = _meaning(decision="PASS", reason_code="ACCEPT", subject_hash="5" * 64, nonce="6" * 64)
    base = json.loads(_provider_fixture(content=content).decode("utf-8"))
    raw = _canonical_json(mutator(base)).encode("utf-8")
    with pytest.raises(SemanticVerticalError):
        typed_message_from_provider_response(
            raw=raw,
            expected_model="gpt-4.1-mini",
            provider_id="openai",
            request_id="7" * 64,
            provider_request_id="fixture-request-1",
        )


@pytest.mark.parametrize(
    "content",
    [
        "not-json",
        "```json\n{}\n```",
        _canonical_json({"schema_id": "kt.semantic_meaning.v1", "decision": "MAYBE", "reason_code": "ACCEPT", "subject_hash": "8" * 64, "nonce": "9" * 64}),
        _canonical_json({"schema_id": "kt.semantic_meaning.v1", "decision": "PASS", "reason_code": "ACCEPT", "subject_hash": "8" * 64, "nonce": "9" * 64, "extra": True}),
        _canonical_json({"schema_id": "kt.semantic_meaning.v1", "decision": "PASS", "reason_code": "ACCEPT", "subject_hash": "0" * 64, "nonce": "9" * 64}),
        _canonical_json({"schema_id": "kt.semantic_meaning.v1", "decision": "PASS", "reason_code": "ACCEPT", "subject_hash": "8" * 64, "nonce": "0" * 64}),
    ],
)
def test_semantic_admission_mutations_fail_closed(content: str) -> None:
    from council.semantic_router import admit_typed_message, typed_message_from_provider_response
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    raw = _provider_fixture(content=content)
    with pytest.raises(SemanticVerticalError):
        message = typed_message_from_provider_response(
            raw=raw,
            expected_model="gpt-4.1-mini",
            provider_id="openai",
            request_id="a" * 64,
            provider_request_id="fixture-request-1",
        )
        admit_typed_message(message=message, expected_subject_hash="8" * 64, expected_nonce="9" * 64)


def test_live_mode_cannot_use_offline_fixture_or_reach_network(tmp_path: Path) -> None:
    from schemas.semantic_vertical_schemas import SemanticCouncilRequestSchema

    network_attempts = 0
    original_socket = socket.socket

    def blocked_socket(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal network_attempts
        network_attempts += 1
        raise AssertionError("network attempted")

    artifact_root = tmp_path / "live-refusal" / "evidence"
    artifact_root.mkdir(parents=True)
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_SEMANTIC"
    socket.socket = blocked_socket  # type: ignore[assignment]
    try:
        with _isolated_runtime(tmp_path / "live-refusal") as (registry, entry, spine):
            request = _request(
                registry_hash=spine._runtime_registry_hash(registry),
                subject=_subject("live-refusal"),
                nonce="c" * 64,
                probe_enabled=True,
            )
            request["mode"] = "LIVE_REQUESTED"
            request["request_id"] = SemanticCouncilRequestSchema.compute_request_id(request)
            result = entry.invoke(_context(request=request, artifact_root=artifact_root))
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        os.environ.pop("KT_PROVIDERS_ENABLED", None)
        os.environ.pop("KT_EXECUTION_LANE", None)
    assert result["status"] == "FAIL"
    assert network_attempts == 0
    assert not (artifact_root / "governance_verdict.json").exists()
    assert not (artifact_root / "semantic_vertical").exists()


def test_direct_semantic_spine_cannot_counterfeit_canonical_entry(tmp_path: Path) -> None:
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    artifact_root = tmp_path / "direct" / "evidence"
    artifact_root.mkdir(parents=True)
    with _isolated_runtime(tmp_path / "direct") as (registry, _entry, spine):
        request = _request(
            registry_hash=spine._runtime_registry_hash(registry),
            subject=_subject("direct"),
            nonce="d" * 64,
            probe_enabled=True,
        )
        with pytest.raises(SemanticVerticalError, match="requires kt.entrypoint.invoke"):
            spine.run(_context(request=request, artifact_root=artifact_root))
    assert not (artifact_root / "semantic_vertical").exists()


def test_direct_caller_cannot_mint_canonical_entry_scope() -> None:
    from core import semantic_probe
    from schemas.semantic_vertical_schemas import SemanticVerticalError

    assert not hasattr(semantic_probe, "begin_canonical_entry_scope")
    with pytest.raises(SemanticVerticalError, match="only by kt.entrypoint.invoke"):
        semantic_probe._begin_canonical_entry_scope({"schema_id": "forged"})

    forged_globals: dict[str, Any] = {
        "__name__": "kt.entrypoint",
        "_begin": semantic_probe._begin_canonical_entry_scope,
    }
    exec("def invoke(context):\n    return _begin(context)", forged_globals)
    with pytest.raises(SemanticVerticalError, match="only by kt.entrypoint.invoke"):
        forged_globals["invoke"]({"schema_id": "forged-lookalike"})


def test_canonical_entry_scope_resets_before_later_direct_spine_call(tmp_path: Path) -> None:
    subject = _subject("scope-reset")
    subject_hash = _subject_hash(subject)
    nonce = "e" * 64
    artifact_root = tmp_path / "scope-reset" / "evidence"
    artifact_root.mkdir(parents=True)
    fixture_path = artifact_root / "transport_fixture.json"
    fixture_path.write_bytes(
        _provider_fixture(
            content=_meaning(decision="PASS", reason_code="ACCEPT", subject_hash=subject_hash, nonce=nonce)
        )
    )
    os.environ["KT_PRB_OFFLINE_PROOF"] = "1"
    os.environ["KT_PRB_SEMANTIC_FIXTURE_PATH"] = str(fixture_path.resolve())
    try:
        with _isolated_runtime(tmp_path / "scope-reset") as (registry, entry, spine):
            request = _request(
                registry_hash=spine._runtime_registry_hash(registry),
                subject=subject,
                nonce=nonce,
                probe_enabled=True,
            )
            context = _context(request=request, artifact_root=artifact_root)
            assert entry.invoke(context)["status"] == "OK"
            with pytest.raises(Exception, match="requires kt.entrypoint.invoke"):
                spine.run(context)
    finally:
        os.environ.pop("KT_PRB_OFFLINE_PROOF", None)
        os.environ.pop("KT_PRB_SEMANTIC_FIXTURE_PATH", None)


def test_canonical_entry_attestation_rejects_context_mismatch(tmp_path: Path) -> None:
    from core.semantic_probe import require_canonical_entry_attestation

    artifact_root = tmp_path / "context-mismatch" / "evidence"
    artifact_root.mkdir(parents=True)
    with _isolated_runtime(tmp_path / "context-mismatch") as (registry, entry, spine):
        request = _request(
            registry_hash=spine._runtime_registry_hash(registry),
            subject=_subject("context-mismatch"),
            nonce="7" * 64,
            probe_enabled=True,
        )
        context = _context(request=request, artifact_root=artifact_root)
        original_run = spine.run

        def mismatched_run(_context_value: dict[str, Any]) -> dict[str, Any]:
            changed = dict(context)
            changed["envelope"] = {"input": "different"}
            require_canonical_entry_attestation(changed)
            return {"status": "UNREACHABLE"}

        spine.run = mismatched_run
        try:
            result = entry.invoke(context)
        finally:
            spine.run = original_run
    assert result["status"] == "FAIL"
    assert "context binding mismatch" in result["error"]


@pytest.mark.parametrize(
    ("original", "injected"),
    [
        (
            '"mode":"OFFLINE_PROOF"',
            '"mode":"LIVE_REQUESTED","mode":"OFFLINE_PROOF"',
        ),
        (
            '"schema_id":"council.semantic_request.v1"',
            '"schema_id":"council.request.v1","schema_id":"council.semantic_request.v1"',
        ),
    ],
)
def test_duplicate_semantic_request_keys_fail_before_dispatch(
    tmp_path: Path,
    original: str,
    injected: str,
) -> None:
    artifact_root = tmp_path / "duplicate-envelope" / "evidence"
    artifact_root.mkdir(parents=True)
    with _isolated_runtime(tmp_path / "duplicate-envelope") as (registry, entry, spine):
        request = _request(
            registry_hash=spine._runtime_registry_hash(registry),
            subject=_subject("duplicate-envelope"),
            nonce="8" * 64,
            probe_enabled=True,
        )
        raw_request = _canonical_json(request).replace(original, injected, 1)
        context = _context(request=request, artifact_root=artifact_root)
        context["envelope"]["input"] = raw_request
        result = entry.invoke(context)
    assert result["status"] == "FAIL"
    assert "Duplicate runtime-envelope JSON key" in result["error"]
    assert not (artifact_root / "semantic_vertical").exists()


def test_invalid_semantic_request_preserves_original_fail_closed_error(tmp_path: Path) -> None:
    artifact_root = tmp_path / "invalid" / "evidence"
    artifact_root.mkdir(parents=True)
    with _isolated_runtime(tmp_path / "invalid") as (registry, entry, spine):
        request = _request(
            registry_hash=spine._runtime_registry_hash(registry),
            subject=_subject("invalid"),
            nonce="f" * 64,
            probe_enabled=True,
        )
        request.pop("subject")
        result = entry.invoke(_context(request=request, artifact_root=artifact_root))
    assert result["status"] == "FAIL"
    assert "Missing required fields" in result["error"]
    assert "FrozenInstanceError" not in result["error"]
