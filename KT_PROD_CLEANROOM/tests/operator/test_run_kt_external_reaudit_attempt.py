from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import run_kt_external_reaudit_attempt as attempt
from tools.operator.titanium_common import repo_root


RUN_HEAD = "c" * 40
MAIN_HEAD = "5b6a82360d3c3e33a57126778801aee7f0de6ada"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_file(source_root: Path, tmp_path: Path, raw: str) -> None:
    source = source_root / raw
    if source.is_file():
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _copy_inputs(tmp_path: Path) -> None:
    source_root = repo_root()
    for raw in attempt.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = attempt.RUN_BRANCH,
    head: str = RUN_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(attempt, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(attempt.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(attempt.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(attempt.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        attempt,
        "validate_trust_zones",
        lambda *, root: {
            "schema_id": "trust",
            "status": trust_status,
            "failures": [] if trust_status == "PASS" else ["forced failure"],
            "checks": [{"status": trust_status}],
        },
    )


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    attempt.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def deferred_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("external_reaudit_attempt_deferred")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / attempt.OUTPUTS[role])


def _accepted_attestation() -> dict:
    return {
        "schema_id": "kt.external_reaudit.independent_attestation.v1",
        "attestation_status": "ACCEPTED",
        "external_reviewer_independent": True,
        "review_scope_includes_external_audit_packet": True,
        "review_scope_includes_public_verifier": True,
        "review_scope_includes_supply_chain": True,
        "review_scope_includes_claim_boundary": True,
        "claims_reviewed_against_claim_ceiling": True,
    }


def test_reason_codes_are_unique() -> None:
    assert len(attempt.REASON_CODES) == len(set(attempt.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(attempt.OUTPUTS.values()))
def test_outputs_exist(deferred_outputs: Path, raw: str) -> None:
    path = deferred_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "External re-audit attempt executed: true" in text
        assert "External audit completed: false" in text


def test_missing_external_attestation_defers_with_named_blocker(deferred_outputs: Path) -> None:
    receipt = _payload(deferred_outputs, "attempt_receipt")
    blockers = _payload(deferred_outputs, "blocker_ledger")
    assert receipt["selected_outcome"] == attempt.OUTCOME_DEFERRED
    assert receipt["next_lawful_move"] == attempt.NEXT_DEFERRED
    assert receipt["external_reaudit_attempt_executed"] is True
    assert receipt["external_reaudit_deferred"] is True
    assert blockers["blocker_count"] == 1
    assert blockers["blockers"][0]["blocker_id"] == "independent_external_reaudit_attestation_missing"


def test_deferred_attempt_preserves_claim_boundaries(deferred_outputs: Path) -> None:
    decision = _payload(deferred_outputs, "decision")
    assert decision["external_reaudit_accepted"] is False
    assert decision["external_audit_completed"] is False
    assert decision["commercial_claims_authorized"] is False
    assert decision["commercial_activation_claim_authorized"] is False
    assert decision["seven_b_amplification_claimed_proven"] is False
    assert decision["beyond_sota_claimed"] is False
    assert decision["s_tier_claimed"] is False


def test_accepted_attestation_selects_commercial_claim_authorization_next(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _write(tmp_path / attempt.OPTIONAL_EXTERNAL_ATTESTATION, _accepted_attestation())
    _patch_env(monkeypatch, tmp_path)
    attempt.run(output_root=tmp_path)
    receipt = _payload(tmp_path, "attempt_receipt")
    assert receipt["selected_outcome"] == attempt.OUTCOME_ACCEPTED
    assert receipt["next_lawful_move"] == attempt.NEXT_ACCEPTED
    assert receipt["external_reaudit_accepted"] is True
    assert receipt["commercial_claims_authorized"] is False


def test_rejects_previous_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / attempt.INPUTS["validation_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(attempt.LaneFailure) as excinfo:
        attempt.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_REAUDIT_PREVIOUS_OUTCOME_DRIFT"


def test_rejects_previous_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / attempt.INPUTS["validation_next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(attempt.LaneFailure) as excinfo:
        attempt.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_REAUDIT_PREVIOUS_NEXT_MOVE_DRIFT"


def test_rejects_public_verifier_status_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / attempt.INPUTS["public_verifier_manifest"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(attempt.LaneFailure) as excinfo:
        attempt.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED"


def test_rejects_commercial_claim_authorization_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / attempt.INPUTS["validation_receipt"]
    payload = _load(path)
    payload["commercial_claims_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(attempt.LaneFailure) as excinfo:
        attempt.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(attempt.LaneFailure) as excinfo:
        attempt.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_REAUDIT_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(attempt.LaneFailure) as excinfo:
        attempt.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_REAUDIT_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(attempt.LaneFailure) as excinfo:
        attempt.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_REAUDIT_TRUST_ZONE_FAILED"
