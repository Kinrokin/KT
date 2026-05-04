from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_afsh_shadow_screen_execution_packet as packet
from tools.operator import cohort0_b04_r6_afsh_shadow_screen_execution_packet_validation as validation


VALIDATION_HEAD = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
VALIDATION_MAIN_HEAD = "ffffffffffffffffffffffffffffffffffffffff"


def _load_packet_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_afsh_shadow_screen_execution_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_shadow_packet_test_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load packet test helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packet_helpers = _load_packet_helpers()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _patch_validation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    origin_main: str = VALIDATION_MAIN_HEAD,
) -> None:
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _write_packet_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = packet_helpers._run_packet(tmp_path, monkeypatch)
    return reports


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _write_packet_outputs(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_validation(tmp_path, monkeypatch)


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _packet_contract(outputs: Path) -> dict:
    return _load(outputs / packet.OUTPUTS["packet_contract"])


def _disqualifier_receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["disqualifier_validation"])


def _result_receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["result_interpretation_validation"])


def _replay_receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["replay_binding_validation"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _receipt(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    if filename.endswith(".md"):
        assert (outputs / filename).read_text(encoding="utf-8").strip()
    else:
        assert _load(outputs / filename)


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == validation.SELECTED_ARCHITECTURE_ID


def test_validation_binds_shadow_packet_contract(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["packet_contract_validation"])
    assert receipt["status"] == "PASS"
    assert receipt["packet_contract_hash"]


def test_validation_binds_shadow_packet_receipt(outputs: Path) -> None:
    assert _receipt(outputs)["packet_receipt_hash"]


def test_validation_binds_shadow_packet_report(outputs: Path) -> None:
    assert _receipt(outputs)["packet_report_hash"]


def test_candidate_binding_receipt_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["candidate_binding_validation"])["artifact_id"] == "B04_R6_AFSH_SHADOW_SCREEN_CANDIDATE_BINDING_VALIDATION_RECEIPT"


def test_candidate_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["candidate_artifact_hash"]) == 64


def test_candidate_manifest_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["candidate_manifest_hash"]) == 64


def test_candidate_semantic_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["candidate_semantic_hash"]) == 64


def test_validated_blind_universe_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["validated_blind_universe_hash"]) == 64


def test_validated_route_value_court_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["validated_court_hash"]) == 64


def test_validated_source_packet_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["validated_source_packet_hash"]) == 64


def test_admissibility_receipt_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["admissibility_receipt_hash"]) == 64


def test_numeric_triage_core_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["numeric_triage_emit_core_hash"]) == 64


def test_triage_tag_schema_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["triage_tag_schema_hash"]) == 64


def test_triage_score_schema_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["triage_score_schema_hash"]) == 64


def test_triage_receipt_schema_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["triage_receipt_schema_hash"]) == 64


def test_trace_schema_hash_bound(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["trace_schema_hash"]) == 64


def test_static_comparator_contract_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["static_comparator_validation"])["status"] == "PASS"


def test_static_comparator_is_frozen(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["static_comparator_contract"])["comparator_must_be_frozen"] is True


def test_static_comparator_weakening_forbidden(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["static_comparator_contract"])["comparator_weakening_forbidden"] is True


def test_metric_contract_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["metric_contract_validation"])["status"] == "PASS"


def test_metric_contract_is_frozen_before_execution(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["metric_contract"])["metrics_frozen_before_execution"] is True


def test_metric_widening_forbidden(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["metric_contract"])["metric_widening_forbidden"] is True


def test_route_value_contract_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["route_value_validation"])["status"] == "PASS"


@pytest.mark.parametrize("metric", packet.PRIMARY_METRICS)
def test_metric_contract_includes_primary_metrics(outputs: Path, metric: str) -> None:
    assert metric in _load(outputs / packet.OUTPUTS["metric_contract"])["primary_metrics"]


def test_disqualifier_ledger_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["disqualifier_validation"])["status"] == "PASS"


@pytest.mark.parametrize("name", packet.DISQUALIFIER_CLASSES)
def test_disqualifier_ledger_marks_hard_classes(outputs: Path, name: str) -> None:
    receipt = _disqualifier_receipt(outputs)
    assert name in receipt["hard_disqualifier_classes"]
    assert name in _load(outputs / packet.OUTPUTS["disqualifier_ledger"])["disqualifier_classes"]


@pytest.mark.parametrize("name", packet.TERMINAL_DISQUALIFIERS)
def test_disqualifier_ledger_marks_terminal_disqualifiers(outputs: Path, name: str) -> None:
    assert name in _load(outputs / packet.OUTPUTS["disqualifier_ledger"])["terminal_disqualifiers"]


def test_result_interpretation_contract_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["result_interpretation_validation"])["status"] == "PASS"


def test_result_interpretation_prevents_partial_win_from_superiority(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["result_interpretation_contract"])["partial_win_cannot_claim_superiority"] is True


def test_result_interpretation_requires_all_success_conditions(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["result_interpretation_contract"])["superiority_cannot_be_earned_unless_all_required_conditions_pass"] is True


def test_result_interpretation_preserves_failed_deferred_invalidated_outcomes(outputs: Path) -> None:
    outcomes = set(_result_receipt(outputs)["future_screen_allowed_outcomes"])
    assert "B04_R6_AFSH_SHADOW_SUPERIORITY_FAILED__SUPERIORITY_NOT_EARNED_CLOSEOUT_OR_REDESIGN_NEXT" in outcomes
    assert "B04_R6_AFSH_SHADOW_SCREEN_INVALIDATED__FORENSIC_INVALIDATION_COURT_NEXT" in outcomes


@pytest.mark.parametrize("condition", packet.SUCCESS_CONDITIONS)
def test_result_interpretation_requires_success_conditions(outputs: Path, condition: str) -> None:
    assert condition in _result_receipt(outputs)["required_success_conditions"]


def test_replay_manifest_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["replay_manifest_validation"])["status"] == "PASS"


def test_expected_artifact_manifest_exists(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["expected_artifact_validation"])["status"] == "PASS"


def test_external_verifier_requirements_exist(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["external_verifier_validation"])["status"] == "PASS"


def test_replay_manifest_includes_required_json_artifacts(outputs: Path) -> None:
    manifest = _load(outputs / packet.OUTPUTS["replay_manifest"])
    assert set(packet.INPUTS).issubset(set(manifest["expected_json_artifact_roles"]))


def test_replay_manifest_includes_required_text_artifacts(outputs: Path) -> None:
    manifest = _load(outputs / packet.OUTPUTS["replay_manifest"])
    assert set(packet.TEXT_INPUTS).issubset(set(manifest["expected_text_artifact_roles"]))


def test_replay_manifest_includes_admissibility_report(outputs: Path) -> None:
    assert "admissibility_report" in _load(outputs / packet.OUTPUTS["replay_manifest"])["expected_text_artifact_roles"]


def test_bound_file_hashes_come_from_single_input_bindings_path(outputs: Path) -> None:
    packet_contract = _packet_contract(outputs)
    by_role = {row["role"]: row["sha256"] for row in packet_contract["input_bindings"]}
    assert by_role["candidate_manifest"] == packet_contract["binding_hashes"]["candidate_manifest_hash"]
    assert by_role["numeric_triage_emit_core"] == packet_contract["binding_hashes"]["numeric_triage_emit_core_hash"]


def test_mixed_hash_binding_sources_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_packet_outputs(tmp_path, monkeypatch)
    manifest_path = reports / packet.OUTPUTS["replay_manifest"]
    payload = _load(manifest_path)
    payload["binding_hashes"]["candidate_manifest_hash"] = "0" * 64
    _write_json(manifest_path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        validation.run(reports_root=reports)


def test_packet_self_replay_handoff_allowed_without_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    result = validation.run(reports_root=reports)
    assert result["verdict"] == validation.SELECTED_OUTCOME
    assert _next(reports)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_mutable_next_lawful_move_handoff_bound_before_overwrite(outputs: Path) -> None:
    rows = [row for row in _replay_receipt(outputs)["input_bindings"] if row["role"] == "next_lawful_move"]
    assert len(rows) == 1
    assert rows[0]["binding_kind"] == "git_object_before_overwrite"
    assert rows[0]["mutable_canonical_path_overwritten_by_this_lane"] is True


def test_valid_prior_lane_authoritative_branch_artifacts_are_accepted(outputs: Path) -> None:
    assert _contract(outputs)["packet_replay_binding_head"] == packet_helpers.PACKET_BRANCH_HEAD


def test_invalid_prior_lane_branch_artifacts_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_packet_outputs(tmp_path, monkeypatch)
    contract_path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(contract_path)
    payload["current_git_head"] = "9" * 40
    _write_json(contract_path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        validation.run(reports_root=reports)


def test_external_verifier_requirements_are_non_executing(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["external_verifier_requirements"])["cannot_execute_shadow_screen"] is True


def test_external_verifier_requirements_do_not_claim_superiority(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["external_verifier_requirements"])["cannot_claim_superiority"] is True


def test_compressed_index_cannot_be_source_of_truth(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["external_verifier_requirements"])["compressed_index_cannot_be_source_of_truth"] is True


def test_raw_hash_bound_artifact_required_after_compressed_retrieval(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["external_verifier_validation"])["status"] == "PASS"


@pytest.mark.parametrize("role", validation.PREP_ONLY_PACKET_ROLES)
def test_prep_only_drafts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / packet.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_execute_shadow_screen"] is True


def test_validation_does_not_execute_shadow_screen(outputs: Path) -> None:
    assert _contract(outputs)["shadow_screen_executed"] is False


def test_validation_does_not_open_r6(outputs: Path) -> None:
    assert _contract(outputs)["r6_open"] is False


def test_validation_does_not_claim_superiority(outputs: Path) -> None:
    assert _contract(outputs)["learned_router_superiority_earned"] is False


def test_validation_does_not_authorize_activation_review(outputs: Path) -> None:
    assert _contract(outputs)["activation_review_authorized"] is False


def test_validation_does_not_authorize_package_promotion(outputs: Path) -> None:
    assert _contract(outputs)["package_promotion_authorized"] is False


def test_validation_does_not_mutate_metric_contract(outputs: Path) -> None:
    assert "validation_does_not_mutate_metric_contract" in _row_ids(outputs)


def test_validation_does_not_weaken_static_comparator(outputs: Path) -> None:
    assert "validation_does_not_weaken_static_comparator" in _row_ids(outputs)


def test_truth_engine_law_unchanged(outputs: Path) -> None:
    assert _contract(outputs)["truth_engine_derivation_law_unchanged"] is True


def test_trust_zone_law_unchanged(outputs: Path) -> None:
    assert _contract(outputs)["trust_zone_law_unchanged"] is True


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["no_authorization_drift_validation"])
    assert receipt["status"] == "PASS"
    assert receipt["no_downstream_authorization_drift"] is True


def test_next_lawful_move_is_run_shadow_screen(outputs: Path) -> None:
    assert _next(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _next(outputs)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_execution_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_packet_outputs(tmp_path, monkeypatch)
    contract_path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(contract_path)
    payload["shadow_screen_executed"] = True
    _write_json(contract_path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_packet_outputs(tmp_path, monkeypatch)
    draft_path = reports / packet.OUTPUTS["execution_prep_only_draft"]
    payload = _load(draft_path)
    payload["authority"] = "AUTHORITATIVE"
    _write_json(draft_path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        validation.run(reports_root=reports)


def test_compressed_index_truth_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_packet_outputs(tmp_path, monkeypatch)
    compressed_path = tmp_path / packet.INPUTS["compressed_receipt_index"]
    payload = _load(compressed_path)
    payload["compressed_index_is_source_of_truth"] = True
    _write_json(compressed_path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        validation.run(reports_root=reports)
