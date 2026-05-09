from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_canary_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_canary_evidence_review_packet_validation as validation


VALIDATION_HEAD = "dddddddddddddddddddddddddddddddddddddddd"
VALIDATION_MAIN_HEAD = "823bd14d76fd7b14643078ffed3da240ae522b97"


def _load_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_canary_evidence_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_canary_evidence_review_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load canary evidence review helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


review_helpers = _load_review_helpers()
SOURCE_BLOB_STORES: dict[str, dict[tuple[str, str], bytes]] = {}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_validation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    origin_main: str = VALIDATION_MAIN_HEAD,
    dirty: str = "",
    git_refs: dict[str, str] | None = None,
    git_blob_store: dict[tuple[str, str], bytes] | None = None,
) -> None:
    raw_inputs = (
        list(validation.REVIEW_JSON_INPUTS.values())
        + list(validation.REVIEW_TEXT_INPUTS.values())
        + list(review.ALL_JSON_INPUTS.values())
        + list(review.ALL_TEXT_INPUTS.values())
    )
    blob_store = {
        (origin_main, raw): (tmp_path / raw).read_bytes()
        for raw in raw_inputs
        if (tmp_path / raw).exists()
    }
    blob_store.update(SOURCE_BLOB_STORES.get(str(tmp_path), {}))
    if git_blob_store is not None:
        blob_store.update(git_blob_store)
    refs = {
        "HEAD": head,
        "origin/main": origin_main,
        head: head,
        origin_main: origin_main,
        review_helpers.SUPERLANE_MAIN_HEAD: review_helpers.SUPERLANE_MAIN_HEAD,
        **(git_refs or {}),
    }

    def fake_git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
        return blob_store.get((commit, raw), (root / raw).read_bytes())

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        return hashlib.sha256(fake_git_blob_bytes(root, commit, raw)).hexdigest()

    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(validation, "_git_blob_bytes", fake_git_blob_bytes)
    monkeypatch.setattr(validation, "_git_blob_sha256", fake_git_blob_sha256)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_review_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = review_helpers.canary_helpers._run_canary(tmp_path, monkeypatch)
    raw_inputs = list(review.ALL_JSON_INPUTS.values()) + list(review.ALL_TEXT_INPUTS.values())
    source_blobs = {
        (review_helpers.SUPERLANE_MAIN_HEAD, raw): (tmp_path / raw).read_bytes()
        for raw in raw_inputs
        if (tmp_path / raw).exists()
    }
    SOURCE_BLOB_STORES[str(tmp_path)] = source_blobs
    review_helpers._patch_review_env(monkeypatch, tmp_path, git_blob_store=source_blobs)
    review.run(reports_root=reports)
    return reports


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("canary_evidence_review_packet_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _review_payload(outputs: Path, role: str) -> dict:
    return _load(outputs / review.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "validation_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "validation_receipt")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _binding_row(outputs: Path, role: str) -> dict:
    for row in _contract(outputs)["input_bindings"]:
        if row["role"] == role:
            return row
    raise AssertionError(f"missing binding row {role}")


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_canary_evidence_review_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "CANARY_EVIDENCE_REVIEW_PACKET_VALIDATED_EXPANDED_CANARY_PACKET_NEXT"


def test_next_lawful_move_is_expanded_canary_authorization_packet(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert nxt["recommended_next_path_validated"] == review.RECOMMENDED_NEXT_PATH


def test_validation_report_states_boundaries(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "expanded canary authorization packet authorship" in text
    assert "does not authorize expanded canary execution" in text
    assert "does not authorize runtime cutover" in text
    assert "does not open r6" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("canary_evidence_review_validated", True),
        ("expanded_canary_authorization_packet_next", True),
        ("canary_runtime_executed", True),
        ("expanded_canary_authorized", False),
        ("expanded_canary_executed", False),
        ("runtime_cutover_authorized", False),
        ("activation_cutover_executed", False),
        ("r6_open", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("canary_evidence_treated_as_package_promotion", False),
    ],
)
def test_validation_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", sorted(validation.REVIEW_JSON_INPUTS))
def test_validation_binds_all_review_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.REVIEW_TEXT_INPUTS))
def test_validation_binds_all_review_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


@pytest.mark.parametrize("row_index", range(0, 120))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    row = rows[row_index]
    assert len(row["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in row["sha256"])


@pytest.mark.parametrize(
    "role",
    [
        "next_lawful_move",
        "pipeline_board",
        "e2e_closure_campaign_board",
        "runtime_cutover_review_packet_prep_only_draft",
    ],
)
def test_overwritten_review_inputs_bind_to_handoff_git_objects(outputs: Path, role: str) -> None:
    row = _binding_row(outputs, role)
    assert row["binding_kind"] == "git_object_before_overwrite"
    assert row["git_commit"] == VALIDATION_MAIN_HEAD
    assert row["mutable_canonical_path_overwritten_by_this_lane"] is True


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hashes"]


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_bind_hash_shapes(outputs: Path, role: str) -> None:
    receipt = _payload(outputs, role)
    for value in receipt["validated_hashes"].values():
        assert len(value) == 64
        assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", validation.REVIEW_CONTRACT_ROLES)
def test_direct_review_contracts_were_passed_before_validation(outputs: Path, role: str) -> None:
    payload = _review_payload(outputs, role)
    expected = {
        "external_verifier_readiness_review_contract": "PARTIAL",
        "package_promotion_blocker_review_contract": "BLOCKED",
    }.get(role, "PASS")
    assert payload["review_status"] == expected


@pytest.mark.parametrize("category", review.REVIEW_CATEGORIES)
def test_scorecard_required_categories_validated(outputs: Path, category: str) -> None:
    scorecard = _review_payload(outputs, "evidence_scorecard")["scorecard"]
    categories = {row["category"]: row for row in scorecard["categories"]}
    assert category in categories
    assert categories[category]["status"]


def test_decision_matrix_recommendation_is_validated(outputs: Path) -> None:
    matrix = _review_payload(outputs, "post_run_decision_matrix")["decision_matrix"]
    assert matrix["recommended_next_path"] == "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
    assert matrix["runtime_cutover_review_ready"] is False
    assert matrix["expanded_canary_ready"] is True
    assert matrix["second_canary_ready"] is True
    assert matrix["package_promotion_ready"] is False
    assert matrix["commercial_claim_status"] == "BOUNDARY_ONLY"
    assert _payload(outputs, "post_run_decision_matrix_validation")["recommended_next_path_validated"] == review.RECOMMENDED_NEXT_PATH


def test_readiness_matrices_preserve_lawful_next_options(outputs: Path) -> None:
    cutover = _review_payload(outputs, "runtime_cutover_readiness_matrix")["readiness"]
    expanded = _review_payload(outputs, "expanded_canary_readiness_matrix")["readiness"]
    second = _review_payload(outputs, "second_canary_readiness_matrix")["readiness"]
    assert cutover["ready"] is False
    assert cutover["runtime_cutover_authorized"] is False
    assert expanded["ready"] is True
    assert expanded["recommendation"] == "READY_FOR_AUTHORIZATION_PACKET_IF_VALIDATED"
    assert expanded["runtime_cutover_authorized"] is False
    assert second["ready"] is True
    assert second["runtime_cutover_authorized"] is False


def test_post_canary_blocker_ledger_covers_campaign_blockers(outputs: Path) -> None:
    categories = {row["category"] for row in _review_payload(outputs, "post_canary_blocker_ledger")["blockers"]}
    assert {
        "runtime_cutover",
        "expanded_canary",
        "second_canary",
        "package_promotion",
        "external_audit",
        "public_verifier",
        "commercial_claims",
        "operator_readiness",
        "deployment_profile",
        "rollback_proof",
        "data_governance",
        "secret_distributable_hygiene",
        "benchmark_reaudit_readiness",
    } <= categories


def test_pipeline_board_routes_to_expanded_canary_authoring_without_execution(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    lanes = {row["lane"]: row for row in board["lanes"]}
    assert lanes["VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"]["status"] == "CURRENT_VALIDATED"
    assert lanes["AUTHOR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"]["status"] == "NEXT"
    assert lanes["RUN_B04_R6_EXPANDED_CANARY"]["status"] == "BLOCKED"
    assert lanes["RUNTIME_CUTOVER"]["status"] == "BLOCKED"
    assert lanes["PACKAGE_PROMOTION"]["status"] == "BLOCKED"


def test_campaign_board_tracks_all_e2e_corridors(outputs: Path) -> None:
    board = _payload(outputs, "campaign_board")
    corridors = {row["corridor"]: row for row in board["corridors"]}
    assert {
        "R6 proof corridor",
        "canary corridor",
        "runtime cutover corridor",
        "package promotion corridor",
        "external audit corridor",
        "public verifier corridor",
        "claim compiler corridor",
        "proof factory corridor",
        "promotion engine corridor",
        "lobe ratification corridor",
        "adapter / tournament / academy corridor",
        "benchmark / re-audit corridor",
        "commercial truth plane corridor",
    } <= set(corridors)
    for corridor in corridors.values():
        assert "RUNTIME_CUTOVER_AUTHORIZED" in corridor["blocked_authorities"]
        assert "R6_OPEN" in corridor["blocked_authorities"]
        assert "PACKAGE_PROMOTION_AUTHORIZED" in corridor["blocked_authorities"]
        assert "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED" in corridor["blocked_authorities"]


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_review_prep_only_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    filename = review.OUTPUTS[role]
    if filename.endswith(".json"):
        payload = _review_payload(outputs, role)
        for key, value in review.PREP_ONLY_INVARIANTS.items():
            assert payload[key] == value
    else:
        assert "PREP_ONLY" in (outputs / filename).read_text(encoding="utf-8")


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_continuation_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    for key, value in validation.PREP_ONLY_INVARIANTS.items():
        assert payload[key] == value
    assert payload["expanded_canary_authorized"] is False
    assert payload["expanded_canary_executed"] is False


@pytest.mark.parametrize("action", validation.FORBIDDEN_ACTIONS)
def test_forbidden_actions_are_recorded(outputs: Path, action: str) -> None:
    assert action in _contract(outputs)["forbidden_actions"]


@pytest.mark.parametrize("code", validation.REASON_CODES)
def test_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("defect", validation.TERMINAL_DEFECTS)
def test_terminal_defects_are_recorded(outputs: Path, defect: str) -> None:
    assert defect in _contract(outputs)["terminal_defects"]


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_validation")
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False
    assert receipt["package_promotion_authorized"] is False


def test_lane_compiler_scaffold_remains_prep_only_tooling(outputs: Path) -> None:
    receipt = _payload(outputs, "lane_compiler_scaffold_receipt")
    assert receipt["scaffold_authority"] == "PREP_ONLY_TOOLING"
    assert receipt["scaffold_can_authorize"] is False
    assert receipt["scaffold"]["authority"] == "PREP_ONLY_TOOLING"


@pytest.mark.parametrize("role", _json_output_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("expanded_canary_authorized", False),
        ("expanded_canary_executed", False),
        ("runtime_cutover_authorized", False),
        ("activation_cutover_executed", False),
        ("r6_open", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("canary_evidence_treated_as_package_promotion", False),
    ],
)
def test_validation_outputs_preserve_negative_boundaries(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


def test_missing_validation_signed_input_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    contract_path = reports / review.OUTPUTS["packet_contract"]
    contract = _load(contract_path)
    contract["input_bindings"].pop("canary_result_hash")
    _write(contract_path, contract)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="INPUT_HASH_MISSING"):
        validation.run(reports_root=reports)


def test_malformed_validation_signed_input_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    contract_path = reports / review.OUTPUTS["packet_contract"]
    contract = _load(contract_path)
    contract["input_bindings"]["canary_result_hash"] = "not-a-sha"
    _write(contract_path, contract)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="INPUT_HASH_MALFORMED"):
        validation.run(reports_root=reports)


def test_source_evidence_hash_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    result_path = tmp_path / review.ALL_JSON_INPUTS["canary_result"]
    result = _load(result_path)
    result["tampered_after_review_packet"] = True
    _write(result_path, result)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="INPUT_HASH_MISSING"):
        validation.run(reports_root=reports)


def test_decision_matrix_cutover_recommendation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    matrix_path = reports / review.OUTPUTS["post_run_decision_matrix"]
    matrix = _load(matrix_path)
    matrix["decision_matrix"]["recommended_next_path"] = "RUNTIME_CUTOVER_REVIEW_PACKET_NEXT"
    _write(matrix_path, matrix)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="DECISION_MATRIX_UNJUSTIFIED"):
        validation.run(reports_root=reports)


def test_expanded_canary_readiness_false_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    readiness_path = reports / review.OUTPUTS["expanded_canary_readiness_matrix"]
    readiness = _load(readiness_path)
    readiness["readiness"]["ready"] = False
    _write(readiness_path, readiness)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="READINESS_MATRIX_MISSING"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    prep_path = reports / review.OUTPUTS["claim_compiler_contract_prep_only"]
    prep = _load(prep_path)
    prep["authority"] = "AUTHORITATIVE"
    _write(prep_path, prep)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PREP_ONLY_AUTHORITY_DRIFT"):
        validation.run(reports_root=reports)


def test_claim_bearing_authority_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    contract_path = reports / review.OUTPUTS["packet_contract"]
    contract = _load(contract_path)
    contract["commercial_claim_status"] = "PACKAGE_PROMOTION AUTHORIZED"
    contract["package_promotion_authorized"] = False
    _write(contract_path, contract)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="COMMERCIAL_CLAIM_DRIFT"):
        validation.run(reports_root=reports)


def test_negative_qualifier_cannot_mask_later_authority_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    contract_path = reports / review.OUTPUTS["packet_contract"]
    contract = _load(contract_path)
    contract["commercial_claim_status"] = "UNAUTHORIZED; PACKAGE_PROMOTION AUTHORIZED"
    contract["package_promotion_authorized"] = False
    _write(contract_path, contract)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="COMMERCIAL_CLAIM_DRIFT"):
        validation.run(reports_root=reports)


def test_non_deferred_package_promotion_state_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    contract_path = reports / review.OUTPUTS["packet_contract"]
    contract = _load(contract_path)
    contract["authorization_state"] = {"package_promotion": "AUTHORIZED"}
    contract["package_promotion_authorized"] = False
    _write(contract_path, contract)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKAGE_PROMOTION_DRIFT|COMMERCIAL_CLAIM_DRIFT"):
        validation.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M file")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(RuntimeError, match="must run on one of"):
        validation.run(reports_root=reports)


def test_missing_predecessor_handoff_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    orphan_main = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    invalid_handoff = b'{"authoritative_lane":"NOT_THE_PREVIOUS_HANDOFF"}'
    _patch_validation_env(
        monkeypatch,
        tmp_path,
        branch="main",
        head=orphan_main,
        origin_main=orphan_main,
        git_refs={orphan_main: orphan_main},
        git_blob_store={
            (
                orphan_main,
                f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['next_lawful_move']}",
            ): invalid_handoff
        },
    )
    with pytest.raises(RuntimeError, match="could not find predecessor handoff"):
        validation.run(reports_root=reports)


def test_main_replay_binds_overwritten_review_inputs_to_first_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    raw_inputs = (
        list(validation.REVIEW_JSON_INPUTS.values())
        + list(validation.REVIEW_TEXT_INPUTS.values())
        + list(review.ALL_JSON_INPUTS.values())
        + list(review.ALL_TEXT_INPUTS.values())
    )
    pre_validation_main = VALIDATION_MAIN_HEAD
    validation_merge_main = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    validation_replay_main = "ffffffffffffffffffffffffffffffffffffffff"
    pre_validation_blobs = {
        (pre_validation_main, raw): (tmp_path / raw).read_bytes()
        for raw in raw_inputs
        if (tmp_path / raw).exists()
    }

    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)

    _patch_validation_env(
        monkeypatch,
        tmp_path,
        branch="main",
        head=validation_replay_main,
        origin_main=validation_replay_main,
        git_refs={
            f"{validation_replay_main}^1": validation_merge_main,
            f"{validation_merge_main}^1": pre_validation_main,
            validation_replay_main: validation_replay_main,
            validation_merge_main: validation_merge_main,
            pre_validation_main: pre_validation_main,
        },
        git_blob_store=pre_validation_blobs,
    )
    validation.run(reports_root=reports)

    row = _binding_row(reports, "next_lawful_move")
    assert row["binding_kind"] == "git_object_before_overwrite"
    assert row["git_commit"] == pre_validation_main
    assert row["sha256"] == hashlib.sha256(
        pre_validation_blobs[
            (
                pre_validation_main,
                f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['next_lawful_move']}",
            )
        ]
    ).hexdigest()


def test_malformed_parent_handoff_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    raw_inputs = list(validation.REVIEW_JSON_INPUTS.values()) + list(validation.REVIEW_TEXT_INPUTS.values())
    pre_validation_main = VALIDATION_MAIN_HEAD
    validation_merge_main = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    pre_validation_blobs = {
        (pre_validation_main, raw): (tmp_path / raw).read_bytes()
        for raw in raw_inputs
        if (tmp_path / raw).exists()
    }
    pre_validation_blobs[
        (
            pre_validation_main,
            f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['next_lawful_move']}",
        )
    ] = b"{not-json"
    pre_validation_blobs[
        (
            validation_merge_main,
            f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['next_lawful_move']}",
        )
    ] = b'{"authoritative_lane":"NOT_THE_PREVIOUS_HANDOFF"}'

    _patch_validation_env(
        monkeypatch,
        tmp_path,
        branch="main",
        head=validation_merge_main,
        origin_main=validation_merge_main,
        git_refs={
            f"{validation_merge_main}^1": pre_validation_main,
            validation_merge_main: validation_merge_main,
            pre_validation_main: pre_validation_main,
        },
        git_blob_store=pre_validation_blobs,
    )
    with pytest.raises(RuntimeError, match="malformed prior handoff candidate"):
        validation.run(reports_root=reports)
