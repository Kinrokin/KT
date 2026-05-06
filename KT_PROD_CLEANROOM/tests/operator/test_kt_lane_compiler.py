from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator.kt_lane_compiler import (
    AUTHORITY,
    FORBIDDEN_AUTHORITY_TOKENS,
    LaneSpecError,
    build_lane_contract,
    build_paired_lane_contract,
    compile_lane_spec_file,
    validate_lane_spec,
)


def _spec() -> dict:
    return {
        "lane_id": "KT_LANE_COMPILER_V0_SAMPLE",
        "lane_name": "Sample Prep Lane",
        "authority": "PREP_ONLY_TOOLING",
        "owner": "tooling/prep",
        "summary": "Compile a non-executing prep scaffold.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/sample_prep_lane.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_sample_prep_lane.py",
        "artifacts": [
            "KT_PROD_CLEANROOM/reports/sample_artifact.json",
            "KT_PROD_CLEANROOM/reports/sample_receipt.json",
        ],
        "json_parse_inputs": ["KT_PROD_CLEANROOM/reports/sample_input.json"],
        "no_authorization_drift_checks": ["PREP_ONLY boundary is retained."],
        "future_blockers": ["AUTHORITATIVE_PACKET_PENDING"],
        "reason_codes": ["PREP_ONLY_NOT_AUTHORIZED"],
        "lane_kind": "VALIDATION",
        "current_main_head": "60822fab5dfbaddcbe236f8e3266fbca50af7f14",
        "predecessor_outcome": "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_BOUND__LIMITED_RUNTIME_VALIDATION_NEXT",
        "selected_outcome": "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED__LIMITED_RUNTIME_EXECUTION_PACKET_NEXT",
        "next_lawful_move": "AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
        "may_authorize": ["LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED"],
        "must_not_authorize": ["LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "R6_OPEN"],
        "authoritative_inputs": ["limited_runtime_authorization_packet"],
        "prep_only_outputs": ["limited_runtime_execution_packet_draft"],
    }


def test_schema_validation_basics_require_prep_only_authority() -> None:
    normalized = validate_lane_spec(_spec())

    assert normalized["authority"] == AUTHORITY
    assert normalized["artifacts"] == sorted(normalized["artifacts"])

    invalid = _spec()
    invalid["authority"] = "AUTHORITATIVE_RUNTIME"
    with pytest.raises(LaneSpecError, match="authority must be PREP_ONLY_TOOLING"):
        validate_lane_spec(invalid)


def test_optional_lists_accept_empty_arrays_to_match_schema() -> None:
    spec = _spec()
    spec["json_parse_inputs"] = []
    spec["no_authorization_drift_checks"] = []
    spec["future_blockers"] = []
    spec["reason_codes"] = []

    normalized = validate_lane_spec(spec)

    assert normalized["json_parse_inputs"] == []
    assert normalized["no_authorization_drift_checks"] == []
    assert normalized["future_blockers"] == []
    assert normalized["reason_codes"] == []


def test_generated_artifacts_include_all_required_scaffolds() -> None:
    contract = build_lane_contract(_spec())
    generated = contract["generated_artifacts"]

    assert contract["schema_id"] == "kt.lane_contract.prep_only.v0"
    assert contract["authority"] == "PREP_ONLY_TOOLING"
    assert contract["lane_law_metadata"]["lane_kind"] == "VALIDATION"
    assert "R6_OPEN" in contract["lane_law_metadata"]["must_not_authorize"]
    assert contract["non_authorization_guards"]["runtime_authorized"] is False
    assert "KT_PROD_CLEANROOM/tools/operator/sample_prep_lane.py" in generated
    assert "KT_PROD_CLEANROOM/tests/operator/test_sample_prep_lane.py" in generated
    assert any(path.startswith("KT_PROD_CLEANROOM/reports/kt_lane_artifact_list__") for path in generated)
    assert any(path.startswith("KT_PROD_CLEANROOM/reports/kt_lane_reason_codes__") for path in generated)
    assert any(path.startswith("KT_PROD_CLEANROOM/reports/kt_lane_json_parse_list__") for path in generated)
    assert any(path.startswith("KT_PROD_CLEANROOM/reports/kt_lane_no_authorization_drift__") for path in generated)
    assert any(path.startswith("KT_PROD_CLEANROOM/reports/kt_lane_future_blockers__") for path in generated)
    assert any(path.startswith("KT_PROD_CLEANROOM/reports/kt_lane_pr_body__") for path in generated)
    assert any(path.startswith("KT_PROD_CLEANROOM/reports/kt_lane_replay_pr_body__") for path in generated)


@pytest.mark.parametrize("token", FORBIDDEN_AUTHORITY_TOKENS)
def test_forbidden_outcomes_are_rejected_from_specs(token: str) -> None:
    spec = _spec()
    spec["may_authorize"] = [f"attempt_to_claim_{token}"]

    with pytest.raises(LaneSpecError, match="may_authorize"):
        build_lane_contract(spec)


@pytest.mark.parametrize("field", ["summary", "selected_outcome", "next_lawful_move"])
def test_forbidden_authority_tokens_are_rejected_from_claim_fields(field: str) -> None:
    spec = _spec()
    spec[field] = "RUNTIME_CUTOVER_AUTHORIZED"

    with pytest.raises(LaneSpecError, match=field):
        build_lane_contract(spec)


def test_must_not_authorize_can_name_forbidden_boundaries() -> None:
    spec = _spec()
    spec["must_not_authorize"] = list(FORBIDDEN_AUTHORITY_TOKENS)

    contract = build_lane_contract(spec)

    assert set(contract["lane_law_metadata"]["must_not_authorize"]) == set(FORBIDDEN_AUTHORITY_TOKENS)


def test_negative_and_prep_fields_can_name_future_boundaries_without_authorizing() -> None:
    spec = _spec()
    spec["artifacts"] = ["KT_PROD_CLEANROOM/reports/package_promotion_review_preconditions_prep_only.json"]
    spec["json_parse_inputs"] = ["KT_PROD_CLEANROOM/reports/package_promotion_review_preconditions_prep_only.json"]
    spec["authoritative_inputs"] = ["package_promotion_review_preconditions_prep_only"]
    spec["future_blockers"] = ["PACKAGE_PROMOTION_REVIEW_NOT_YET_AUTHORED"]
    spec["reason_codes"] = ["RC_B04R6_RUNTIME_CUTOVER_AUTHORIZED_DRIFT"]
    spec["prep_only_outputs"] = ["package_promotion_review_preconditions_draft"]
    spec["no_authorization_drift_checks"] = ["R6_OPEN remains forbidden."]

    contract = build_lane_contract(spec)

    assert contract["non_authorization_guards"]["package_promotion_authorized"] is False
    assert contract["lane_law_metadata"]["prep_only_outputs"] == ["package_promotion_review_preconditions_draft"]


def test_output_is_deterministic() -> None:
    first = build_lane_contract(_spec())
    second = build_lane_contract(dict(reversed(list(_spec().items()))))

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_generated_content_stays_prep_only_and_non_authoritative() -> None:
    contract = build_lane_contract(_spec())
    rendered = json.dumps(contract, sort_keys=True)

    assert "PREP_ONLY_TOOLING" in rendered
    assert "runtime_authorized" in rendered
    assert contract["non_authorization_guards"]["r6_open_authorized"] is False
    assert contract["non_authorization_guards"]["package_promotion_authorized"] is False
    assert contract["non_authorization_guards"]["commercial_claims_authorized"] is False
    for token in FORBIDDEN_AUTHORITY_TOKENS:
        assert token in contract["non_authorization_guards"]["forbidden_authority_tokens"]


def test_paired_lane_contract_keeps_author_and_validation_separate() -> None:
    author = _spec()
    author["lane_id"] = "AUTHOR_SAMPLE_PACKET"
    author["lane_name"] = "Author Sample Packet"
    author["lane_kind"] = "AUTHORING"
    author["selected_outcome"] = "SAMPLE_PACKET_BOUND__VALIDATION_NEXT"
    author["next_lawful_move"] = "VALIDATE_SAMPLE_PACKET"
    author["may_authorize"] = ["SAMPLE_PACKET_AUTHORED"]

    validation = _spec()
    validation["lane_id"] = "VALIDATE_SAMPLE_PACKET"
    validation["lane_name"] = "Validate Sample Packet"
    validation["lane_kind"] = "VALIDATION"
    validation["predecessor_outcome"] = author["selected_outcome"]
    validation["selected_outcome"] = "SAMPLE_PACKET_VALIDATED__NEXT_PACKET_NEXT"
    validation["next_lawful_move"] = "AUTHOR_NEXT_SAMPLE_PACKET"
    validation["may_authorize"] = ["SAMPLE_PACKET_VALIDATED"]

    paired = build_paired_lane_contract(author, validation)

    assert paired["authority"] == AUTHORITY
    assert paired["status"] == "PREP_ONLY_PAIRED_SCAFFOLD"
    assert paired["paired_lane_law"]["authoring_is_not_validation"] is True
    assert paired["paired_lane_law"]["canonical_validation_requires_separate_lane"] is True
    assert paired["paired_lane_law"]["compiler_can_authorize"] is False
    assert paired["author_lane_id"] == "AUTHOR_SAMPLE_PACKET"
    assert paired["validation_lane_id"] == "VALIDATE_SAMPLE_PACKET"
    assert paired["non_authorization_guards"]["r6_open_authorized"] is False


def test_compile_lane_spec_file_can_write_files_without_execution(tmp_path: Path) -> None:
    spec_path = tmp_path / "lane_spec.json"
    spec_path.write_text(json.dumps(_spec(), sort_keys=True), encoding="utf-8")

    contract = compile_lane_spec_file(spec_path, output_root=tmp_path)

    assert contract["status"] == "PREP_ONLY_SCAFFOLD"
    for relpath in contract["generated_artifacts"]:
        assert (tmp_path / relpath).exists()
    operator_text = (tmp_path / "KT_PROD_CLEANROOM/tools/operator/sample_prep_lane.py").read_text(encoding="utf-8")
    assert "PREP_ONLY_TOOLING" in operator_text


def test_compile_lane_spec_file_rejects_output_root_escape(tmp_path: Path) -> None:
    spec = _spec()
    spec["operator_path"] = "../escape.py"
    spec_path = tmp_path / "lane_spec.json"
    spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

    with pytest.raises(LaneSpecError, match="operator_path must be a safe relative path"):
        compile_lane_spec_file(spec_path, output_root=tmp_path / "out")


def test_compile_lane_spec_file_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    spec_path = tmp_path / "lane_spec.json"
    spec_path.write_text('{"lane_id":"ONE","lane_id":"TWO"}', encoding="utf-8")

    with pytest.raises(LaneSpecError, match="lane spec JSON must parse strictly"):
        compile_lane_spec_file(spec_path, output_root=tmp_path / "out")


def test_lane_id_must_be_filename_safe() -> None:
    spec = _spec()
    spec["lane_id"] = "../escape"

    with pytest.raises(LaneSpecError, match="lane_id must use only"):
        validate_lane_spec(spec)


def test_operator_and_test_paths_must_use_expected_prefixes() -> None:
    spec = _spec()
    spec["operator_path"] = "KT_PROD_CLEANROOM/reports/not_an_operator.py"

    with pytest.raises(LaneSpecError, match="operator_path must start with"):
        validate_lane_spec(spec)
