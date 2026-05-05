from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator.kt_lane_compiler import (
    AUTHORITY,
    FORBIDDEN_AUTHORITY_TOKENS,
    LaneSpecError,
    build_lane_contract,
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
    }


def test_schema_validation_basics_require_prep_only_authority() -> None:
    normalized = validate_lane_spec(_spec())

    assert normalized["authority"] == AUTHORITY
    assert normalized["artifacts"] == sorted(normalized["artifacts"])

    invalid = _spec()
    invalid["authority"] = "AUTHORITATIVE_RUNTIME"
    with pytest.raises(LaneSpecError, match="authority must be PREP_ONLY_TOOLING"):
        validate_lane_spec(invalid)


def test_generated_artifacts_include_all_required_scaffolds() -> None:
    contract = build_lane_contract(_spec())
    generated = contract["generated_artifacts"]

    assert contract["schema_id"] == "kt.lane_contract.prep_only.v0"
    assert contract["authority"] == "PREP_ONLY_TOOLING"
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
    spec["summary"] = f"attempt to claim {token}"

    with pytest.raises(LaneSpecError, match="forbidden authority tokens present"):
        build_lane_contract(spec)


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


def test_compile_lane_spec_file_can_write_files_without_execution(tmp_path: Path) -> None:
    spec_path = tmp_path / "lane_spec.json"
    spec_path.write_text(json.dumps(_spec(), sort_keys=True), encoding="utf-8")

    contract = compile_lane_spec_file(spec_path, output_root=tmp_path)

    assert contract["status"] == "PREP_ONLY_SCAFFOLD"
    for relpath in contract["generated_artifacts"]:
        assert (tmp_path / relpath).exists()
    operator_text = (tmp_path / "KT_PROD_CLEANROOM/tools/operator/sample_prep_lane.py").read_text(encoding="utf-8")
    assert "PREP_ONLY_TOOLING" in operator_text
