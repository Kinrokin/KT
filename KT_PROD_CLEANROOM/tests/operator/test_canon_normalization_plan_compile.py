from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.canon_normalization_plan_compile import (  # noqa: E402
    DOC_LAYER_IDS,
    MAJOR_FUNCTION_IDS,
    RELEASE_PROFILE_IDS,
    SUBMISSION_PROFILE_IDS,
    WORK_PACKAGE_IDS,
    build_step8_outputs,
)
from tools.operator.titanium_common import repo_root, semantically_equal_json  # noqa: E402


def test_step8_outputs_cover_major_functions_and_planning_contract() -> None:
    root = repo_root()
    outputs = build_step8_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")

    assert [row["major_function_id"] for row in outputs["kt_canon_proposal"]["major_function_proposals"]] == MAJOR_FUNCTION_IDS
    assert [row["package_id"] for row in outputs["kt_normalization_work_order"]["work_packages"]] == WORK_PACKAGE_IDS
    assert [row["layer_id"] for row in outputs["kt_docs_topology"]["layers"]] == DOC_LAYER_IDS
    assert [row["profile_id"] for row in outputs["kt_release_profile"]["profiles"]] == RELEASE_PROFILE_IDS
    assert [row["profile_id"] for row in outputs["kt_submission_profile"]["profiles"]] == SUBMISSION_PROFILE_IDS

    assert outputs["kt_canon_ratification_log"]["ratification_status"] == "UNRATIFIED_PROPOSAL_ONLY"
    assert outputs["kt_release_profile"]["h1_allowed"] is False
    assert outputs["kt_submission_profile"]["h1_allowed"] is False

    for row in outputs["kt_normalization_work_order"]["work_packages"]:
        assert row["migration_tests"], row["package_id"]
        assert row["rollback_plan"], row["package_id"]

    coverage_axes = set(outputs["kt_repo_professionalization_plan"]["coverage_axes"])
    assert {"repo_shape", "docs", "schemas", "release_layout", "submission_layout"} <= coverage_axes


def test_step8_outputs_are_semantically_deterministic() -> None:
    root = repo_root()
    first = build_step8_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")
    second = build_step8_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")

    for key in first:
        assert semantically_equal_json(first[key], second[key]), key
