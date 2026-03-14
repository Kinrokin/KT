from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.closure_foundation_validate import (
    CLAIM_COMPILER_POLICY_REL,
    DETERMINISM_CONTRACT_REL,
    PUBLIC_VERIFIER_CONTRACT_REL,
    REQUIRED_DETERMINISM_CONTROLS,
    REQUIRED_MINIMUM_ENVIRONMENTS,
    TUF_ROOT_POLICY_REL,
    build_closure_foundation_report,
)
from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json


def test_closure_foundation_report_passes_and_foundation_contracts_are_explicit() -> None:
    root = repo_root()
    report = build_closure_foundation_report(root)
    determinism = load_json(root / DETERMINISM_CONTRACT_REL)
    tuf_policy = load_json(root / TUF_ROOT_POLICY_REL)
    verifier_contract = load_json(root / PUBLIC_VERIFIER_CONTRACT_REL)
    claim_policy = load_json(root / CLAIM_COMPILER_POLICY_REL)

    assert report["schema_id"] == "kt.operator.closure_foundation_receipt.v1"
    assert report["status"] == "PASS"
    assert report["pass_verdict"] == "CLOSURE_FOUNDATION_RATIFIED"
    assert report["subject_head_commit"] == report["compiled_head_commit"]
    assert report["unexpected_touches"] == []
    assert report["protected_touch_violations"] == []
    assert report["next_lawful_step"]["workstream_id"] == "WS1_ACTIVE_ARCHIVE_CUTLINE_FREEZE"

    assert set(determinism["required_controls"]) == REQUIRED_DETERMINISM_CONTROLS
    assert set(determinism["minimum_environments"]) == REQUIRED_MINIMUM_ENVIRONMENTS
    assert determinism["closure_boundary"]["foundation_ratification_only"] is True

    assert tuf_policy["root_of_trust"]["threshold"] == 1
    assert len(tuf_policy["root_of_trust"]["root_keys"]) == 1
    assert tuf_policy["closure_boundary"]["opens_release_gates"] == []

    assert verifier_contract["offline_verification_capable"] is True
    assert "subject_evidence_boundary_ambiguous" in verifier_contract["fail_closed_conditions"]
    assert "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json" in verifier_contract["required_inputs"]

    assert claim_policy["ambiguity_downgrade_policy"]["default_class_on_ambiguity"] == "LOWEST_ADMISSIBLE_TIER"
    assert "docs/generated/**" in claim_policy["always_on_surfaces"]
    assert "KT_PROD_CLEANROOM/docs/commercial/**" in claim_policy["always_on_surfaces"]

    check_ids = {row["check"] for row in report["checks"]}
    assert "determinism_controls_complete" in check_ids
    assert "tuf_root_policy_matches_active_signer" in check_ids
    assert "public_verifier_contract_explicit_and_fail_closed" in check_ids
    assert "claim_compiler_policy_downgrades_on_ambiguity" in check_ids


def test_closure_foundation_report_is_semantically_deterministic() -> None:
    root = repo_root()
    first = build_closure_foundation_report(root)
    second = build_closure_foundation_report(root)
    first["step_report"]["timestamp"] = "NORMALIZED"
    second["step_report"]["timestamp"] = "NORMALIZED"
    assert semantically_equal_json(first, second)
