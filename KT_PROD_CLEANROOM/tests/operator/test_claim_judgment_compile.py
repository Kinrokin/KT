from __future__ import annotations

import sys
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.claim_judgment_compile import build_judgment_outputs  # noqa: E402
from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json  # noqa: E402


def test_step7_outputs_cover_claim_classes_and_validate_state_vector() -> None:
    root = repo_root()
    outputs = build_judgment_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")
    schema = load_json(root / "KT_PROD_CLEANROOM/governance/foundation_pack/kt_state_vector.schema.json")

    jsonschema.validate(instance=outputs["state_vector"], schema=schema)

    claim_rows = outputs["claim_registry"]["claim_classes"]
    claim_ids = {row["claim_class_id"] for row in claim_rows}
    expected = {
        "truth_authority_claim",
        "transparency_publication_claim",
        "governance_legitimacy_claim",
        "runtime_boundary_claim",
        "reproducibility_claim",
        "experiment_lineage_claim",
        "paradox_bound_claim",
        "doctrine_generation_claim",
        "commercial_surface_claim",
        "release_readiness_claim",
        "historical_lineage_claim",
    }

    assert claim_ids == expected
    assert outputs["claims_raw"]["claims"]
    assert outputs["conflict_register"]["conflicts"]
    assert outputs["counterexample_register"]["counterexamples"]
    assert outputs["state_vector"]["open_blockers"]
    assert outputs["state_vector"]["proof_obligations"]

    for row in claim_rows:
        assert row["evidence_refs"], row["claim_class_id"]
        assert row["raw_claim_ids"], row["claim_class_id"]
        assert row["evidence_chain_complete"] is True, row["claim_class_id"]


def test_step7_outputs_are_semantically_deterministic() -> None:
    root = repo_root()
    first = build_judgment_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")
    second = build_judgment_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")

    for key in first:
        assert semantically_equal_json(first[key], second[key]), key
