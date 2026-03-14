from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.constitutional_spine_ratify import (
    ACCREDITATION_POLICY_REL,
    CONSTITUTION_DOC_REL,
    COST_MODEL_REL,
    COURT_PROCEDURE_REL,
    DELIVERABLE_REFS,
    DEPENDENCY_MATRIX_REL,
    EPOCH_MODEL_REL,
    FORGETTING_LAW_REL,
    MANIFEST_REL,
    QUALITY_AXES,
    QUALITY_POLICY_REL,
    READINESS_LATTICE_REL,
    REQUIRED_SECTION_HEADINGS,
    SELF_DESCRIPTION_REL,
)
from tools.operator.titanium_common import load_json, repo_root


def test_constitutional_spine_artifacts_are_structurally_complete() -> None:
    root = repo_root()
    manifest = load_json(root / Path(MANIFEST_REL))
    dependency_matrix = load_json(root / Path(DEPENDENCY_MATRIX_REL))
    epoch_model = load_json(root / Path(EPOCH_MODEL_REL))
    quality_policy = load_json(root / Path(QUALITY_POLICY_REL))
    readiness_lattice = load_json(root / Path(READINESS_LATTICE_REL))
    forgetting_law = load_json(root / Path(FORGETTING_LAW_REL))
    accreditation_policy = load_json(root / Path(ACCREDITATION_POLICY_REL))
    self_description = load_json(root / Path(SELF_DESCRIPTION_REL))
    cost_model = load_json(root / Path(COST_MODEL_REL))
    court_procedure = load_json(root / Path(COURT_PROCEDURE_REL))
    constitution_text = (root / Path(CONSTITUTION_DOC_REL)).read_text(encoding="utf-8")

    assert manifest["schema_id"] == "kt.constitution.manifest.v1"
    assert set(manifest["artifact_refs"]) == set(DELIVERABLE_REFS)
    assert manifest["required_section_headings"] == REQUIRED_SECTION_HEADINGS
    assert len(manifest["artifact_digests"]) == len(DELIVERABLE_REFS) - 1

    assert dependency_matrix["schema_id"] == "kt.constitution.organ_dependency_matrix.v1"
    assert dependency_matrix["organ_count"] >= 14
    assert dependency_matrix["edge_count"] >= 1

    assert epoch_model["schema_id"] == "kt.constitution.epoch_model.v1"
    assert epoch_model["current_epoch_id"] == "epoch_2_foundation_and_baseline_frozen"
    assert epoch_model["pending_epoch_id"] == "epoch_3_constitutional_spine_ratification"

    assert quality_policy["schema_id"] == "kt.constitution.quality_policy.v1"
    assert quality_policy["quality_axes"] == QUALITY_AXES
    assert quality_policy["required_quality_by_profile"]

    assert readiness_lattice["schema_id"] == "kt.constitution.readiness_lattice.v1"
    assert any(row["profile_id"] == "h1_activation" for row in readiness_lattice["nodes"])

    assert forgetting_law["schema_id"] == "kt.constitution.forgetting_law.v1"
    assert forgetting_law["retention_classes"]
    assert forgetting_law["reopen_triggers"]

    assert accreditation_policy["schema_id"] == "kt.constitution.accreditation_policy.v1"
    assert len(accreditation_policy["roles"]) >= 4

    assert self_description["schema_id"] == "kt.constitution.self_description.v1"
    assert self_description["governance_ceiling"] == "WORKFLOW_GOVERNANCE_ONLY"
    assert self_description["published_head_self_convergence_status"] == "UNRESOLVED"
    assert self_description["h1_status"] == "BLOCKED"

    assert cost_model["schema_id"] == "kt.constitution.cost_model.v1"
    assert cost_model["mode_cost_classes"]

    filing_types = {row["filing_type"] for row in court_procedure["filing_types"]}
    assert {"amendment", "appeal", "dissent", "precedent_entry"}.issubset(filing_types)
    for section in REQUIRED_SECTION_HEADINGS:
        assert section in constitution_text
