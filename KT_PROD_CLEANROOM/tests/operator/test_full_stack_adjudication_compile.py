from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.full_stack_adjudication_compile import (  # noqa: E402
    ADJUDICATION_CLOSEOUT_BUNDLE_REL,
    ATTACK_VECTORS_REL,
    FULL_STACK_AUDIT_REL,
    PROOF_OBLIGATIONS_REL,
    RELEASE_READINESS_MATRIX_REL,
    SURVIVAL_METRICS_REL,
    build_step12_outputs,
)
from tools.operator.titanium_common import repo_root, semantically_equal_json  # noqa: E402


def test_step12_outputs_cover_organs_claims_and_profiles() -> None:
    root = repo_root()
    outputs = build_step12_outputs(root, generated_utc="2026-03-14T00:00:00Z")

    full_stack = outputs[FULL_STACK_AUDIT_REL]
    attack_vectors = outputs[ATTACK_VECTORS_REL]
    survival_metrics = outputs[SURVIVAL_METRICS_REL]
    proof_obligations = outputs[PROOF_OBLIGATIONS_REL]
    release_matrix = outputs[RELEASE_READINESS_MATRIX_REL]
    closeout = outputs[ADJUDICATION_CLOSEOUT_BUNDLE_REL]

    assert full_stack["completion_status"] == "FULL_STACK_ADJUDICATION_COMPLETE"
    assert full_stack["organ_coverage"]["required_organ_count"] == 14
    assert full_stack["organ_coverage"]["covered_organ_count"] == 14
    assert full_stack["organ_coverage"]["all_major_organs_covered"] is True

    claim_rows = full_stack["claim_assessments"]
    assert len(claim_rows) == 18
    assert {row["classification"] for row in claim_rows} == {
        "proven",
        "evidenced_only",
        "contradicted",
        "aspirational",
    }

    release_summary = release_matrix["summary"]
    assert release_summary == {
        "profile_count": 14,
        "ready_with_boundaries_count": 6,
        "hold_count": 2,
        "blocked_count": 6,
    }

    assert proof_obligations["summary"]["open_obligation_count"] == 10
    obligation_ids = {row["obligation_id"] for row in proof_obligations["obligations"]}
    assert "OBLIGATION::REMOVE_LOCAL_RESIDUE_FROM_CANONICAL_ROOT" in obligation_ids
    assert "OBLIGATION::MIGRATE_ROOT_ARCHIVE_CONTAMINATION" in obligation_ids

    assert attack_vectors["summary"]["attack_vector_count"] == 10
    assert attack_vectors["summary"]["verdict_counts"]["RESIDUAL_RISK_ACKNOWLEDGED"] == 1
    assert attack_vectors["summary"]["verdict_counts"]["OPEN_HYGIENE_RISK"] == 1

    assert survival_metrics["metrics"]["organ_count"] == 14
    assert survival_metrics["metrics"]["claim_count"] == 18
    assert survival_metrics["metrics"]["open_proof_obligation_count"] == 10

    assert closeout["summary"]["claim_count"] == 18
    assert closeout["summary"]["open_blocker_count"] == 6


def test_step12_outputs_are_semantically_deterministic() -> None:
    root = repo_root()
    first = build_step12_outputs(root, generated_utc="2026-03-14T00:00:00Z")
    second = build_step12_outputs(root, generated_utc="2026-03-14T00:00:00Z")

    for rel in first:
        assert semantically_equal_json(first[rel], second[rel]), rel
