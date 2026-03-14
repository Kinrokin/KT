from __future__ import annotations

from tools.operator.governance_baseline_ingest import (
    build_claim_ceiling_summary,
    build_governance_baseline_ingestion_report,
    build_governance_closeout_bundle,
    build_governance_evidence_subject_map,
    build_open_blocker_ladder,
)
from tools.operator.titanium_common import repo_root


def test_governance_baseline_builders_are_structurally_complete() -> None:
    root = repo_root()

    bundle = build_governance_closeout_bundle(root=root)
    blocker_ladder = build_open_blocker_ladder(root=root)
    claim_ceiling = build_claim_ceiling_summary(root=root)
    evidence_map = build_governance_evidence_subject_map(root=root)

    assert bundle["schema_id"] == "kt.operator.governance_closeout_bundle.v1"
    assert bundle["baseline_is_immutable_input"] is True
    assert bundle["closeout_verdict"] == "SEALED_WITH_OPEN_BLOCKERS"
    assert bundle["proven"]
    assert bundle["not_proven"]
    assert len(str(bundle["baseline_subject_commit"])) == 40
    assert len(str(bundle["baseline_evidence_commit"])) == 40

    assert blocker_ladder["schema_id"] == "kt.operator.open_blocker_ladder.v1"
    assert blocker_ladder["open_blocker_count"] >= 1
    assert any(row["blocker_id"] == "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED" for row in blocker_ladder["blocker_ladder"])

    assert claim_ceiling["schema_id"] == "kt.operator.claim_ceiling_summary.v1"
    assert claim_ceiling["highest_attained_proof_class"]["proof_class_id"] == "FRONTIER_SETTLEMENT_WITH_H1_BLOCK"
    assert claim_ceiling["current_ceiling_by_domain"]["governance"]["ceiling_id"] == "WORKFLOW_GOVERNANCE_ONLY"
    assert claim_ceiling["current_ceiling_by_domain"]["activation"]["ceiling_id"] == "H1_BLOCKED"
    assert any(row["proof_class_id"] == "PLATFORM_ENFORCEMENT_PROVEN" for row in claim_ceiling["unattained_proof_classes"])

    assert evidence_map["schema_id"] == "kt.operator.governance_evidence_subject_map.v1"
    assert len(evidence_map["entries"]) >= 6
    assert any(row["domain_id"] == "governance_closeout_baseline" for row in evidence_map["entries"])
    assert all(len(str(row["evidence_commit"])) == 40 and len(str(row["subject_commit"])) == 40 for row in evidence_map["entries"])


def test_governance_baseline_ingestion_report_passes_once_artifacts_exist() -> None:
    report = build_governance_baseline_ingestion_report(root=repo_root())

    assert report["schema_id"] == "kt.operator.governance_baseline_ingestion_receipt.v1"
    assert report["status"] == "PASS"
    assert report["pass_verdict"] == "BASELINE_FROZEN"
    assert report["unexpected_touches"] == []
    assert report["protected_touch_violations"] == []
    assert report["next_lawful_step"]["step_id"] == 3
