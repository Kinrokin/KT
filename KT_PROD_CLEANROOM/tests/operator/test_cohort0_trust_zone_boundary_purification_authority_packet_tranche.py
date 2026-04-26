from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_trust_zone_boundary_purification_authority_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_trust_zone_boundary_authority_packet_promotes_lane_without_package_promotion(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
        {"schema_id": "audit", "status": "PASS", "outcome": "OK", "next_lawful_move": "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE"},
    )
    _write_json(
        reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_packet.json",
        {
            "schema_id": "prep_packet",
            "status": "PASS",
            "canonical_scope_manifest_v2": {"authoritative_branch": "main"},
            "noncanonical_quarantine_candidate_list_v2": {"candidates": ["KT-Codex/**"]},
            "promotion_safe_boundary_recommendations_v2": ["keep package deferred"],
        },
    )
    _write_json(
        reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json",
        {"schema_id": "prep_receipt", "status": "PASS", "outcome": "POST_F_TRUST_ZONE_BOUNDARY_PURIFICATION_PREP_DEFINED__NON_AUTHORITATIVE"},
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        audit_receipt_path=reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
        prep_packet_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_packet.json",
        prep_receipt_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["authoritative_lane"] == tranche.REQUIRED_BRANCH
    assert "package promotion or stage_and_promote.sh execution" in packet["mutable_surface_contract"]["forbidden_mutations"]
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE


def test_trust_zone_boundary_authority_packet_requires_audit_authorization(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
        {"schema_id": "audit", "status": "PASS", "next_lawful_move": "SOMETHING_ELSE"},
    )
    _write_json(reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_packet.json", {"schema_id": "prep_packet", "status": "PASS"})
    _write_json(reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json", {"schema_id": "prep_receipt", "status": "PASS"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    try:
        tranche.run(
            reports_root=reports,
            audit_receipt_path=reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
            prep_packet_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_packet.json",
            prep_receipt_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json",
        )
    except RuntimeError as exc:
        assert "authorize trust-zone boundary purification promotion" in str(exc)
    else:
        raise AssertionError("expected missing audit authorization to fail closed")
