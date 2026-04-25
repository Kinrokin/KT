from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_parallel_prep_scaffold_packets_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_parallel_prep_scaffolds_emit_four_lane_packets(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    governance = tmp_path / "KT_PROD_CLEANROOM" / "governance"

    _write_json(
        reports / "cohort0_post_f_parallel_prep_lane_matrix_packet.json",
        {"schema_id": "matrix", "status": "PASS"},
    )
    _write_json(
        reports / "cohort0_post_f_track_03_human_review_packet.json",
        {
            "schema_id": "review-packet",
            "status": "PASS",
            "review_evidence_bundle": {
                "current_head_receipt_ref": "head.json",
                "counted_path_receipt_ref": "counted.json",
                "proof_bundle_ref": "bundle.tgz",
                "proof_signature_ref": "bundle.sig",
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_human_review_receipt.json",
        {
            "schema_id": "review-receipt",
            "status": "PASS",
            "subject_head": "track03-head",
            "next_lawful_move": tranche.AUTHORITATIVE_NEXT_MOVE,
        },
    )
    _write_json(reports / "legacy_quarantine_receipt.json", {"status": "PASS"})
    _write_json(reports / "reporting_integrity_contract.json", {"status": "ACTIVE"})
    _write_json(reports / "kt_unified_convergence_contradiction_table.json", {"rows": []})
    _write_json(governance / "adapter_lifecycle_law.json", {"status": "ACTIVE"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_WORKING_BRANCH)
    monkeypatch.setattr(tranche, "_current_head", lambda root: "prep-scaffold-head")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        matrix_packet_path=reports / "cohort0_post_f_parallel_prep_lane_matrix_packet.json",
        human_review_packet_path=reports / "cohort0_post_f_track_03_human_review_packet.json",
        human_review_receipt_path=reports / "cohort0_post_f_track_03_human_review_receipt.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    trust_zone = _load(reports / tranche.OUTPUT_TRUST_ZONE_PACKET)
    truth_engine = _load(reports / tranche.OUTPUT_TRUTH_ENGINE_PACKET)
    proof_law = _load(reports / tranche.OUTPUT_PROOF_LAW_PACKET)
    upper_stack = _load(reports / tranche.OUTPUT_UPPER_STACK_PACKET)

    assert receipt["lane_packet_count"] == 4
    assert trust_zone["lane_id"] == "trust_zone_boundary_purification_scaffold"
    assert truth_engine["lane_id"] == "truth_engine_contradiction_validator_scaffold"
    assert proof_law["lane_id"] == "residual_proof_law_hardening_scaffold"
    assert upper_stack["lane_id"] == "upper_stack_ratification_scaffold"
