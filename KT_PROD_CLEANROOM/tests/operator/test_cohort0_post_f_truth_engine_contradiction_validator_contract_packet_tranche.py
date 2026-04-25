from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_truth_engine_contradiction_validator_contract_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_truth_engine_contract_packet_binds_seven_contract_sections(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    governance = tmp_path / "KT_PROD_CLEANROOM" / "governance"

    _write_json(
        reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
        {
            "schema_id": "authority-packet",
            "status": "PASS",
            "authoritative_scope": {
                "posture_enum": ["CANONICAL_MAIN_LIVE_TRUTH"],
                "truth_engine_contract": {"live_posture_must_be_receipt_derived": True},
                "contradiction_rules": ["rule-1"],
                "source_precedence_table": ["main first"],
                "stale_surface_exclusion_logic": {"exclude_untracked_authority": True},
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json",
        {
            "schema_id": "authority-receipt",
            "status": "PASS",
            "lane_outcome": "POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_LANE_OPEN__AUTHORITATIVE_ONLY",
            "next_lawful_move": "AUTHOR_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_CONTRACT_PACKET",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_post_merge_branch_snapshot.json",
        {
            "snapshot_type": "snapshot",
            "retained_non_authoritative_prep_lanes": [
                "trust_zone_boundary_purification_scaffold",
                "residual_proof_law_hardening_scaffold",
            ],
            "package_promotion_split": {
                "auto_promotion_candidate_count": 6,
                "review_approved_auto_skip_count": 3,
                "review_approved_out_of_scope_count": 2,
                "package_promotion_boundary": "explicit later step",
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        {
            "schema_id": "post-merge-receipt",
            "status": "PASS",
            "package_promotion_still_deferred": True,
            "track03_repo_authority_now_canonical": True,
        },
    )
    _write_json(governance / "truth_engine_contract.json", {"schema_id": "legacy", "contract_id": "TRUTH_ENGINE_CONTRACT_V2"})
    _write_json(governance / "posture_contract.json", {"schema_id": "posture", "contract_id": "POSTURE_CONTRACT_V1"})
    _write_json(governance / "settled_truth_source_contract.json", {"schema_id": "settled", "contract_id": "SETTLED_TRUTH_SOURCE_CONTRACT_V1"})
    _write_json(governance / "truth_supersession_rules.json", {"schema_id": "supersession", "rules_id": "TRUTH_SUPERSESSION_RULES_V1"})
    _write_json(reports / "reporting_integrity_contract.json", {"schema_id": "reporting", "contract_id": "REPORTING_INTEGRITY_CONTRACT_V1"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-head" if ref == "main" else "branch-head")
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "main-head")

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json",
        post_merge_snapshot_path=reports / "cohort0_post_f_track_03_post_merge_branch_snapshot.json",
        post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        legacy_truth_contract_path=governance / "truth_engine_contract.json",
        posture_contract_path=governance / "posture_contract.json",
        settled_truth_contract_path=governance / "settled_truth_source_contract.json",
        supersession_rules_path=governance / "truth_supersession_rules.json",
        reporting_integrity_contract_path=reports / "reporting_integrity_contract.json",
    )

    assert result["contract_outcome"] == tranche.CONTRACT_OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert len(packet["source_precedence"]) >= 5
    assert len(packet["contradiction_classes"]) == 7
    assert "derivation_law" in packet
    assert "exclusion_law" in packet
    assert "emission_surfaces" in packet
    assert "failure_law" in packet
