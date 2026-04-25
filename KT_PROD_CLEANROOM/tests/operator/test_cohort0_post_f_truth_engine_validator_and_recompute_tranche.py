from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_truth_engine_validator_and_recompute_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_truth_engine_recompute_emits_five_surfaces_and_keeps_remote_pending_advisory(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json", {"schema_id": "a", "status": "PASS"})
    _write_json(reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json", {"schema_id": "b", "status": "PASS", "exclusion_law": {"retained_non_authoritative_prep_lanes": ["prep-a", "prep-b"]}})
    _write_json(
        reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json",
        {
            "schema_id": "c",
            "status": "PASS",
            "emission_surface_schemas": {
                "authority_graph": {"required_fields": ["schema_id", "generated_utc", "branch_ref", "winning_authority_sources", "rejected_conflicting_sources", "precedence_edges"]},
                "posture_index": {"required_fields": ["schema_id", "generated_utc", "theorem_truth_posture", "product_truth_posture", "merge_truth_posture", "package_truth_posture", "winning_source_refs"]},
                "contradiction_ledger": {"required_fields": ["schema_id", "generated_utc", "status", "blocking_contradiction_count", "advisory_contradiction_count", "contradictions"]},
                "stale_source_quarantine_list": {"required_fields": ["schema_id", "generated_utc", "quarantine_candidate_count", "quarantine_candidates"]},
                "recompute_receipt": {"required_fields": ["schema_id", "generated_utc", "status", "branch_ref", "derived_from_contract_id", "authority_graph_ref", "posture_index_ref", "contradiction_ledger_ref", "stale_source_quarantine_list_ref", "blocking_contradiction_count", "next_lawful_move"]},
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json",
        {"schema_id": "d", "status": "PASS", "next_lawful_move": "IMPLEMENT_POST_F_TRUTH_ENGINE_VALIDATOR_AND_RECOMPUTE_TRANCHE"},
    )
    _write_json(
        reports / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        {
            "schema_id": "e",
            "status": "PASS",
            "canonical_live_branch_status": {"gate_d_cleared_on_successor_line": True, "gate_e_open": True},
            "authoritative_live_surfaces": {"successor_master_orchestrator_receipt_ref": "orchestrator-ref"},
        },
    )
    _write_json(
        reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        {
            "schema_id": "f",
            "status": "PASS",
            "canonical_live_product_status": {"gate_f_narrow_wedge_confirmed": True, "gate_f_open": False},
            "authoritative_live_product_surfaces": {"gate_f_review_receipt": "gatef-ref"},
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        {"schema_id": "g", "status": "PASS", "track03_repo_authority_now_canonical": True},
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-head" if ref == "main" else "branch-head")
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "main-head")
    monkeypatch.setattr(tranche, "_remote_main_divergence", lambda root: {"remote_ref_present": True, "remote_ahead_of_local_main": 0, "local_main_ahead_of_remote": 2})

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
        contract_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json",
        schema_packet_path=reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json",
        schema_receipt_path=reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json",
        branch_law_path=reports / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        product_truth_path=reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    receipt = _load(reports / tranche.OUTPUT_RECOMPUTE_RECEIPT)
    ledger = _load(reports / tranche.OUTPUT_CONTRADICTION_LEDGER)
    posture = _load(reports / tranche.OUTPUT_POSTURE_INDEX)

    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert ledger["blocking_contradiction_count"] == 0
    assert ledger["advisory_contradiction_count"] == 1
    assert "TRACK03_PROTECTED_PR_PENDING" in posture["merge_truth_posture"]


def test_truth_engine_recompute_allows_canonical_main_replay_after_pr_merge(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json", {"schema_id": "a", "status": "PASS"})
    _write_json(reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json", {"schema_id": "b", "status": "PASS", "exclusion_law": {"retained_non_authoritative_prep_lanes": []}})
    _write_json(
        reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json",
        {
            "schema_id": "c",
            "status": "PASS",
            "emission_surface_schemas": {
                "authority_graph": {"required_fields": ["schema_id", "generated_utc", "branch_ref", "winning_authority_sources", "rejected_conflicting_sources", "precedence_edges"]},
                "posture_index": {"required_fields": ["schema_id", "generated_utc", "theorem_truth_posture", "product_truth_posture", "merge_truth_posture", "package_truth_posture", "winning_source_refs"]},
                "contradiction_ledger": {"required_fields": ["schema_id", "generated_utc", "status", "blocking_contradiction_count", "advisory_contradiction_count", "contradictions"]},
                "stale_source_quarantine_list": {"required_fields": ["schema_id", "generated_utc", "quarantine_candidate_count", "quarantine_candidates"]},
                "recompute_receipt": {"required_fields": ["schema_id", "generated_utc", "status", "branch_ref", "derived_from_contract_id", "authority_graph_ref", "posture_index_ref", "contradiction_ledger_ref", "stale_source_quarantine_list_ref", "blocking_contradiction_count", "next_lawful_move"]},
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json",
        {"schema_id": "d", "status": "PASS", "next_lawful_move": "IMPLEMENT_POST_F_TRUTH_ENGINE_VALIDATOR_AND_RECOMPUTE_TRANCHE"},
    )
    _write_json(
        reports / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        {
            "schema_id": "e",
            "status": "PASS",
            "canonical_live_branch_status": {"gate_d_cleared_on_successor_line": True, "gate_e_open": True},
            "authoritative_live_surfaces": {"successor_master_orchestrator_receipt_ref": "orchestrator-ref"},
        },
    )
    _write_json(
        reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        {
            "schema_id": "f",
            "status": "PASS",
            "canonical_live_product_status": {"gate_f_narrow_wedge_confirmed": True, "gate_f_open": False},
            "authoritative_live_product_surfaces": {"gate_f_review_receipt": "gatef-ref"},
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        {"schema_id": "g", "status": "PASS", "track03_repo_authority_now_canonical": True},
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.CANONICAL_REPLAY_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-head")
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "main-head")
    monkeypatch.setattr(tranche, "_remote_main_divergence", lambda root: {"remote_ref_present": True, "remote_ahead_of_local_main": 0, "local_main_ahead_of_remote": 0})

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
        contract_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json",
        schema_packet_path=reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json",
        schema_receipt_path=reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json",
        branch_law_path=reports / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        product_truth_path=reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
    )

    receipt = _load(reports / tranche.OUTPUT_RECOMPUTE_RECEIPT)
    ledger = _load(reports / tranche.OUTPUT_CONTRADICTION_LEDGER)
    posture = _load(reports / tranche.OUTPUT_POSTURE_INDEX)

    assert result["outcome"] == tranche.CANONICAL_REPLAY_OUTCOME
    assert receipt["branch_ref"] == "main"
    assert receipt["recompute_scope"] == "CANONICAL_MAIN_REPLAY_CONVERGED"
    assert receipt["next_lawful_move"] == tranche.CANONICAL_REPLAY_NEXT_MOVE
    assert ledger["blocking_contradiction_count"] == 0
    assert ledger["advisory_contradiction_count"] == 0
    assert "TRACK03_PROTECTED_PR_PENDING" not in posture["merge_truth_posture"]


def test_truth_engine_canonical_main_replay_requires_origin_main(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json", {"schema_id": "a", "status": "PASS"})
    _write_json(reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json", {"schema_id": "b", "status": "PASS", "exclusion_law": {"retained_non_authoritative_prep_lanes": []}})
    _write_json(
        reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json",
        {
            "schema_id": "c",
            "status": "PASS",
            "emission_surface_schemas": {
                "authority_graph": {"required_fields": ["schema_id", "generated_utc", "branch_ref", "winning_authority_sources", "rejected_conflicting_sources", "precedence_edges"]},
                "posture_index": {"required_fields": ["schema_id", "generated_utc", "theorem_truth_posture", "product_truth_posture", "merge_truth_posture", "package_truth_posture", "winning_source_refs"]},
                "contradiction_ledger": {"required_fields": ["schema_id", "generated_utc", "status", "blocking_contradiction_count", "advisory_contradiction_count", "contradictions"]},
                "stale_source_quarantine_list": {"required_fields": ["schema_id", "generated_utc", "quarantine_candidate_count", "quarantine_candidates"]},
                "recompute_receipt": {"required_fields": ["schema_id", "generated_utc", "status", "branch_ref", "derived_from_contract_id", "authority_graph_ref", "posture_index_ref", "contradiction_ledger_ref", "stale_source_quarantine_list_ref", "blocking_contradiction_count", "next_lawful_move"]},
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json",
        {"schema_id": "d", "status": "PASS", "next_lawful_move": "IMPLEMENT_POST_F_TRUTH_ENGINE_VALIDATOR_AND_RECOMPUTE_TRANCHE"},
    )
    _write_json(reports / "cohort0_successor_gate_d_post_clear_branch_law_packet.json", {"schema_id": "e", "status": "PASS"})
    _write_json(reports / "cohort0_gate_f_post_close_live_product_truth_packet.json", {"schema_id": "f", "status": "PASS"})
    _write_json(reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json", {"schema_id": "g", "status": "PASS"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.CANONICAL_REPLAY_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-head")
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "main-head")
    monkeypatch.setattr(tranche, "_remote_main_divergence", lambda root: {"remote_ref_present": False, "remote_ahead_of_local_main": 0, "local_main_ahead_of_remote": 0})

    try:
        tranche.run(
            reports_root=reports,
            authority_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
            contract_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json",
            schema_packet_path=reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json",
            schema_receipt_path=reports / "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json",
            branch_law_path=reports / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
            product_truth_path=reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
            post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        )
    except RuntimeError as exc:
        assert "origin/main to be present" in str(exc)
    else:
        raise AssertionError("expected canonical replay to fail closed without origin/main")
