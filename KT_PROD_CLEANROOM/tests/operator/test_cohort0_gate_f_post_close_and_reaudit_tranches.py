from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_gate_f_buyer_safe_language_packet_tranche as language_tranche
from tools.operator import cohort0_gate_f_deployment_smoke_and_tenant_isolation_tranche as deploy_tranche
from tools.operator import cohort0_gate_f_external_workload_pilot_tranche as pilot_tranche
from tools.operator import cohort0_gate_f_fresh_operator_bootstrap_and_greenline_tranche as bootstrap_tranche
from tools.operator import cohort0_gate_f_one_narrow_wedge_review_tranche as review_tranche
from tools.operator import (
    cohort0_gate_f_post_close_live_product_truth_tranche as live_product_truth_tranche,
)
from tools.operator import (
    cohort0_gate_f_post_close_supersession_note_tranche as post_f_supersession_tranche,
)
from tools.operator import cohort0_gate_f_product_truth_and_governance_contract_tranche as governance_tranche
from tools.operator import cohort0_gate_f_product_wedge_admissibility_screen_tranche as screen_tranche
from tools.operator import cohort0_gate_f_narrow_wedge_scope_packet_tranche as scope_tranche
from tools.operator import cohort0_post_f_broad_canonical_reaudit_tranche as reaudit_tranche


def _fake_smoke(output_path: Path) -> dict:
    payload = {
        "schema_id": "kt.operator.public_verifier_receipt.v1",
        "status": "PASS",
        "head_claim_verdict": "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE",
        "workflow_governance_status": "PASS_WITH_PLATFORM_BLOCK",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_gate_f_post_close_truth_and_reaudit_bind_minimum_path(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    for module in (
        scope_tranche,
        governance_tranche,
        deploy_tranche,
        bootstrap_tranche,
        pilot_tranche,
        language_tranche,
        screen_tranche,
        review_tranche,
        live_product_truth_tranche,
        post_f_supersession_tranche,
        reaudit_tranche,
    ):
        monkeypatch.setattr(module, "repo_root", lambda: tmp_path)

    monkeypatch.setattr(deploy_tranche.common, "run_public_verifier_smoke", lambda *, root, output_path: _fake_smoke(output_path))
    monkeypatch.setattr(pilot_tranche.common, "run_public_verifier_smoke", lambda *, root, output_path: _fake_smoke(output_path))

    branch_law_packet = tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json"
    branch_law_receipt = tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_receipt.json"
    supersession_note = tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json"
    orchestrator_receipt = tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json"

    scope_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
    )
    governance_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
    )
    deploy_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
        governance_contract_path=reports / governance_tranche.OUTPUT_PACKET,
    )
    bootstrap_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        deployment_wave_receipt_path=reports / deploy_tranche.OUTPUT_RECEIPT,
    )
    pilot_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        deployment_wave_receipt_path=reports / deploy_tranche.OUTPUT_RECEIPT,
        bootstrap_wave_receipt_path=reports / bootstrap_tranche.OUTPUT_RECEIPT,
    )
    language_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        pilot_receipt_path=reports / pilot_tranche.OUTPUT_RECEIPT,
    )
    screen_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
        governance_contract_path=reports / governance_tranche.OUTPUT_PACKET,
        deployment_wave_receipt_path=reports / deploy_tranche.OUTPUT_RECEIPT,
        bootstrap_wave_receipt_path=reports / bootstrap_tranche.OUTPUT_RECEIPT,
        pilot_receipt_path=reports / pilot_tranche.OUTPUT_RECEIPT,
        language_receipt_path=reports / language_tranche.OUTPUT_RECEIPT,
    )
    review_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        screen_receipt_path=reports / screen_tranche.OUTPUT_RECEIPT,
    )

    truth_result = live_product_truth_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
        governance_contract_path=reports / governance_tranche.OUTPUT_PACKET,
        deployment_receipt_path=reports / deploy_tranche.OUTPUT_RECEIPT,
        bootstrap_receipt_path=reports / bootstrap_tranche.OUTPUT_RECEIPT,
        pilot_receipt_path=reports / pilot_tranche.OUTPUT_RECEIPT,
        language_receipt_path=reports / language_tranche.OUTPUT_RECEIPT,
        screen_receipt_path=reports / screen_tranche.OUTPUT_RECEIPT,
        review_packet_path=reports / review_tranche.OUTPUT_PACKET,
        review_receipt_path=reports / review_tranche.OUTPUT_RECEIPT,
    )
    assert truth_result["current_product_posture"] == live_product_truth_tranche.common.GATE_F_CONFIRMED_POSTURE

    supersession_result = post_f_supersession_tranche.run(
        reports_root=reports,
        live_product_truth_packet_path=reports / live_product_truth_tranche.OUTPUT_PACKET,
        live_product_truth_receipt_path=reports / live_product_truth_tranche.OUTPUT_RECEIPT,
    )
    assert supersession_result["note_path"].endswith(post_f_supersession_tranche.OUTPUT_NOTE)

    reaudit_result = reaudit_tranche.run(
        reports_root=reports,
        branch_law_packet_path=branch_law_packet,
        branch_law_receipt_path=branch_law_receipt,
        supersession_note_path=supersession_note,
        orchestrator_receipt_path=orchestrator_receipt,
        gate_f_review_receipt_path=reports / review_tranche.OUTPUT_RECEIPT,
        live_product_truth_packet_path=reports / live_product_truth_tranche.OUTPUT_PACKET,
        live_product_truth_receipt_path=reports / live_product_truth_tranche.OUTPUT_RECEIPT,
        post_f_supersession_note_path=reports / post_f_supersession_tranche.OUTPUT_NOTE,
        post_f_supersession_receipt_path=reports / post_f_supersession_tranche.OUTPUT_RECEIPT,
    )
    assert reaudit_result["next_lawful_move"] == live_product_truth_tranche.common.NEXT_MOVE_POST_F_EXPANSION

    truth_receipt = _load(reports / live_product_truth_tranche.OUTPUT_RECEIPT)
    supersession_note_payload = _load(reports / post_f_supersession_tranche.OUTPUT_NOTE)
    reaudit_receipt = _load(reports / reaudit_tranche.OUTPUT_RECEIPT)
    blocker_ledger = _load(reports / reaudit_tranche.OUTPUT_BLOCKER_LEDGER)

    assert truth_receipt["current_product_posture"] == live_product_truth_tranche.common.GATE_F_CONFIRMED_POSTURE
    assert truth_receipt["gate_f_open"] is False
    assert supersession_note_payload[
        "gate_f_post_close_live_product_truth_supersedes_prior_product_headers_for_live_posture"
    ] is True
    assert len(supersession_note_payload["historically_valid_but_live_superseded_surfaces"]) == 5
    assert reaudit_receipt["reaudit_outcome"] == reaudit_tranche.OUTCOME_PASS
    assert reaudit_receipt["controlled_post_f_expansion_tracks_authorized_now"] is True
    assert blocker_ledger["ranked_missing_predicates"] == []
