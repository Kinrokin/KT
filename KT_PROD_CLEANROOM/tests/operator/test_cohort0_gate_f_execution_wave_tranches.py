from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_gate_f_buyer_safe_language_packet_tranche as language_tranche
from tools.operator import cohort0_gate_f_deployment_smoke_and_tenant_isolation_tranche as deploy_tranche
from tools.operator import cohort0_gate_f_external_workload_pilot_tranche as pilot_tranche
from tools.operator import cohort0_gate_f_fresh_operator_bootstrap_and_greenline_tranche as bootstrap_tranche
from tools.operator import cohort0_gate_f_product_truth_and_governance_contract_tranche as governance_tranche
from tools.operator import cohort0_gate_f_narrow_wedge_scope_packet_tranche as scope_tranche
from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


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


def test_gate_f_execution_waves_bind(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    for module in (
        scope_tranche,
        governance_tranche,
        deploy_tranche,
        bootstrap_tranche,
        pilot_tranche,
        language_tranche,
    ):
        monkeypatch.setattr(module, "repo_root", lambda: tmp_path)

    monkeypatch.setattr(deploy_tranche.common, "run_public_verifier_smoke", lambda *, root, output_path: _fake_smoke(output_path))
    monkeypatch.setattr(pilot_tranche.common, "run_public_verifier_smoke", lambda *, root, output_path: _fake_smoke(output_path))

    scope_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
    )
    governance_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
    )
    deploy_result = deploy_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
        governance_contract_path=reports / governance_tranche.OUTPUT_PACKET,
    )
    assert deploy_result["wave_outcome"] == deploy_tranche.WAVE_OUTCOME

    bootstrap_result = bootstrap_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
        deployment_wave_receipt_path=reports / deploy_tranche.OUTPUT_RECEIPT,
    )
    assert bootstrap_result["wave_outcome"] == bootstrap_tranche.WAVE_OUTCOME

    pilot_result = pilot_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
        deployment_wave_receipt_path=reports / deploy_tranche.OUTPUT_RECEIPT,
        bootstrap_wave_receipt_path=reports / bootstrap_tranche.OUTPUT_RECEIPT,
    )
    assert pilot_result["pilot_outcome"] == pilot_tranche.PILOT_OUTCOME

    language_result = language_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
        pilot_receipt_path=reports / pilot_tranche.OUTPUT_RECEIPT,
    )
    assert language_result["packet_outcome"] == language_tranche.PACKET_OUTCOME

    pilot_packet = _load(reports / pilot_tranche.OUTPUT_PACKET)
    assert pilot_packet["pilot_definition"]["single_tenant_only"] is True
    assert pilot_packet["pilot_results"]["detached_receipt_status"] == "PASS"
