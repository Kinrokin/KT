from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_gate_f_product_truth_and_governance_contract_tranche as governance_tranche
from tools.operator import cohort0_gate_f_narrow_wedge_scope_packet_tranche as scope_tranche
from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_gate_f_scope_and_governance_bind(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    monkeypatch.setattr(scope_tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(governance_tranche, "repo_root", lambda: tmp_path)

    scope_result = scope_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
    )
    assert scope_result["scope_outcome"] == scope_tranche.SCOPE_OUTCOME

    scope_packet = _load(reports / scope_tranche.OUTPUT_PACKET)
    assert scope_packet["wedge_surface"]["active_profile_id"] == "local_verifier_mode"
    assert scope_packet["authority_header"]["gate_e_open_on_successor_line"] is True

    governance_result = governance_tranche.run(
        reports_root=reports,
        branch_law_packet_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        supersession_note_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        orchestrator_receipt_path=tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cohort0_successor_master_orchestrator_receipt.json",
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
    )
    assert governance_result["contract_outcome"] == governance_tranche.CONTRACT_OUTCOME

    governance_packet = _load(reports / governance_tranche.OUTPUT_PACKET)
    assert governance_packet["gate_f_governance_bundle"]["tenant_posture_required"] == "SINGLE_TENANT_ONLY_DECLARED"
    assert governance_packet["gate_f_comparator_definition"]["bounded_surface_under_review"] == scope_packet["wedge_surface"]["wedge_id"]
