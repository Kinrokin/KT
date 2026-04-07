from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_router_shadow_state_binding_tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def test_cohort0_router_shadow_state_binding_tranche_rebinds_r4_state_surfaces(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    current_overlay = tmp_path / "current_campaign_state_overlay.json"
    next_workstream = tmp_path / "next_counted_workstream_contract.json"
    resume = tmp_path / "resume_blockers_receipt.json"
    reanchor = tmp_path / "gate_d_decision_reanchor_packet.json"

    current_overlay.write_text(
        (ROOT / "KT_PROD_CLEANROOM" / "reports" / "current_campaign_state_overlay.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    next_workstream.write_text(
        (ROOT / "KT_PROD_CLEANROOM" / "reports" / "next_counted_workstream_contract.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    resume.write_text(
        (ROOT / "KT_PROD_CLEANROOM" / "reports" / "resume_blockers_receipt.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    reanchor.write_text(
        (ROOT / "KT_PROD_CLEANROOM" / "reports" / "gate_d_decision_reanchor_packet.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = cohort0_router_shadow_state_binding_tranche.run_router_shadow_state_binding_tranche(
        followthrough_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_real_engine_tournament_followthrough_packet.json",
        promotion_outcome_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_promotion_outcome_binding_receipt.json",
        merge_outcome_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_merge_outcome_binding_receipt.json",
        current_overlay_path=current_overlay,
        next_workstream_path=next_workstream,
        resume_blockers_path=resume,
        reanchor_packet_path=reanchor,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["router_shadow_state_binding_receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["binding_posture"] == "PROMOTION_AND_MERGE_OUTCOME_BOUND__R4_CURRENT_HEAD_STATE_SURFACES_READY"
    assert receipt["next_lawful_move"] == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"

    overlay_obj = json.loads(current_overlay.read_text(encoding="utf-8"))
    next_obj = json.loads(next_workstream.read_text(encoding="utf-8"))
    resume_obj = json.loads(resume.read_text(encoding="utf-8"))
    reanchor_obj = json.loads(reanchor.read_text(encoding="utf-8"))
    tracked = json.loads((reports_root / "cohort0_router_shadow_state_binding_receipt.json").read_text(encoding="utf-8"))

    assert overlay_obj["next_counted_workstream_id"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert overlay_obj["repo_state_executable_now"] is True
    assert next_obj["exact_next_counted_workstream_id"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert next_obj["execution_mode"] == "CIVILIZATION_RATIFICATION_ORDER_LOCKED__FIFTH_STEP_ONLY"
    assert next_obj["repo_state_executable_now"] is True
    assert resume_obj["exact_next_counted_workstream_id"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert resume_obj["repo_state_executable_now"] is True
    assert reanchor_obj["next_lawful_move"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_ROUTER_SHADOW_STATE_BINDING_RECEIPT"
