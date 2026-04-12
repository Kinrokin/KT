from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_crucible_escalation_packet_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_crucible_escalation_packet_stays_lab_only_and_emits_transfer_rule(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    diagnosis = tmp_path / "router_failure_diagnosis_packet.json"
    stage_pack_manifest = tmp_path / "route_bearing_stage_pack_manifest.json"
    oracle_scorecard = tmp_path / "oracle_router_local_scorecard.json"
    lobe_survival = tmp_path / "lobe_survival_verdicts.json"
    alpha_manifest = tmp_path / "alpha_should_lose_here_manifest.json"
    negative_ledger = tmp_path / "negative_result_ledger.json"

    _write_json(diagnosis, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        stage_pack_manifest,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "family_rows": [
                {
                    "family_id": "P2_SIGNAL_NOISE_SEPARATION",
                    "target_lobe_id": "lobe.p2.v1",
                    "alpha_liability": "Alpha blurs decisive and decorative constraints.",
                },
                {
                    "family_id": "STATIC_NO_ROUTE_CONTROL",
                    "target_lobe_id": "lobe.alpha.v1",
                    "alpha_liability": "No liability should be asserted on true static controls.",
                },
            ],
        },
    )
    _write_json(
        oracle_scorecard,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "oracle_positive_family_ids": ["P2_SIGNAL_NOISE_SEPARATION"],
        },
    )
    _write_json(lobe_survival, {"status": "PASS"})
    _write_json(alpha_manifest, {"status": "PASS"})
    _write_json(negative_ledger, {"status": "PASS"})

    payload = tranche.run_crucible_escalation_packet_tranche(
        diagnosis_path=diagnosis,
        stage_pack_manifest_path=stage_pack_manifest,
        oracle_scorecard_path=oracle_scorecard,
        lobe_survival_path=lobe_survival,
        alpha_manifest_path=alpha_manifest,
        negative_ledger_path=negative_ledger,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    packet = payload["crucible_escalation_packet"]
    registry = payload["crucible_registry"]

    assert packet["status"] == "PASS"
    assert packet["packet_posture"] == "LAB_FULL_POWER_READY__COUNTED_PROOF_LANE_STILL_SEPARATE"
    assert packet["counted_lane_contamination_forbidden"] is True
    assert packet["transfer_rule"]["named_wedge_sharpening_required"] is True
    assert packet["transfer_rule"]["new_admissible_eval_family_required"] is True
    assert packet["next_lawful_move"] == "AUTHOR_SINGLE_AXIS_CRUCIBLE_INPUTS_AND_EXECUTE_LAB_ONLY_SWEEPS"
    assert registry["entry_count"] >= 3

    tracked = json.loads((reports_root / "cohort0_crucible_escalation_packet.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_COHORT0_CRUCIBLE_ESCALATION_PACKET"
