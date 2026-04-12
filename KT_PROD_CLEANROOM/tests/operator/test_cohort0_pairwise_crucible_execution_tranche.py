from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT
from tools.operator import cohort0_pairwise_crucible_execution_tranche as tranche


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def _family_rows(family_id: str, target_lobe_id: str, primary_axis: str, secondary_axis: str, preferred: str, control_family: bool) -> list[dict]:
    levels = [
        ("L1", 0.45, 0.25),
        ("L2", 0.60, 0.40),
        ("L3", 0.75, 0.55),
        ("L4", 0.90, 0.70),
    ]
    frames = ("PRIMARY_DECISION", "AXIS_INTERACTION", "PROOF_CHECK", "RECOVERY_HANDOFF")
    rows: list[dict] = []
    for level_id, primary_intensity, secondary_intensity in levels:
        for frame_id in frames:
            rows.append(
                {
                    "case_id": f"{family_id}__{level_id}__{frame_id}",
                    "family_id": family_id,
                    "target_lobe_id": target_lobe_id,
                    "control_family": control_family,
                    "primary_pressure_axis": primary_axis,
                    "secondary_pressure_axis": secondary_axis,
                    "primary_intensity_level_id": level_id,
                    "primary_intensity": primary_intensity,
                    "secondary_intensity": secondary_intensity,
                    "prompt_frame_id": frame_id,
                    "preferred_policy_outcome": preferred,
                }
            )
    return rows


def test_pairwise_crucible_execution_tranche_emits_phase_transition_and_route_economics(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative_pairwise_execution"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    manifest_path = reports_root / "pairwise_crucible_input_manifest.json"
    registry_path = reports_root / "pairwise_crucible_registry.json"
    ladder_path = reports_root / "pairwise_pressure_ladder.json"
    failures_path = reports_root / "pairwise_expected_failure_modes.json"
    receipt_path = reports_root / "pairwise_crucible_receipt.json"
    transfer_guard_path = tmp_path / "lab_to_counted_transfer_guard.json"
    verdict_path = tmp_path / "counted_lane_verdict_grammar.json"

    families = [
        ("P2_SIGNAL_NOISE_SEPARATION", "lobe.p2.v1", "AMBIGUITY_NOISE_DENSITY", "CROSS_DOMAIN_OVERLAY", tranche.ROUTE, False),
        ("STRATEGIST_CONSEQUENCE_CHAIN", "lobe.strategist.v1", "HOP_DEPTH", "TEMPORAL_DISTORTION", tranche.ROUTE, False),
        ("SCOUT_SPARSE_SEARCH", "lobe.scout.v1", "SPARSE_BRANCH_BREADTH", "CAUSAL_BRANCHING", tranche.ROUTE, False),
        ("AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "lobe.auditor.v1", "PROOF_DISCIPLINE_BURDEN", "ADVERSARIAL_AMBIGUITY", tranche.ROUTE, False),
        ("BETA_SECOND_ORDER_REFRAME", "lobe.beta.v1", "PARADOX_PRESSURE", "CROSS_DOMAIN_OVERLAY", tranche.ROUTE, False),
        ("BOUNDARY_ABSTENTION_CONTROL", "", "AMBIGUITY_ESCALATION", "CONSTITUTIONAL_BOUNDARY_PRESSURE", tranche.ABSTAIN, True),
        ("STATIC_NO_ROUTE_CONTROL", "lobe.alpha.v1", "STATIC_HOLD_STABILITY", "NO_REGRESSION_GUARD", tranche.STATIC, True),
    ]

    manifest_rows = []
    registry_rows = []
    ladder_rows = []
    failure_rows = []
    for family_id, target_lobe_id, primary_axis, secondary_axis, preferred, control_family in families:
        relpath = f"pairwise_inputs/{family_id}/pairwise_inputs.jsonl"
        _write_jsonl(reports_root / relpath, _family_rows(family_id, target_lobe_id, primary_axis, secondary_axis, preferred, control_family))
        manifest_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": target_lobe_id,
                "control_family": control_family,
                "input_relpath": relpath,
                "line_count": 16,
                "preferred_policy_outcome": preferred,
                "primary_pressure_axis": primary_axis,
                "secondary_pressure_axis": secondary_axis,
            }
        )
        registry_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": target_lobe_id,
                "control_family": control_family,
                "expected_policy_outcome": preferred,
                "primary_pressure_axis": primary_axis,
                "secondary_pressure_axis": secondary_axis,
            }
        )
        ladder_rows.append(
            {
                "family_id": family_id,
                "primary_pressure_axis": primary_axis,
                "secondary_pressure_axis": secondary_axis,
                "levels": [
                    {"level_id": "L1", "primary_intensity": 0.45, "secondary_intensity": 0.25},
                    {"level_id": "L2", "primary_intensity": 0.60, "secondary_intensity": 0.40},
                    {"level_id": "L3", "primary_intensity": 0.75, "secondary_intensity": 0.55},
                    {"level_id": "L4", "primary_intensity": 0.90, "secondary_intensity": 0.70},
                ],
            }
        )
        failure_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "expected_pairwise_gain": "Sharpen without destabilizing controls.",
                "pairwise_invalidation_condition": "Void if controls regress or attribution collapses.",
            }
        )

    _write_json(
        manifest_path,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "control_family_ids": ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"],
            "family_rows": manifest_rows,
        },
    )
    _write_json(registry_path, {"status": "PASS", "subject_head": subject_head, "rows": registry_rows})
    _write_json(ladder_path, {"status": "PASS", "subject_head": subject_head, "rows": ladder_rows})
    _write_json(failures_path, {"status": "PASS", "subject_head": subject_head, "rows": failure_rows})
    _write_json(receipt_path, {"status": "PASS", "subject_head": subject_head, "next_lawful_move": "EXECUTE_PAIRWISE_CRUCIBLE_SWEEPS__LAB_ONLY"})
    _write_json(transfer_guard_path, {"status": "PASS", "subject_head": subject_head})
    _write_json(verdict_path, {"status": "PASS", "subject_head": subject_head})

    payload = tranche.run_pairwise_crucible_execution_tranche(
        input_manifest_path=manifest_path,
        registry_path=registry_path,
        ladder_path=ladder_path,
        failures_path=failures_path,
        input_receipt_path=receipt_path,
        transfer_guard_path=transfer_guard_path,
        verdict_grammar_path=verdict_path,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["pairwise_crucible_execution_receipt"]
    control_validation = payload["pairwise_control_validation"]
    transfer = payload["pairwise_transfer_eligibility"]
    phase = payload["pairwise_phase_transition_report"]
    economics = payload["pairwise_route_economics_scorecard"]

    assert receipt["status"] == "PASS"
    assert receipt["pairwise_execution_posture"] == tranche.POSTURE
    assert control_validation["controls_preserved"] is True
    assert set(receipt["provisional_ready_family_ids"]) == {
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
    }
    assert "P2_SIGNAL_NOISE_SEPARATION" in transfer["lab_hold_family_ids"]
    phase_rows = {row["family_id"]: row for row in phase["rows"]}
    econ_rows = {row["family_id"]: row for row in economics["rows"]}
    assert phase_rows["STRATEGIST_CONSEQUENCE_CHAIN"]["transition_detected"] is True
    assert econ_rows["STRATEGIST_CONSEQUENCE_CHAIN"]["route_economics_positive"] is True

    tracked = json.loads((reports_root / "pairwise_crucible_execution_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_PAIRWISE_CRUCIBLE_EXECUTION_RECEIPT"
