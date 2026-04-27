from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_candidate_v2_source as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base() -> dict:
    return {
        "status": "PASS",
        "current_git_head": "revision-head",
        "subject_main_head": "prior-head",
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _blind_rows() -> list[dict]:
    rows = [
        ("R6B01", "math", "adjacent_quantitative_pressure", "fresh_heldout_design"),
        ("R6B02", "poetry", "form_shift_pressure", "fresh_heldout_design"),
        ("R6B03", "governance", "counterfactual_review_pressure", "fresh_heldout_design"),
        ("R6B04", "default", "unknown_family_static_hold_pressure", "fresh_heldout_design"),
        ("R6B05", "mixed_math_governance", "multi_family_abstention_pressure", "mutated_sibling_not_label_derived"),
        ("R6B06", "masked_ambiguous", "masked_family_route_pressure", "fresh_heldout_design"),
    ]
    return [
        {
            "case_id": case_id,
            "family": family,
            "pressure_type": pressure,
            "source_kind": source_kind,
            "source_sha256": f"{case_id.lower()}-hash",
            "mirror_masked_required": True,
            "old_r01_r04_derived": False,
            "static_baseline_labels_blinded_until_counted_screen": True,
            "candidate_v2_training_label_visible": False,
        }
        for case_id, family, pressure, source_kind in rows
    ]


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    common = {**_base(), "next_lawful_move": tranche.EXPECTED_PRIOR_NEXT_MOVE}
    blind_rows = _blind_rows()
    payloads = {
        "revision_packet": {**common, "schema_id": "revision_packet", "verdict": tranche.EXPECTED_PRIOR_VERDICT},
        "revision_receipt": {
            **common,
            "schema_id": "revision_receipt",
            "verdict": tranche.EXPECTED_PRIOR_VERDICT,
            "candidate_revision_authorized": True,
            "candidate_v2_generation_performed": False,
            "candidate_v2_screen_execution_authorized": False,
        },
        "blind_contract": {
            **common,
            "schema_id": "blind_contract",
            "row_count": 6,
            "candidate_rows": blind_rows,
            "holdout_policy": {
                "candidate_v2_may_not_train_on_counted_labels": True,
                "static_comparator_labels_blinded_until_counted_screen": True,
            },
        },
        "v2_source_requirements": {
            **common,
            "schema_id": "requirements",
            "candidate_v2_source_requirements": {
                "deterministic": True,
                "hash_bound": True,
                "seed_bound": True,
                "trace_emitting": True,
                "abstention_aware": True,
                "static_hold_preserving": True,
                "no_package_promotion_dependency": True,
                "no_truth_engine_mutation_dependency": True,
                "no_trust_zone_mutation_dependency": True,
                "must_not_train_on_new_blind_screen_labels": True,
                "must_not_reuse_r01_r04_as_counted_screen": True,
            },
        },
        "v2_feature_requirements": {
            **common,
            "schema_id": "feature_requirements",
            "candidate_v2_feature_requirements": [
                "visible_family_policy",
                "static_hold_preservation",
                "abstention_aware_trace",
            ],
            "new_blind_universe_labels_available": False,
        },
        "overfit_guard": {
            **common,
            "schema_id": "overfit",
            "new_blind_universe_required": True,
        },
        "feature_gap_matrix": {
            **common,
            "schema_id": "feature_gap",
            "rows": [
                {"case_id": "R01", "family": "math", "diagnostic_use_allowed": True, "candidate_v2_training_target_allowed": False},
                {"case_id": "R02", "family": "poetry", "diagnostic_use_allowed": True, "candidate_v2_training_target_allowed": False},
            ],
        },
        "static_dominance": {
            **common,
            "schema_id": "static",
            "static_dominance_on_screen1": True,
            "candidate_wins_on_screen1": 0,
            "static_baseline_weakening_allowed": False,
        },
        "blind_candidate_set": {**common, "schema_id": "candidate_set", "rows": blind_rows},
    }
    for role, payload in payloads.items():
        _write_json(root / tranche.INPUTS[role], payload)
    return reports


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "candidate-v2-head")


def test_candidate_v2_source_generates_admissible_candidate_without_screen_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["admissibility_receipt"])
    source_receipt = _load(reports / tranche.OUTPUTS["source_receipt"])
    contamination = _load(reports / tranche.OUTPUTS["no_contamination_receipt"])
    separation = _load(reports / tranche.OUTPUTS["blind_separation_receipt"])
    next_receipt = _load(reports / tranche.OUTPUTS["next_lawful_move_receipt"])
    candidate_path = tmp_path / tranche.CANDIDATE_SOURCE_REL

    assert result["verdict"] == tranche.FINAL_VERDICT
    assert candidate_path.is_file()
    assert receipt["candidate_v2_admissible"] is True
    assert receipt["second_shadow_screen_executed"] is False
    assert receipt["learned_router_superiority_earned"] is False
    assert source_receipt["second_shadow_screen_authorization_next"] is True
    assert contamination["new_blind_universe_labels_used"] is False
    assert separation["candidate_saw_only_visible_fields"] is True
    assert next_receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE


def test_candidate_v2_source_fails_closed_if_blind_row_labels_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    blind = _load(reports / "b04_r6_new_blind_input_universe_contract.json")
    blind["candidate_rows"][0]["candidate_v2_training_label_visible"] = True
    _write_json(reports / "b04_r6_new_blind_input_universe_contract.json", blind)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="blind universe"):
        tranche.run(reports_root=reports)


def test_candidate_v2_source_fails_closed_if_prior_next_move_wrong(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    revision_receipt = _load(reports / "b04_r6_candidate_revision_receipt.json")
    revision_receipt["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write_json(reports / "b04_r6_candidate_revision_receipt.json", revision_receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="candidate v2 source packet"):
        tranche.run(reports_root=reports)


def test_candidate_v2_source_fails_closed_if_cutover_authorized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    revision_receipt = _load(reports / "b04_r6_candidate_revision_receipt.json")
    revision_receipt["learned_router_cutover_authorized"] = True
    _write_json(reports / "b04_r6_candidate_revision_receipt.json", revision_receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="learned_router_cutover_authorized"):
        tranche.run(reports_root=reports)


def test_candidate_v2_source_fails_closed_if_blind_rows_malformed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    blind = _load(reports / "b04_r6_new_blind_input_universe_contract.json")
    blind["candidate_rows"] = [blind["candidate_rows"][0], "not-a-row", None, 4, [], True]
    _write_json(reports / "b04_r6_new_blind_input_universe_contract.json", blind)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="row 1 must be an object"):
        tranche.run(reports_root=reports)


def test_contamination_scan_blocks_blind_case_id_in_source() -> None:
    with pytest.raises(RuntimeError, match="forbidden blind-label"):
        tranche._contamination_scan("route = 'R6B01'", _blind_rows())
