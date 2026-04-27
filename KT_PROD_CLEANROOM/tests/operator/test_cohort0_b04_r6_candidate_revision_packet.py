from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_candidate_revision_packet as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base() -> dict:
    return {
        "status": "PASS",
        "current_git_head": "prior-head",
        "subject_main_head": "screen-head",
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_activated": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    common = {**_base(), "next_lawful_move": tranche.EXPECTED_PRIOR_NEXT_MOVE}
    payloads = {
        "revision_or_closeout_packet": {
            **common,
            "schema_id": "packet",
            "selected_outcome": tranche.EXPECTED_PRIOR_VERDICT,
        },
        "revision_or_closeout_receipt": {
            **common,
            "schema_id": "receipt",
            "verdict": tranche.EXPECTED_PRIOR_VERDICT,
            "candidate_revision_allowed_next": True,
            "candidate_v2_generation_performed": False,
            "input_universe_for_next_counted_screen_must_be_new_or_blinded": True,
            "shadow_screen_execution_performed": False,
        },
        "prior_failure_autopsy_receipt": {
            **common,
            "schema_id": "autopsy",
            "candidate_wins_over_static": "0/4",
            "clean_failure": True,
            "failure_classes": {
                "static_comparator_dominance": True,
                "candidate_underfitting": True,
                "feature_insufficiency": True,
            },
        },
        "prior_per_row_failure_matrix": {
            **common,
            "schema_id": "per_row",
            "rows": [
                {"case_id": "R01", "family": "math", "candidate_beats_static": False},
                {"case_id": "R02", "family": "poetry", "candidate_beats_static": False},
                {"case_id": "R03", "family": "governance", "candidate_beats_static": False},
                {"case_id": "R04", "family": "default", "candidate_beats_static": False},
            ],
        },
        "prior_candidate_static_delta_matrix": {
            **common,
            "schema_id": "delta",
            "summary": {"candidate_win_count": 0, "case_count": 4, "static_comparator_dominance": True},
        },
        "prior_revision_eligibility_receipt": {
            **common,
            "schema_id": "eligibility",
            "revision_path_plausible": True,
            "same_r01_r04_reuse_for_counted_superiority_screen_allowed": False,
            "new_blind_input_universe_required": True,
        },
        "prior_revision_blocker_ledger": {
            **common,
            "schema_id": "blockers",
            "live_blocker_count": 2,
            "entries": [{"blocker_id": "B04_R6_NEXT_COUNTED_SCREEN_REQUIRES_NEW_BLIND_INPUT_UNIVERSE"}],
        },
        "prior_input_policy_packet": {
            **common,
            "schema_id": "policy",
            "r01_r04_use_policy": {
                "diagnostic_use_allowed": True,
                "reuse_as_counted_superiority_screen_after_revision_allowed": False,
            },
        },
        "prior_blind_input_receipt": {
            **common,
            "schema_id": "blind",
            "new_blind_input_universe_required": True,
            "r01_r04_closed_for_candidate_v2_counted_superiority_rerun": True,
        },
        "prior_next_lawful_move": {
            **common,
            "schema_id": "next",
        },
    }
    for role, payload in payloads.items():
        _write_json(root / tranche.INPUTS[role], payload)
    return reports


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "revision-packet-head")


def test_candidate_revision_packet_authorizes_revision_with_blind_input_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["revision_receipt"])
    contract = _load(reports / tranche.OUTPUTS["blind_input_universe_contract"])
    overfit = _load(reports / tranche.OUTPUTS["overfit_risk_guard_receipt"])
    v2 = _load(reports / tranche.OUTPUTS["candidate_v2_source_requirements"])
    candidate_set = _load(reports / tranche.OUTPUTS["blind_input_candidate_set"])

    assert result["verdict"] == tranche.FINAL_VERDICT
    assert receipt["candidate_revision_authorized"] is True
    assert "r6_open" in receipt["forbidden_claims"]
    assert receipt["candidate_v2_screen_execution_authorized"] is False
    assert contract["row_count"] == 6
    assert all(row["static_baseline_labels_blinded_until_counted_screen"] for row in contract["candidate_rows"])
    assert overfit["new_blind_universe_required"] is True
    assert v2["candidate_v2_generation_authorized_by_this_packet"] is False
    assert candidate_set["selection_status"] == "CANDIDATE_SET_PREP_ONLY_NOT_COUNTED_SCREEN"


def test_candidate_revision_packet_fails_closed_if_prior_blind_requirement_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    blind = _load(reports / "b04_r6_blind_input_requirement_receipt.json")
    blind["new_blind_input_universe_required"] = False
    _write_json(reports / "b04_r6_blind_input_requirement_receipt.json", blind)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="blind input universe requirement"):
        tranche.run(reports_root=reports)


def test_candidate_revision_packet_fails_closed_if_prior_next_move_wrong(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    prior_next = _load(reports / "b04_r6_candidate_revision_next_lawful_move_receipt.json")
    prior_next["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write_json(reports / "b04_r6_candidate_revision_next_lawful_move_receipt.json", prior_next)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="next-lawful-move"):
        tranche.run(reports_root=reports)


def test_candidate_revision_packet_fails_closed_if_prior_revision_flag_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_candidate_revision_or_closeout_receipt.json")
    receipt["candidate_revision_allowed_next"] = False
    _write_json(reports / "b04_r6_candidate_revision_or_closeout_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="authorize candidate revision"):
        tranche.run(reports_root=reports)


def test_candidate_revision_packet_fails_closed_if_per_row_has_candidate_win(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    per_row = _load(reports / "b04_r6_per_row_failure_matrix.json")
    per_row["rows"][0]["candidate_beats_static"] = True
    _write_json(reports / "b04_r6_per_row_failure_matrix.json", per_row)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="zero candidate wins"):
        tranche.run(reports_root=reports)


def test_candidate_revision_packet_fails_closed_if_r6_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_candidate_revision_or_closeout_receipt.json")
    receipt["r6_open"] = True
    _write_json(reports / "b04_r6_candidate_revision_or_closeout_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="r6_open"):
        tranche.run(reports_root=reports)
