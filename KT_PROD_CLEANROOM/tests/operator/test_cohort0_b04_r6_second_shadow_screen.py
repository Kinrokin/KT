from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_second_shadow_screen as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": "prior-head",
        "subject_main_head": "subject-head",
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


def _candidate_source() -> str:
    return '''from __future__ import annotations

ROUTES = {
    "default": (True, ["lobe.strategist.v1"], 0.0),
    "governance": (False, ["lobe.auditor.v1", "lobe.censor.v1"], 0.64),
    "masked_ambiguous": (True, ["lobe.strategist.v1"], 0.0),
    "math": (False, ["lobe.censor.v1", "lobe.quant.v1"], 0.66),
    "mixed_math_governance": (False, ["lobe.auditor.v1", "lobe.quant.v1", "lobe.censor.v1"], 0.58),
    "poetry": (False, ["lobe.muse.v1"], 0.63),
}

def route_case(case, *, seed=42):
    family = str(case.get("family", "default")).strip()
    abstain, adapters, confidence = ROUTES.get(family, ROUTES["default"])
    return {
        "candidate_id": "b04_r6_diagnostic_gap_shadow_router_v2",
        "candidate_version": "2.0.0",
        "case_id": str(case.get("case_id", "")),
        "family": family,
        "seed": seed,
        "shadow_only": True,
        "activation_allowed": False,
        "route_adapter_ids": list(adapters),
        "abstention_decision": abstain,
        "overrouting_detected": False,
        "confidence": confidence,
        "route_reason": "fixture",
        "trace_schema_version": "b04.r6.route_trace.v2",
        "visible_features_used": {
            "family": family,
            "pressure_type": str(case.get("pressure_type", "")),
            "source_kind": str(case.get("source_kind", "")),
        },
        "diagnostic_training_targets_used": False,
        "blind_label_dependency": False,
        "source_holdout_dependency": False,
        "consequence_visibility": {
            "selected_family": family,
            "static_hold_preserved": abstain,
            "package_promotion_dependency": False,
            "truth_engine_mutation_dependency": False,
            "trust_zone_mutation_dependency": False,
        },
    }

def route_cases(cases, *, seed=42):
    return [route_case(dict(case), seed=seed) for case in cases]
'''


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
            "pressure_type": pressure_type,
            "source_kind": source_kind,
            "source_sha256": f"{case_id.lower()}-hash",
            "holdout_role": "candidate_v2_counted_screen_candidate",
            "mirror_masked_required": True,
            "old_r01_r04_derived": False,
            "static_baseline_labels_blinded_until_counted_screen": True,
            "candidate_v2_training_label_visible": False,
            "candidate_visible_fields": ["case_id", "family", "pressure_type", "source_kind"],
        }
        for case_id, family, pressure_type, source_kind in rows
    ]


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    source = root / "KT_PROD_CLEANROOM" / "runs" / "b04_r6" / "candidate_v2_generation" / "generated_learned_router_candidate_v2.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(_candidate_source(), encoding="utf-8")
    candidate = {
        "candidate_id": "b04_r6_diagnostic_gap_shadow_router_v2",
        "candidate_version": "2.0.0",
        "candidate_source_ref": "KT_PROD_CLEANROOM/runs/b04_r6/candidate_v2_generation/generated_learned_router_candidate_v2.py",
        "candidate_source_sha256": tranche.file_sha256(source),
        "seed": 42,
        "shadow_only": True,
        "activation_allowed": False,
    }
    rows = _blind_rows()
    common = {**_base(), "next_lawful_move": "AUTHOR_B04_R6_SECOND_SHADOW_SCREEN_EXECUTION_PACKET"}
    payloads = {
        "candidate_source_packet": {**common, "schema_id": "source_packet", "candidate": candidate},
        "candidate_source_receipt": {**common, "schema_id": "source_receipt", "candidate": candidate},
        "candidate_manifest": {**common, "schema_id": "manifest", "candidate": candidate},
        "candidate_provenance": {**common, "schema_id": "provenance", "candidate": candidate},
        "candidate_derivation": {**common, "schema_id": "derivation", "candidate": candidate},
        "candidate_eval": {**common, "schema_id": "eval", "candidate": candidate, "score_against_static_baseline_performed": False},
        "candidate_no_contamination": {**common, "schema_id": "no_contamination", "candidate": candidate},
        "candidate_overfit_guard": {**common, "schema_id": "overfit", "candidate": candidate},
        "candidate_blind_separation": {**common, "schema_id": "separation", "candidate": candidate},
        "candidate_deterministic_replay": {**common, "schema_id": "replay", "candidate": candidate},
        "candidate_trace_compatibility": {**common, "schema_id": "trace", "candidate": candidate},
        "candidate_admissibility": {
            **common,
            "schema_id": "admissibility",
            "verdict": tranche.PRIOR_VERDICT,
            "candidate": candidate,
            "candidate_v2_admissible": True,
            "second_shadow_screen_authorization_next": True,
            "second_shadow_screen_executed": False,
        },
        "second_readiness": {**common, "schema_id": "readiness", "second_shadow_screen_execution_packet_authorized_next": True},
        "second_authorization": {**common, "schema_id": "authorization", "second_shadow_screen_execution_packet_authorized_next": True},
        "blind_contract": {
            **common,
            "schema_id": "blind_contract",
            "row_count": 6,
            "candidate_rows": rows,
            "holdout_policy": {
                "candidate_v2_may_not_train_on_counted_labels": True,
                "r01_r04_not_counted_for_candidate_v2_superiority": True,
                "static_comparator_labels_blinded_until_counted_screen": True,
            },
        },
        "blind_candidate_set": {**common, "schema_id": "candidate_set", "rows": rows},
        "overfit_guard": {**common, "schema_id": "old_overfit", "new_blind_universe_required": True},
        "comparator_contract": {**common, "schema_id": "comparator"},
        "metric_contract": {**common, "schema_id": "metric"},
        "disqualifier_contract": {**common, "schema_id": "disqualifier"},
        "static_baseline_guard": {**_base("PREP_ONLY"), "schema_id": "static_guard", "static_baseline_mutated": False},
    }
    for role, payload in payloads.items():
        _write_json(root / tranche.INPUTS[role], payload)
    return reports


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "second-screen-head")
    monkeypatch.setattr(
        tranche,
        "validate_trust_zones",
        lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []},
    )


def test_second_shadow_screen_invalidates_overrouting_without_opening_r6(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["result_receipt"])
    scorecard = _load(reports / tranche.OUTPUTS["scorecard"])
    disqualifier_ledger = _load(reports / tranche.OUTPUTS["disqualifier_ledger"])
    next_receipt = _load(reports / tranche.OUTPUTS["next_lawful_move"])

    assert result["verdict"] == tranche.VERDICT_INVALIDATED
    assert receipt["r6_open"] is False
    assert receipt["learned_router_activated"] is False
    assert scorecard["candidate_win_count"] == 0
    assert scorecard["metrics"]["overrouting_penalty"]["result"] == "FAIL"
    assert disqualifier_ledger["triggered_count"] >= 1
    assert next_receipt["next_lawful_move"] == tranche.NEXT_IF_INVALIDATED


def test_second_shadow_screen_fails_closed_if_candidate_not_admissible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    admissibility = _load(reports / "b04_r6_candidate_v2_admissibility_receipt.json")
    admissibility["candidate_v2_admissible"] = False
    _write_json(reports / "b04_r6_candidate_v2_admissibility_receipt.json", admissibility)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="candidate v2 must be admissible"):
        tranche.run(reports_root=reports)


def test_second_shadow_screen_fails_closed_if_blind_label_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    blind = _load(reports / "b04_r6_new_blind_input_universe_contract.json")
    blind["candidate_rows"][0]["candidate_v2_training_label_visible"] = True
    _write_json(reports / "b04_r6_new_blind_input_universe_contract.json", blind)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="blind labels"):
        tranche.run(reports_root=reports)
