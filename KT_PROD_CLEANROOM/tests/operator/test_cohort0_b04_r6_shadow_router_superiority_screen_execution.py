from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_shadow_router_superiority_screen_execution as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _base() -> dict:
    return {
        "status": "PASS",
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _candidate_source() -> str:
    return '''from __future__ import annotations

CANDIDATE_ID = "fixture_candidate"

def route_case(case, *, seed=42):
    family = case.get("family", "default")
    routes = {
        "math": ["lobe.censor.v1", "lobe.quant.v1"],
        "poetry": ["lobe.muse.v1"],
        "governance": ["lobe.censor.v1", "lobe.auditor.v1"],
        "default": ["lobe.strategist.v1"],
    }
    abstain = family == "default"
    return {
        "candidate_id": CANDIDATE_ID,
        "case_id": case["case_id"],
        "family": family,
        "seed": seed,
        "shadow_only": True,
        "activation_allowed": False,
        "route_adapter_ids": routes[family],
        "abstention_decision": abstain,
        "overrouting_detected": False,
        "consequence_visibility": {"static_hold_preserved": abstain, "package_promotion_dependency": False},
    }

def route_cases(cases, *, seed=42):
    return [route_case(dict(case), seed=seed) for case in cases]
'''


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    run_root = root / "KT_PROD_CLEANROOM" / "runs" / "b04_r6" / "candidate_generation"
    source = run_root / "generated_learned_router_candidate.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(_candidate_source(), encoding="utf-8")
    _write_json(run_root / "generated_learned_router_candidate_manifest.json", {"schema_id": "manifest", **_base()})
    _write_json(
        reports / "b04_r6_shadow_router_input_manifest_bound.json",
        {
            **_base(),
            "input_manifest_ready": True,
            "input_cases": [
                {"case_id": "R01", "family": "math", "baseline_adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"], "fallback_engaged": False},
                {"case_id": "R02", "family": "poetry", "baseline_adapter_ids": ["lobe.muse.v1"], "fallback_engaged": False},
                {"case_id": "R03", "family": "governance", "baseline_adapter_ids": ["lobe.auditor.v1", "lobe.censor.v1"], "fallback_engaged": False},
                {"case_id": "R04", "family": "default", "baseline_adapter_ids": ["lobe.strategist.v1"], "fallback_engaged": True},
            ],
        },
    )
    simple = [
        "b04_r6_admissible_learned_router_candidate_source_receipt.json",
        "b04_r6_candidate_provenance_matrix.json",
        "b04_r6_candidate_source_holdout_separation_receipt.json",
        "b04_r6_candidate_no_contamination_receipt.json",
        "b04_r6_candidate_deterministic_replay_receipt.json",
        "b04_r6_candidate_trace_compatibility_receipt.json",
        "b04_r6_comparator_matrix_contract.json",
        "b04_r6_metric_thresholds_contract.json",
        "b04_r6_hard_disqualifier_contract.json",
        "b04_r6_static_baseline_immutability_guard_receipt.json",
        "b04_r6_overrouting_detector_prep_receipt.json",
        "b04_r6_abstention_collapse_detector_prep_receipt.json",
        "b04_r6_mirror_masked_invariance_checker_prep_receipt.json",
    ]
    for name in simple:
        payload = {**_base(), "schema_id": name}
        if name == "b04_r6_admissible_learned_router_candidate_source_receipt.json":
            payload.update({"verdict": "R6_CANDIDATE_ADMISSIBLE__SHADOW_SCREEN_AUTHORIZATION_NEXT", "screen_execution_authorized": True})
        _write_json(reports / name, payload)
    _write_json(
        reports / "b04_r6_shadow_router_execution_mode_contract.json",
        {**_base(), "activation_allowed": False, "package_promotion_allowed": False, "lobe_promotion_allowed": False},
    )
    packet = {
        "schema_id": "packet",
        "status": "FROZEN_PACKET",
        "current_git_head": "subject123",
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "packet_authorizes_screen_execution": True,
        "candidate": {
            "candidate_source_ref": "KT_PROD_CLEANROOM/runs/b04_r6/candidate_generation/generated_learned_router_candidate.py",
            "deterministic_seed": 42,
        },
        "prerequisite_bindings": [],
    }
    for name in simple + ["b04_r6_shadow_router_input_manifest_bound.json", "b04_r6_shadow_router_execution_mode_contract.json"]:
        p = reports / name
        packet["prerequisite_bindings"].append({"role": name, "path": p.relative_to(root).as_posix(), "sha256": _sha(p)})
    _write_json(reports / "b04_r6_shadow_router_superiority_screen_execution_packet.json", packet)
    _write_json(
        reports / "b04_r6_shadow_router_superiority_screen_execution_packet_receipt.json",
        {
            **_base(),
            "execution_packet": {
                "path": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_execution_packet.json",
                "sha256": _sha(reports / "b04_r6_shadow_router_superiority_screen_execution_packet.json"),
            },
        },
    )
    return reports


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "exec456")
    monkeypatch.setattr(
        tranche,
        "validate_trust_zones",
        lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []},
    )


def test_shadow_screen_executes_and_fails_superiority_when_static_is_not_beaten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["receipt"])
    scorecard = _load(reports / tranche.OUTPUTS["scorecard"])
    disqualifier_ledger = _load(reports / tranche.OUTPUTS["disqualifier_ledger"])
    blocker_ledger = _load(reports / tranche.OUTPUTS["blocker_ledger"])

    assert result["verdict"] == tranche.VERDICT_FAILED
    assert receipt["screen_execution_performed"] is True
    assert receipt["r6_open"] is False
    assert scorecard["candidate_win_count"] == 0
    assert scorecard["metrics"]["control_preservation"]["result"] == "PASS"
    assert disqualifier_ledger["triggered_count"] == 0
    assert blocker_ledger["live_blocker_count"] == 1


def test_shadow_screen_fails_closed_if_execution_packet_hash_mismatches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_shadow_router_superiority_screen_execution_packet_receipt.json")
    receipt["execution_packet"]["sha256"] = "0" * 64
    _write_json(reports / "b04_r6_shadow_router_superiority_screen_execution_packet_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="execution packet receipt hash"):
        tranche.run(reports_root=reports)


def test_shadow_screen_fails_closed_if_activation_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    mode = _load(reports / "b04_r6_shadow_router_execution_mode_contract.json")
    mode["activation_allowed"] = True
    _write_json(reports / "b04_r6_shadow_router_execution_mode_contract.json", mode)
    packet = _load(reports / "b04_r6_shadow_router_superiority_screen_execution_packet.json")
    for row in packet["prerequisite_bindings"]:
        if row["path"].endswith("b04_r6_shadow_router_execution_mode_contract.json"):
            row["sha256"] = _sha(reports / "b04_r6_shadow_router_execution_mode_contract.json")
    _write_json(reports / "b04_r6_shadow_router_superiority_screen_execution_packet.json", packet)
    receipt = _load(reports / "b04_r6_shadow_router_superiority_screen_execution_packet_receipt.json")
    receipt["execution_packet"]["sha256"] = _sha(reports / "b04_r6_shadow_router_superiority_screen_execution_packet.json")
    _write_json(reports / "b04_r6_shadow_router_superiority_screen_execution_packet_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="activation"):
        tranche.run(reports_root=reports)
