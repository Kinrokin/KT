from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_expanded_canary_authorization_packet as expanded
from tools.operator.titanium_common import file_sha256


HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN = "a72502df57ed4d816ada7a1bebd8c34c8970288c"


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = expanded.AUTHORITY_BRANCH,
    head: str = HEAD,
    origin_main: str = MAIN,
) -> None:
    monkeypatch.setattr(expanded, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(expanded.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(expanded.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)


def _seed_inputs(reports: Path) -> None:
    base = {
        "runtime_cutover_authorized": False,
        "r6_open": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
    }
    _write(
        reports / expanded.INPUTS["canary_evidence_review_validation_receipt"],
        {
            **base,
            "artifact_id": "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATION_RECEIPT",
            "selected_outcome": expanded.PREDECESSOR_OUTCOME,
            "next_lawful_move": expanded.PREDECESSOR_NEXT_MOVE,
            "recommended_next_path_validated": "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
        },
    )
    _write(
        reports / expanded.INPUTS["canary_evidence_scorecard"],
        {
            **base,
            "artifact_id": "B04_R6_CANARY_EVIDENCE_SCORECARD",
            "overall_grade": "B_GOOD_BUT_MORE_CANARY_RECOMMENDED",
            "expanded_canary_ready": True,
            "runtime_cutover_review_ready": False,
            "package_promotion_ready": False,
        },
    )
    _write(
        reports / expanded.INPUTS["post_canary_decision_matrix"],
        {
            **base,
            "artifact_id": "B04_R6_POST_CANARY_DECISION_MATRIX",
            "recommended_next_path": "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
            "expanded_canary_ready": True,
            "runtime_cutover_review_ready": False,
            "package_promotion_ready": False,
        },
    )
    _write(
        reports / expanded.INPUTS["expanded_canary_readiness_matrix"],
        {
            **base,
            "artifact_id": "B04_R6_EXPANDED_CANARY_READINESS_MATRIX",
            "decision_matrix": {
                "expanded_canary_ready": True,
                "runtime_cutover_review_ready": False,
                "package_promotion_ready": False,
            },
        },
    )
    _write(
        reports / expanded.INPUTS["current_next_lawful_move"],
        {
            **base,
            "artifact_id": "KT_NEXT_LAWFUL_MOVE_RECEIPT",
            "selected_outcome": (
                "KT_E2E_CLOSURE_ADAPTIVE_RATIFICATION_AND_7B_AMPLIFICATION_BENCHMARK_ORDER_VALIDATED__"
                "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
            ),
            "next_lawful_move": expanded.PREDECESSOR_NEXT_MOVE,
        },
    )
    for role, filename in expanded.INPUTS.items():
        path = reports / filename
        if not path.exists():
            _write(path, {**base, "artifact_id": role.upper(), "status": "BOUND"})


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_inputs(reports)
    _patch_env(monkeypatch, tmp_path)
    expanded.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run(tmp_path, monkeypatch)


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / expanded.OUTPUTS[role])


@pytest.mark.parametrize("filename", sorted(expanded.OUTPUTS.values()))
def test_required_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["artifact_id"]


def test_packet_selects_expected_outcome(outputs: Path) -> None:
    contract = _payload(outputs, "packet_contract")
    assert contract["selected_outcome"] == expanded.SELECTED_OUTCOME
    assert contract["next_lawful_move"] == expanded.NEXT_LAWFUL_MOVE
    assert contract["validation_success_outcome"] == expanded.VALIDATION_SUCCESS_OUTCOME


def test_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _payload(outputs, "packet_contract")["current_main_head"] == MAIN


def test_next_lawful_move_routes_to_validation(outputs: Path) -> None:
    nxt = _payload(outputs, "next_lawful_move")
    assert nxt["selected_outcome"] == expanded.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == expanded.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize("role, filename", sorted(expanded.INPUTS.items()))
def test_packet_binds_all_inputs(outputs: Path, role: str, filename: str) -> None:
    contract = _payload(outputs, "packet_contract")
    assert contract["binding_hashes"][f"{role}_hash"] == file_sha256(outputs / filename)


@pytest.mark.parametrize(
    "flag",
    [
        "expanded_canary_runtime_authorized",
        "expanded_canary_runtime_executed",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "r6_open",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "metric_contract_mutated",
        "static_comparator_weakened",
    ],
)
def test_packet_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _payload(outputs, "packet_contract")[flag] is False


def test_scope_is_expanded_but_bounded(outputs: Path) -> None:
    details = _payload(outputs, "scope_manifest")["details"]
    assert details["scope_status"] == "EXPANDED_CANARY_SCOPE_DEFINED_NOT_EXECUTING"
    assert details["global_r6_scope_allowed"] is False
    assert details["runtime_cutover_allowed"] is False
    assert details["max_case_count_per_window"] == 36


def test_allowed_and_excluded_case_classes_are_defined(outputs: Path) -> None:
    allowed = _payload(outputs, "allowed_case_class_contract")["details"]["allowed_case_classes"]
    excluded = _payload(outputs, "excluded_case_class_contract")["details"]["excluded_case_classes"]
    assert "PRIOR_CANARY_COVERED_CASE_CLASS_EXTENSION" in allowed
    assert "GLOBAL_R6_TRAFFIC" in excluded
    assert "COMMERCIAL_ACTIVATION_SURFACE" in excluded


@pytest.mark.parametrize("role", expanded.CONTRACT_ROLES)
def test_operational_contracts_are_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["contract_status"] == "BOUND_NON_EXECUTING"
    assert payload["expanded_canary_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False


@pytest.mark.parametrize(
    "role, detail_key",
    [
        ("static_fallback_contract", "static_fallback_required"),
        ("abstention_fallback_contract", "abstention_fallback_required"),
        ("null_route_preservation_contract", "null_route_preservation_required"),
        ("operator_override_contract", "operator_override_required"),
        ("kill_switch_contract", "kill_switch_required"),
        ("rollback_contract", "rollback_required"),
        ("external_verifier_requirements", "external_verifier_required"),
    ],
)
def test_required_safety_controls_are_defined(outputs: Path, role: str, detail_key: str) -> None:
    assert _payload(outputs, role)["details"][detail_key] is True


@pytest.mark.parametrize("role", expanded.PREP_ONLY_ROLES)
def test_downstream_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_authorize_expanded_canary_execution"] is True
    assert payload["expanded_canary_runtime_authorized"] is False


def test_report_states_no_cutover_or_execution(outputs: Path) -> None:
    text = (outputs / expanded.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute expanded canary" in text
    assert "authorize runtime cutover" in text
    assert "commercial activation claims" in text


def test_rejects_decision_matrix_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_inputs(reports)
    decision = _load(reports / expanded.INPUTS["post_canary_decision_matrix"])
    decision["recommended_next_path"] = "RUNTIME_CUTOVER_REVIEW_PACKET_NEXT"
    _write(reports / expanded.INPUTS["post_canary_decision_matrix"], decision)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="DECISION_MATRIX_DRIFT"):
        expanded.run(reports_root=reports)


def test_rejects_readiness_matrix_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_inputs(reports)
    readiness = _load(reports / expanded.INPUTS["expanded_canary_readiness_matrix"])
    readiness["decision_matrix"]["expanded_canary_ready"] = False
    _write(reports / expanded.INPUTS["expanded_canary_readiness_matrix"], readiness)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="READINESS_MATRIX_DRIFT"):
        expanded.run(reports_root=reports)


def test_rejects_current_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_inputs(reports)
    nxt = _load(reports / expanded.INPUTS["current_next_lawful_move"])
    nxt["next_lawful_move"] = "RUN_B04_R6_EXPANDED_CANARY"
    _write(reports / expanded.INPUTS["current_next_lawful_move"], nxt)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        expanded.run(reports_root=reports)


def test_rejects_runtime_cutover_authority_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_inputs(reports)
    scorecard = _load(reports / expanded.INPUTS["canary_evidence_scorecard"])
    scorecard["runtime_cutover_authorized"] = True
    _write(reports / expanded.INPUTS["canary_evidence_scorecard"], scorecard)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="RUNTIME_CUTOVER_AUTHORIZED"):
        expanded.run(reports_root=reports)


@pytest.mark.parametrize("field", ["expanded_canary_runtime_authorized", "expanded_canary_runtime_executed"])
def test_rejects_expanded_canary_runtime_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_inputs(reports)
    scorecard = _load(reports / expanded.INPUTS["canary_evidence_scorecard"])
    scorecard[field] = True
    _write(reports / expanded.INPUTS["canary_evidence_scorecard"], scorecard)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="RUNTIME_AUTHORIZED"):
        expanded.run(reports_root=reports)
