from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.governance.evaluation_admission_gate import ensure_evaluation_admission_receipt  # noqa: E402
from tools.governance.law_change_admission_gate import ensure_law_change_admission_receipt  # noqa: E402
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object  # noqa: E402


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def _build_simulated_signoff(*, key_id: str, payload_hash: str, created_at: str) -> dict:
    signoff = {
        "schema_id": "kt.human_signoff.v2",
        "schema_version_hash": schema_version_hash("fl3/kt.human_signoff.v2.json"),
        "signoff_id": "",
        "attestation_mode": "SIMULATED",
        "key_id": key_id,
        "payload_hash": payload_hash,
        "simulated_signature": sha256_hex_of_obj({"key_id": key_id, "payload_hash": payload_hash}, drop_keys=set()),
        "created_at": created_at,
    }
    signoff["signoff_id"] = sha256_hex_of_obj(signoff, drop_keys={"created_at", "signoff_id"})
    return signoff


def _mk_suite_registry(*, suite_id: str, suite_root_hash: str, suite_definition_ref: str) -> dict:
    created_at = "1970-01-01T00:00:00Z"
    authorization_payload_hash = sha256_hex_of_obj({"suite_id": suite_id, "suite_root_hash": suite_root_hash}, drop_keys=set())
    obj = {
        "schema_id": "kt.suite_registry.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.suite_registry.v1.json"),
        "suite_registry_id": "",
        "attestation_mode": "SIMULATED",
        "suites": [
            {
                "suite_id": suite_id,
                "suite_root_hash": suite_root_hash,
                "suite_definition_ref": suite_definition_ref,
                "authorization_payload_hash": authorization_payload_hash,
                "signoffs": [
                    _build_simulated_signoff(key_id="SIGNER_A", payload_hash=authorization_payload_hash, created_at=created_at),
                    _build_simulated_signoff(key_id="SIGNER_B", payload_hash=authorization_payload_hash, created_at=created_at),
                ],
                "notes": None,
            }
        ],
        "created_at": created_at,
        "notes": None,
    }
    obj["suite_registry_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "suite_registry_id"})
    validate_schema_bound_object(obj)
    return obj


def _mk_break_hypothesis(*, base_model_id: str, suite_id: str) -> dict:
    obj = {
        "schema_id": "kt.break_hypothesis.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.break_hypothesis.v1.json"),
        "break_hypothesis_id": "",
        "base_model_id": base_model_id,
        "suite_id": suite_id,
        "hypothesis": "format-perturbations will break JSON compliance",
        "predicted_failure_modes": [{"mode_id": "FMT1", "description": "outputs non-JSON under perturbation"}],
        "required_probe_families": ["perturbation", "schema_trap"],
        "regression_budgets": {"safety_regression_epsilon": 0.0, "new_hard_failures_allowed": 0},
        "created_at": "1970-01-01T00:00:00Z",
        "notes": None,
    }
    obj["break_hypothesis_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "break_hypothesis_id"})
    validate_schema_bound_object(obj)
    return obj


def _mk_counterpressure_plan(
    *,
    base_model_id: str,
    optimization_suite_id: str,
    optimization_suite_root_hash: str,
    decode_policy_id: str,
    decode_cfg_hash: str,
    break_hypothesis_id: str,
) -> dict:
    obj = {
        "schema_id": "kt.counterpressure_plan.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.counterpressure_plan.v1.json"),
        "counterpressure_plan_id": "",
        "base_model_id": base_model_id,
        "optimization_suite_id": optimization_suite_id,
        "optimization_suite_root_hash": optimization_suite_root_hash,
        "adversarial_suite_id": f"{optimization_suite_id}_ADV",
        "adversarial_suite_root_hash": "b" * 64,
        "decode_policy_id": decode_policy_id,
        "decode_cfg_hash": decode_cfg_hash,
        "break_hypothesis_id": break_hypothesis_id,
        "required_probe_families": ["perturbation", "schema_trap"],
        "created_at": "1970-01-01T00:00:00Z",
        "notes": None,
    }
    obj["counterpressure_plan_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "counterpressure_plan_id"})
    validate_schema_bound_object(obj)
    return obj


def _mk_tournament_plan(*, base_model_id: str, suite_id: str, suite_root_hash: str, decode_cfg_hash: str) -> dict:
    entrants = [{"adapter_root_hash": "1" * 64, "adapter_id": "lobe.alpha.v1", "adapter_version": "1"}]
    seed_payload = base_model_id + "|" + suite_id + "|" + entrants[0]["adapter_root_hash"]
    import hashlib

    obj = {
        "schema_id": "kt.tournament_plan.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.tournament_plan.v1.json"),
        "tournament_plan_id": "",
        "base_model_id": base_model_id,
        "suite_id": suite_id,
        "suite_root_hash": suite_root_hash,
        "decode_policy_id": "greedy_v1",
        "decode_cfg_hash": decode_cfg_hash,
        "tournament_mode": "round_robin_v1",
        "epsilon": 0.01,
        "entrants": entrants,
        "seed": hashlib.sha256(seed_payload.encode("utf-8")).hexdigest(),
        "created_at": "1970-01-01T00:00:00Z",
        "notes": None,
    }
    obj["tournament_plan_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "tournament_plan_id"})
    validate_schema_bound_object(obj)
    return obj


def test_epic16_evaluation_admission_gate_pass_and_rerun_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KT_CANONICAL_LANE", raising=False)
    monkeypatch.delenv("CI", raising=False)

    base_model_id = "mistral-7b"
    suite_id = "SUITE_X"
    suite_definition_ref = "KT_PROD_CLEANROOM/AUDITS/EPIC_16_DOCTRINE.md"
    suite_root_hash = sha256_file_canonical((_REPO_ROOT / suite_definition_ref).resolve())
    decode_cfg_hash = "d" * 64

    registry_path = tmp_path / "suite_registry.json"
    plan_path = tmp_path / "tournament_plan.json"
    cp_path = tmp_path / "counterpressure_plan.json"
    bh_path = tmp_path / "break_hypothesis.json"
    out_path = tmp_path / "evaluation_admission_receipt.json"

    _write_json(registry_path, _mk_suite_registry(suite_id=suite_id, suite_root_hash=suite_root_hash, suite_definition_ref=suite_definition_ref))

    bh = _mk_break_hypothesis(base_model_id=base_model_id, suite_id=suite_id)
    _write_json(bh_path, bh)
    _write_json(
        cp_path,
        _mk_counterpressure_plan(
            base_model_id=base_model_id,
            optimization_suite_id=suite_id,
            optimization_suite_root_hash=suite_root_hash,
            decode_policy_id="greedy_v1",
            decode_cfg_hash=decode_cfg_hash,
            break_hypothesis_id=bh["break_hypothesis_id"],
        ),
    )
    _write_json(plan_path, _mk_tournament_plan(base_model_id=base_model_id, suite_id=suite_id, suite_root_hash=suite_root_hash, decode_cfg_hash=decode_cfg_hash))

    r1 = ensure_evaluation_admission_receipt(
        repo_root=_REPO_ROOT,
        plan_path=plan_path,
        lane_id="TEST_LANE",
        suite_registry_path=registry_path,
        counterpressure_plan_path=cp_path,
        break_hypothesis_path=bh_path,
        out_path=out_path,
    )
    b1 = out_path.read_bytes()

    r2 = ensure_evaluation_admission_receipt(
        repo_root=_REPO_ROOT,
        plan_path=plan_path,
        lane_id="TEST_LANE",
        suite_registry_path=registry_path,
        counterpressure_plan_path=cp_path,
        break_hypothesis_path=bh_path,
        out_path=out_path,
    )
    b2 = out_path.read_bytes()

    assert b1 == b2
    assert r1["admission_receipt_id"] == r2["admission_receipt_id"]
    assert r1["decision"] == "PASS"

    obj = json.loads(out_path.read_text(encoding="utf-8"))
    validate_schema_bound_object(obj)
    assert obj["decision"] == "PASS"


def test_epic16_evaluation_admission_gate_fail_closed_on_unauthorized_suite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KT_CANONICAL_LANE", raising=False)
    monkeypatch.delenv("CI", raising=False)

    base_model_id = "mistral-7b"
    suite_id = "SUITE_X"
    suite_definition_ref = "KT_PROD_CLEANROOM/AUDITS/EPIC_16_DOCTRINE.md"
    suite_root_hash = sha256_file_canonical((_REPO_ROOT / suite_definition_ref).resolve())
    decode_cfg_hash = "d" * 64

    # Registry does not include SUITE_X, so admission must fail closed.
    registry_path = tmp_path / "suite_registry.json"
    registry = _mk_suite_registry(suite_id="OTHER_SUITE", suite_root_hash="a" * 64, suite_definition_ref=suite_definition_ref)
    _write_json(registry_path, registry)

    plan_path = tmp_path / "tournament_plan.json"
    _write_json(plan_path, _mk_tournament_plan(base_model_id=base_model_id, suite_id=suite_id, suite_root_hash=suite_root_hash, decode_cfg_hash=decode_cfg_hash))

    bh_path = tmp_path / "break_hypothesis.json"
    bh = _mk_break_hypothesis(base_model_id=base_model_id, suite_id=suite_id)
    _write_json(bh_path, bh)

    cp_path = tmp_path / "counterpressure_plan.json"
    _write_json(
        cp_path,
        _mk_counterpressure_plan(
            base_model_id=base_model_id,
            optimization_suite_id=suite_id,
            optimization_suite_root_hash=suite_root_hash,
            decode_policy_id="greedy_v1",
            decode_cfg_hash=decode_cfg_hash,
            break_hypothesis_id=bh["break_hypothesis_id"],
        ),
    )

    out_path = tmp_path / "evaluation_admission_receipt.json"

    with pytest.raises(FL3ValidationError):
        _ = ensure_evaluation_admission_receipt(
            repo_root=_REPO_ROOT,
            plan_path=plan_path,
            lane_id="TEST_LANE",
            suite_registry_path=registry_path,
            counterpressure_plan_path=cp_path,
            break_hypothesis_path=bh_path,
            out_path=out_path,
        )

    assert out_path.exists()
    obj = json.loads(out_path.read_text(encoding="utf-8"))
    validate_schema_bound_object(obj)
    assert obj["decision"] == "FAIL_CLOSED"
    assert "SUITE_UNAUTHORIZED" in obj.get("reason_codes", [])


def _mk_law_bundle_change_receipt(*, new_bundle_hash: str, created_at: str) -> dict:
    obj = {
        "schema_id": "kt.law_bundle_change_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.law_bundle_change_receipt.v1.json"),
        "receipt_id": "",
        "bundle_id": "LAW_BUNDLE_FL3",
        "old_ref": "HEAD",
        "old_bundle_hash": "0" * 64,
        "new_bundle_hash": new_bundle_hash,
        "diff": {"added": [], "removed": [], "modified": []},
        "counts": {"added": 0, "removed": 0, "modified": 0},
        "created_at": created_at,
    }
    obj["receipt_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "receipt_id"})
    validate_schema_bound_object(obj)
    return obj


def test_epic16_law_change_admission_gate_pass(tmp_path: Path) -> None:
    requested = (Path(_REPO_ROOT) / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").read_text(encoding="utf-8").strip()
    change_path = tmp_path / "law_bundle_change_receipt.json"
    _write_json(change_path, _mk_law_bundle_change_receipt(new_bundle_hash=requested, created_at="2026-02-15T00:00:00Z"))

    out_path = tmp_path / "law_change_admission_receipt.json"
    r = ensure_law_change_admission_receipt(
        repo_root=_REPO_ROOT,
        requested_bundle_hash=requested,
        law_bundle_change_receipt_path=change_path,
        cooldown_seconds=0,
        out_path=out_path,
    )
    assert r["decision"] == "PASS"
    obj = json.loads(out_path.read_text(encoding="utf-8"))
    validate_schema_bound_object(obj)
    assert obj["decision"] == "PASS"


def test_epic16_law_change_admission_gate_fail_closed_on_cooldown(tmp_path: Path) -> None:
    requested = (Path(_REPO_ROOT) / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").read_text(encoding="utf-8").strip()
    # Use a very old change receipt; latest amendment is newer, so cooldown must trip.
    change_path = tmp_path / "law_bundle_change_receipt.json"
    _write_json(change_path, _mk_law_bundle_change_receipt(new_bundle_hash=requested, created_at="1970-01-01T00:00:00Z"))

    out_path = tmp_path / "law_change_admission_receipt.json"
    with pytest.raises(FL3ValidationError):
        _ = ensure_law_change_admission_receipt(
            repo_root=_REPO_ROOT,
            requested_bundle_hash=requested,
            law_bundle_change_receipt_path=change_path,
            cooldown_seconds=1,
            out_path=out_path,
        )

    obj = json.loads(out_path.read_text(encoding="utf-8"))
    validate_schema_bound_object(obj)
    assert obj["decision"] == "FAIL_CLOSED"
    assert "LAW_CHANGE_ADMISSION_COOLDOWN_ACTIVE" in obj.get("reason_codes", [])
