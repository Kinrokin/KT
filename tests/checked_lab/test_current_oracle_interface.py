"""Native synthetic regression court for frozen interface portfolio ingestion.

No model/provider calls. Fixtures traverse the existing admitted operation,
checker, effects and detached verifier; only the transport backend is synthetic.
This file is a proposed test addition, not executed evidence or source authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_checked_generation import (
    SyntheticBackend, isolated_test_transport, tmp_path, make_contract, invoke,
    _rewrite_record,
)
from test_response_interface import InterfaceBackend
from core import checked_generation as lane
from governance.lab_admission import INTERFACE_CONTRACT_SCHEMA, operator_session
from memory import lab_effect
from schemas.checked_task import TASK_SCHEMA, canonical_bytes, identity
from scripts.v15_oracle_harvest_common import current_checked_portfolio


CONDITIONS = ["full_fixed_display", "full_varied_display", "host_bound_answer"]
MODELS = ["formal_adapter_parent", "quarantined_v25_child"]
BASELINE = "formal_adapter_parent/full_fixed_display"
DISPLAY_RULE = ("First32hex(SHA256(ASCII HI1|task_id|replicate_index)); identical for "
                "corresponding parent/child cells, distinct from fixed display")


def _write(path, value):
    path.write_bytes(canonical_bytes(value))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path):
    return json.loads(path.read_bytes())


def _repin_metadata(root):
    """Re-pin changed *synthetic test* inputs to reach their semantic gate."""
    definition = _read(root / "EXPERIMENT_DEFINITION.json")
    definition["tasks_sha256"] = hashlib.sha256((root / "TASKS.json").read_bytes()).hexdigest()
    definition["model_configuration_reference_sha256"] = hashlib.sha256(
        (root / "MODEL_CONFIGURATION_REFERENCE.json").read_bytes()).hexdigest()
    definition_pin = _write(root / "EXPERIMENT_DEFINITION.json", definition)
    roster = _read(root / "PROSPECTIVE_OPERATION_ROSTER.json")
    roster["frozen_definition_sha256"] = definition_pin
    roster_pin = _write(root / "PROSPECTIVE_OPERATION_ROSTER.json", roster)
    freeze = _read(root / "RUN_FREEZE.json")
    freeze.update(definition_sha256=definition_pin, roster_sha256=roster_pin)
    return _write(root / "RUN_FREEZE.json", freeze)


def _update_contract(root, stage, mutation):
    path = root / f"CONTRACT_{stage}.json"
    value = _read(path)
    mutation(value)
    contract_pin = _write(path, value)
    _write(root / stage / "operator_contract.json", value)
    freeze = _read(root / "RUN_FREEZE.json")
    freeze["contracts"][stage]["sha256"] = contract_pin
    return _write(root / "RUN_FREEZE.json", freeze)


def _portfolio(root, pin, baseline=BASELINE):
    return current_checked_portfolio(root, freeze_sha256=pin, baseline_route=baseline,
                                     comparison_mode="frozen_interface_v1")


def _locate(roster, *, stage="parent_rep0", condition="full_fixed_display", task="OI_add"):
    return next(row for row in roster if row["stage"] == stage and
                row["condition"] == condition and row["task_id"] == task)


def _snapshot(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def _fixture(root, monkeypatch, *, failed_generation=False, denied_effect=False,
             interrupted_restoration=False, split_replicate_baseline=False):
    """2 tasks x 2 named synthetic model subjects x 3 conditions x 2 repeats.

    Source/run/operation evidence is produced by the real native runtime. The
    named model subjects use distinct synthetic backend metadata; no actual
    model identity, weight activation or scientific capability is claimed.
    """
    root.mkdir()
    prep = root.with_name(root.name + "_fixture_preparation")
    prep.mkdir()
    _, _, template, _ = make_contract(prep, strategy="direct", attempts=1,
                                     calls=6, generated_tokens=96, attempts_per_task=1)
    monkeypatch.setattr(lane, "LocalQwenBackend", InterfaceBackend)
    monkeypatch.setattr(InterfaceBackend, "override", None)
    tasks = [
        {"schema_id": TASK_SCHEMA, "task_id": "OI_add", "kind": "integer_arithmetic",
         "problem": {"left": 17, "operation": "add", "right": 25}},
        {"schema_id": TASK_SCHEMA, "task_id": "OI_subtract", "kind": "integer_arithmetic",
         "problem": {"left": 7, "operation": "subtract", "right": 10}},
    ]
    stages = ["parent_rep0", "child_rep0", "child_rep1", "parent_rep1"]
    # Adapter activity is not manufactured: transport subjects have no adapter.
    backends = {
        role: {"kind": "local_qwen_nf4", "adapter_root": None,
               "explicit_synthetic_test_subject": role}
        for role in ("parent", "child")
    }
    _write(root / "TASKS.json", tasks)
    _write(root / "MODEL_CONFIGURATION_REFERENCE.json",
           {"parent_backend": backends["parent"], "child_backend": backends["child"]})
    roster, bindings = [], {}
    target = ("parent_rep0", "full_fixed_display", "OI_add")
    native_write = lab_effect.write_record
    native_generate = InterfaceBackend.generate
    for stage in stages:
        role, rep_text = stage.split("_rep")
        rep = int(rep_text)
        value = copy.deepcopy(template)
        value.update(schema_id=INTERFACE_CONTRACT_SCHEMA,
                     run_id=hashlib.sha256(stage.encode()).hexdigest()[:32],
                     output_root=str(root / stage), backend=backends[role], operations={})
        (root / stage).mkdir()
        stage_rows = []
        for task in tasks:
            for condition in CONDITIONS:
                display = ("1" * 32 if condition == "full_fixed_display" else
                           hashlib.sha256(f"HI1|{task['task_id']}|{rep}".encode()).hexdigest()[:32])
                interface = ({"mode": "host_bound_answer", "display_nonce": None}
                             if condition == "host_bound_answer" else
                             {"mode": "full_envelope_control", "display_nonce": display})
                op = {"task": task, "strategy": "direct", "attempts": 1,
                      "consume": True, "response_interface": interface}
                op_id = identity(op)
                value["operations"][op_id] = op
                row = {"condition": condition, "model": MODELS[role == "child"],
                       "operation": op, "operation_id": op_id, "replicate": rep,
                       "stage": stage, "task_id": task["task_id"], "task_sha256": identity(task)}
                roster.append(row)
                stage_rows.append(row)
        path = root / f"CONTRACT_{stage}.json"
        pin = _write(path, value)
        bindings[stage] = {"name": path.name, "sha256": pin}
        # A real revocation is last in that contract; do not erase its marker to
        # admit later work. Other stage contracts are separately admitted.
        stage_rows.sort(key=lambda r: (r["stage"], r["condition"], r["task_id"]) == target)
        with operator_session(path, expected_sha256=pin):
            for row in stage_rows:
                is_target = (row["stage"], row["condition"], row["task_id"]) == target
                task_id, condition = row["task_id"], row["condition"]
                answer = 42 if task_id == "OI_add" else -3
                if role == "parent" and task_id == "OI_subtract":
                    answer = 3
                if role == "child" and condition == "full_fixed_display" and task_id == "OI_add":
                    answer = 41
                if (split_replicate_baseline and stage == "parent_rep1" and
                        condition == "full_fixed_display" and task_id == "OI_add"):
                    answer = 41
                SyntheticBackend.answers = [answer]
                InterfaceBackend.override = ("-3" if role == "parent" and task_id == "OI_subtract"
                                              and condition == "host_bound_answer" else
                                              "42" if role == "child" and task_id == "OI_add"
                                              and condition == "full_varied_display" else None)
                timing = None if condition == "host_bound_answer" else 0.25
                SyntheticBackend.mutate = staticmethod(lambda raw, t=timing: raw.update(generation_seconds=t))
                with monkeypatch.context() as local:
                    if failed_generation and is_target:
                        def failed(*args, **kwargs):
                            raise TimeoutError("EXPLICIT_SYNTHETIC_UNKNOWN_PARTIAL_GENERATION")
                        local.setattr(InterfaceBackend, "generate", failed)
                    if denied_effect and is_target:
                        def revoked(destination, record):
                            written = native_write(destination, record)
                            if destination.name == "effect_prepared.json":
                                (root / stage / "REVOKED").write_text("explicit synthetic test revocation")
                            return written
                        local.setattr(lab_effect, "write_record", revoked)
                    if interrupted_restoration and is_target:
                        def interrupted(*args, **kwargs):
                            raise OSError("EXPLICIT_SYNTHETIC_INTERRUPTED_RESTORATION")
                        local.setattr(lab_effect, "_restore_owned_target", interrupted)
                    result = invoke(value, row["operation_id"])
                expected_hold = ("HOLD_GENERATION_FAILED" if failed_generation and is_target else
                                 "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED"
                                 if (denied_effect or interrupted_restoration) and is_target else None)
                if expected_hold:
                    assert result["status"] == expected_hold, result
        if interrupted_restoration and stage == target[0]:
            target_row = next(r for r in stage_rows if
                              (r["stage"], r["condition"], r["task_id"]) == target)
            calls = len(SyntheticBackend.seen)
            with operator_session(path, expected_sha256=pin):
                recovered = invoke(value, target_row["operation_id"])
            assert recovered["status"] == "RECOVERED_HELD_OPERATION_NO_RETRY"
            assert len(SyntheticBackend.seen) == calls
        assert InterfaceBackend.generate is native_generate
    definition = {
        "schema_id": "kt.host_interface.development_definition.v1", "conditions": CONDITIONS,
        "models": MODELS, "independent_process_replicates_per_model": 2,
        "attempts_per_operation": 1, "operation_strategy": "direct", "consume": True,
        "varied_display_rule": DISPLAY_RULE, "fixed_display_nonce": "1" * 32,
        "task_order": [t["task_id"] for t in tasks], "stage_order": stages, "generation_total": 24,
    }
    _write(root / "EXPERIMENT_DEFINITION.json", definition)
    _write(root / "PROSPECTIVE_OPERATION_ROSTER.json", {
        "rows": roster, "generation_rows": 24, "independent_tasks": 2,
        "contract_names_expected": [f"CONTRACT_{stage}.json" for stage in stages],
    })
    _write(root / "RUN_FREEZE.json", {"schema_id": "kt.h4.external_engineering_run.v1",
        "run_id": "synthetic_frozen_interface_portfolio", "source_head": "a" * 40,
        "source_tree": "b" * 40, "contracts": bindings})
    pin = _repin_metadata(root)
    return root, pin, roster


def test_complete_portfolio_preserves_conditions_replicates_and_native_semantics(tmp_path, monkeypatch):
    root, pin, roster = _fixture(tmp_path / "portfolio", monkeypatch)
    before = _snapshot(root)
    report = _portfolio(root, pin)
    assert report["status"] == "COMPLETE_RECORDED_ROSTER"
    assert report["assigned_operations"] == report["completed_operations"] == 24
    assert report["independent_tasks"] == 2 and report["replicates"] == 2
    assert report["conditions"] == CONDITIONS and report["models"] == MODELS
    assert len(report["rows"]) == 24 and len(report["cells"]) == 6
    assert all(c["assigned"] == c["observed"] == c["completed"] == 4 for c in report["cells"])
    totals = {c["route"]: c["strict_successes"] for c in report["cells"]}
    assert totals == {
        "formal_adapter_parent/full_fixed_display": 2,
        "formal_adapter_parent/full_varied_display": 2,
        "formal_adapter_parent/host_bound_answer": 2,
        "quarantined_v25_child/full_fixed_display": 2,
        "quarantined_v25_child/full_varied_display": 2,
        "quarantined_v25_child/host_bound_answer": 4,
    }
    assert len({(r["contract_sha256"], r["operation_id"]) for r in report["rows"]}) == 24
    assert len({r["operation_id"] for r in report["rows"]}) < 24
    assert len(report["oracle_gap_matrix"]) == 4  # two tasks, two paired strata
    assert all(len(g["assigned_routes"]) == 6 for g in report["oracle_gap_matrix"])
    wrong = next(r for r in report["rows"] if r["stage"] == "parent_rep0" and
                 r["condition"] == "full_fixed_display" and r["task_id"] == "OI_subtract")
    assert wrong["evidence_valid"] is True and wrong["protocol_valid"] is True
    assert wrong["strict_success"] is False and wrong["effect_applied"] is False
    protocol = next(r for r in report["rows"] if r["stage"] == "parent_rep0" and
                    r["condition"] == "host_bound_answer" and r["task_id"] == "OI_subtract")
    assert protocol["evidence_valid"] is True and protocol["protocol_valid"] is False
    assert protocol["strict_success"] is False and protocol["diagnostic_content_correct"] is None
    success = next(r for r in report["rows"] if r["strict_success"])
    assert success["effect_authorized"] is True and success["effect_restored"] is True
    assert success["input_tokens"] == 3 and success["output_tokens"] == 2
    assert all(r["generation_seconds"] is None for r in report["rows"]
               if r["condition"] == "host_bound_answer")
    assert all(r["generation_seconds"] == 0.25 for r in report["rows"]
               if r["condition"] != "host_bound_answer")
    assert report["training_authority"] is False and report["promotion_authority"] is False
    assert report["runtime_feature_authority"] is False and report["claim_authority"] == "NONE"
    assert all(r["diagnostic_content_correct"] is None for r in report["rows"])
    assert _snapshot(root) == before


def test_actual_cli_reads_intact_portfolio_without_mutation(tmp_path, monkeypatch):
    root, pin, _ = _fixture(tmp_path / "portfolio", monkeypatch)
    before = _snapshot(root)
    repo = Path(lane.__file__).resolve().parents[4]
    output = tmp_path / "external_analysis.json"
    run = subprocess.run([sys.executable, "-B", str(repo / "scripts/build_v15_oracle_gap_matrix.py"),
        "--current-checked-run", str(root), "--freeze-sha256", pin,
        "--comparison-mode", "frozen_interface_v1", "--baseline-route", BASELINE,
        "--output", str(output)], capture_output=True, text=True, timeout=90)
    assert run.returncode == 0, run.stdout + run.stderr
    report = _read(output)
    assert report["assigned_operations"] == report["completed_operations"] == 24
    assert report["independent_tasks"] == 2 and len(report["cells"]) == 6
    assert report["baseline_route"] == BASELINE
    assert _snapshot(root) == before


def test_rescue_damage_and_baseline_are_paired_within_each_replicate(tmp_path, monkeypatch):
    root, pin, _ = _fixture(tmp_path / "portfolio", monkeypatch, split_replicate_baseline=True)
    report = _portfolio(root, pin)
    groups = {g["replicate"]: g for g in report["oracle_gap_matrix"] if g["task_id"] == "OI_add"}
    assert set(groups) == {0, 1}
    assert groups[0]["baseline_success"] is True
    assert groups[0]["rescue_over_baseline"] == []
    assert set(groups[0]["damage_against_baseline"]) == {
        "quarantined_v25_child/full_fixed_display", "quarantined_v25_child/full_varied_display"}
    assert groups[0]["opportunity"] is None
    assert groups[0]["opportunity_scope"] == "NO_OBSERVED_BASELINE_FAILURE"
    assert groups[1]["baseline_success"] is False
    assert groups[1]["damage_against_baseline"] == []
    assert set(groups[1]["rescue_over_baseline"]) == {
        "formal_adapter_parent/full_varied_display", "formal_adapter_parent/host_bound_answer",
        "quarantined_v25_child/host_bound_answer"}
    assert groups[1]["opportunity"] == "SELECTION_OPPORTUNITY"
    assert report["assigned_operations"] == 24 and report["independent_tasks"] == 2


def test_partial_native_generation_never_becomes_zero_total_cost(tmp_path, monkeypatch):
    root, pin, roster = _fixture(tmp_path / "portfolio", monkeypatch, failed_generation=True)
    report = _portfolio(root, pin)
    target = _locate(roster)
    row = next(r for r in report["rows"] if r["stage"] == target["stage"] and
               r["operation_id"] == target["operation_id"])
    assert report["status"] == "INCOMPLETE_RECORDED_ROSTER"
    assert report["assigned_operations"] == 24 and report["completed_operations"] == 23
    assert row["calls_reserved"] == 1 and row["calls_returned"] == 0
    assert row["complete_token_accounting"] is False
    assert row["generation_seconds"] is None
    assert row["known_generation_seconds"] is None and row["complete_time_accounting"] is False
    assert row["protocol_valid"] is None and row["diagnostic_content_correct"] is None
    missing = next(m for m in report["missing"] if m["operation_id"] == target["operation_id"]
                   and m["stage"] == target["stage"])
    assert missing["cost"] == "PARTIAL_KNOWN_PLUS_UNKNOWN"
    group = next(g for g in report["oracle_gap_matrix"] if g["task_id"] == "OI_add" and g["replicate"] == 0)
    assert group["baseline_success"] is None and group["all_assigned_routes_failed"] is False
    # A hash-covered but semantically unauthenticated authority label in a
    # partial record cannot gain authority merely because a file is present.
    folder = root / target["stage"] / target["operation_id"]
    authority_pin = _write(folder / "effect_authority.json", {
        "authorized": True, "origin": "SELF_ASSERTED_SYNTHETIC_NEGATIVE_RECORD"})
    result = _read(folder / "result.json")
    result["files"]["effect_authority.json"] = authority_pin
    result["files"]["effect_recovered.json"] = _write(folder / "effect_recovered.json", {
        "restored_absence_observed": True, "origin": "HASH_COVERED_SELF_ASSERTION_NOT_RECOVERY"})
    _write(folder / "result.json", result)
    altered = _portfolio(root, pin)
    partial = next(r for r in altered["rows"] if r["stage"] == target["stage"] and
                   r["operation_id"] == target["operation_id"])
    assert partial["effect_authority_record_present"] is True
    assert partial["effect_authorized"] is None
    assert partial["effect_applied"] is None
    assert partial["effect_restored"] is None and partial["post_terminal_recovery_verified"] is False
    assert partial["generation_seconds"] is None


def test_native_denied_effect_cannot_gain_authority_from_correct_answer(tmp_path, monkeypatch):
    root, pin, roster = _fixture(tmp_path / "portfolio", monkeypatch, denied_effect=True)
    report = _portfolio(root, pin)
    target = _locate(roster)
    row = next(r for r in report["rows"] if r["stage"] == target["stage"] and
               r["operation_id"] == target["operation_id"])
    assert row["evidence_valid"] is True and row["protocol_valid"] is True
    assert row["first_attempt_success"] is True
    assert row["completed"] is False and row["effect_applied"] is not True
    assert row["effect_authorized"] is not True and row["effect_restored"] is not True
    assert report["training_authority"] is False and report["promotion_authority"] is False


def test_missing_record_preserves_assigned_denominator_and_unknown_cost(tmp_path, monkeypatch):
    root, pin, roster = _fixture(tmp_path / "portfolio", monkeypatch)
    target = _locate(roster)
    result = root / target["stage"] / target["operation_id"] / "result.json"
    result.rename(result.with_name("preserved_interrupted_result.json"))
    report = _portfolio(root, pin)
    assert report["assigned_operations"] == 24 and report["completed_operations"] == 23
    assert report["status"] == "INCOMPLETE_RECORDED_ROSTER"
    assert len(report["missing"]) == 1 and report["missing"][0]["cost"] == "UNKNOWN_NOT_ZERO"
    assert sum(c["assigned"] for c in report["cells"]) == 24


def test_post_terminal_recovery_is_verified_without_creating_a_new_sample(tmp_path, monkeypatch):
    root, pin, roster = _fixture(tmp_path / "portfolio", monkeypatch, interrupted_restoration=True)
    calls = len(SyntheticBackend.seen)
    report = _portfolio(root, pin)
    target = _locate(roster)
    row = next(r for r in report["rows"] if r["stage"] == target["stage"] and
               r["operation_id"] == target["operation_id"])
    assert report["assigned_operations"] == 24 and len(report["rows"]) == 24
    assert row["status"] == "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED"
    assert row["completed"] is False and row["strict_success"] is False
    assert row["post_terminal_recovery_verified"] is True and row["effect_restored"] is True
    assert len(SyntheticBackend.seen) == calls
    folder = root / target["stage"] / target["operation_id"]
    assert "effect_recovered.json" not in _read(folder / "result.json")["files"]
    recovered = _read(folder / "effect_recovered.json")
    recovered["restored_absence_observed"] = False
    _write(folder / "effect_recovered.json", recovered)
    with pytest.raises(RuntimeError, match="LAB_REPLAY_POST_TERMINAL_RECOVERY"):
        _portfolio(root, pin)


@pytest.mark.parametrize("mutation,reason", [
    ("boolean_replicate", "CURRENT_ORACLE_COMPARISON_IDENTITY"),
    ("duplicate_evidence", "CURRENT_ORACLE_DUPLICATE_CELL"),
    ("conflicting_condition", "CURRENT_ORACLE_CONDITION_BINDING"),
    ("extra_roster_row", "CURRENT_ORACLE_COMPARISON_ROSTER"),
    ("wrong_model_reference", "CURRENT_ORACLE_MODEL_BINDING"),
])
def test_rehashed_comparison_metadata_rejects_semantic_corruption(tmp_path, monkeypatch, mutation, reason):
    root, _, _ = _fixture(tmp_path / "portfolio", monkeypatch)
    path = root / "PROSPECTIVE_OPERATION_ROSTER.json"
    roster = _read(path)
    if mutation == "boolean_replicate":
        roster["rows"][0]["replicate"] = False
    elif mutation == "duplicate_evidence":
        roster["rows"][1] = copy.deepcopy(roster["rows"][0])
    elif mutation == "conflicting_condition":
        roster["rows"][0]["condition"] = "full_varied_display"
    elif mutation == "extra_roster_row":
        roster["rows"].append(copy.deepcopy(roster["rows"][0]))
    else:
        refs = _read(root / "MODEL_CONFIGURATION_REFERENCE.json")
        refs["child_backend"]["explicit_synthetic_test_subject"] = "unrelated_model"
        _write(root / "MODEL_CONFIGURATION_REFERENCE.json", refs)
    _write(path, roster)
    pin = _repin_metadata(root)
    with pytest.raises((ValueError, RuntimeError), match=reason):
        _portfolio(root, pin)


@pytest.mark.parametrize("mutation,reason", [
    ("missing_definition_pin", "CURRENT_ORACLE_COMPARISON_PIN"),
    ("missing_roster_pin", "CURRENT_ORACLE_COMPARISON_PIN"),
    ("changed_tasks_without_repin", "CURRENT_ORACLE_INPUT_PIN"),
    ("wrong_backend", "CURRENT_ORACLE_MODEL_BINDING"),
    ("mixed_source", "CURRENT_ORACLE_MIXED_SOURCE"),
    ("extra_stage", "CURRENT_ORACLE_EXTRA_STAGE"),
    ("extra_contract", "CURRENT_ORACLE_EXTRA_CONTRACT"),
    ("orphan_evidence", "CURRENT_ORACLE_EXTRA_OPERATION"),
    ("raw_tamper", "LAB_REPLAY_BYTES"),
    ("rehashed_check_tamper", "LAB_REPLAY_CHECKER_MISMATCH"),
])
def test_native_owners_reject_wrong_identity_and_tamper(tmp_path, monkeypatch, mutation, reason):
    root, pin, roster = _fixture(tmp_path / "portfolio", monkeypatch)
    target = _locate(roster)
    folder = root / target["stage"] / target["operation_id"]
    if mutation.startswith("missing_"):
        freeze = _read(root / "RUN_FREEZE.json")
        freeze.pop("definition_sha256" if mutation == "missing_definition_pin" else "roster_sha256")
        pin = _write(root / "RUN_FREEZE.json", freeze)
    elif mutation == "changed_tasks_without_repin":
        with (root / "TASKS.json").open("ab") as stream:
            stream.write(b" ")
    elif mutation == "wrong_backend":
        pin = _update_contract(root, "child_rep0", lambda c: c["backend"].update(
            explicit_synthetic_test_subject="unrelated_model"))
    elif mutation == "mixed_source":
        def changed_source(c):
            c["source_files"][sorted(c["source_files"])[0]] = "0" * 64
        pin = _update_contract(root, "parent_rep1", changed_source)
    elif mutation == "orphan_evidence":
        (root / "parent_rep0" / ("f" * 64)).mkdir()
    elif mutation == "extra_stage":
        (root / "undeclared_stage").mkdir()
    elif mutation == "extra_contract":
        _write(root / "CONTRACT_undeclared_stage.json", {"self_asserted": True})
    elif mutation == "raw_tamper":
        with (folder / "attempt_0_raw.json").open("ab") as stream:
            stream.write(b" ")
    else:
        _rewrite_record(folder, "attempt_0_check.json", lambda check: check.update(satisfied=False))
    with pytest.raises((ValueError, RuntimeError), match=reason):
        _portfolio(root, pin)


@pytest.mark.parametrize("baseline,reason", [
    (None, "CURRENT_ORACLE_BASELINE_REQUIRED"),
    ("formal_adapter_parent", "CURRENT_ORACLE_BASELINE_NOT_ASSIGNED"),
    ("formal_adapter_parent/unassigned", "CURRENT_ORACLE_BASELINE_NOT_ASSIGNED"),
])
def test_comparison_requires_unambiguous_predeclared_baseline(tmp_path, monkeypatch, baseline, reason):
    root, pin, _ = _fixture(tmp_path / "portfolio", monkeypatch)
    with pytest.raises((ValueError, RuntimeError), match=reason):
        _portfolio(root, pin, baseline=baseline)


def test_new_comparison_mode_does_not_silently_reinterpret_legacy_mode(tmp_path, monkeypatch):
    root, pin, _ = _fixture(tmp_path / "portfolio", monkeypatch)
    with pytest.raises(ValueError, match="CURRENT_ORACLE_DUPLICATE_CELL"):
        current_checked_portfolio(root, freeze_sha256=pin,
                                  baseline_route="parent_rep0/direct/full_envelope_control")
