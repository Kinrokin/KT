"""Hostile unit courts. All model outputs here are explicitly synthetic test data."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types

import pytest

from core.import_truth_guard import ImportTruthGuard
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from core import checked_generation as lane
from governance.lab_admission import CONTRACT_SCHEMA, REQUEST_SCHEMA, LabSession, operator_session
from memory import lab_effect
from schemas.checked_task import PROPOSAL_SCHEMA, TASK_SCHEMA, canonical_bytes, identity
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH


@pytest.fixture
def tmp_path():
    # This dedicated laboratory court requires outputs outside the source tree.
    # Positive lab fixtures require an actually external root; keep all their
    # records there without weakening admission or deleting evidence at teardown.
    parent = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
    repo = Path(lane.__file__).resolve().parents[4]
    assert not parent.is_relative_to(repo), "laboratory test temporary root must be external"
    return Path(tempfile.mkdtemp(prefix="kt_checked_lab_test_", dir=parent))


def make_contract(tmp_path, *, strategy="kt_diagnostic", attempts=3, consume=True, **limits):
    task = {"schema_id": TASK_SCHEMA, "task_id": "addition", "kind": "integer_arithmetic",
            "problem": {"left": 17, "operation": "add", "right": 25}}
    op = {"task": task, "strategy": strategy, "attempts": attempts, "consume": consume}
    source = Path(lane.__file__).resolve().parents[1]
    pins = {p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source.rglob("*.py") if "tests" not in p.parts}
    root = tmp_path / "external_run"
    root.mkdir()
    value = {"schema_id": CONTRACT_SCHEMA, "run_id": "a" * 32, "authority_sha256": "b" * 64,
             "authority_basis": "OWNER_ADOPTED_PRIVATE_NONPAID_EXPERIMENT", "output_root": str(root),
             "expires_at": int(time.time()) + 1200, "source_files": pins,
             "runtime_registry_sha256": hashlib.sha256((source.parent / "docs" / "RUNTIME_REGISTRY.json").read_bytes()).hexdigest(),
             "backend": {"kind": "local_qwen_nf4", "adapter_root": None},
             "limits": {"calls": 9, "generated_tokens": 300, "attempts_per_task": 3,
                        "max_new_tokens": 16, "timeout_seconds": 5, "wall_seconds": 600, **limits},
             "operations": {identity(op): op}}
    path = tmp_path / "operator.json"
    path.write_bytes(canonical_bytes(value))
    return path, hashlib.sha256(path.read_bytes()).hexdigest(), value, identity(op)


class SyntheticBackend:
    answers = [41, 42]
    seen = []
    mutate = None

    def __init__(self, **kwargs):
        self.sha = kwargs["contract_sha256"]
        self.worker_id = "synthetic"
        self.load_record = {"explicit_test_only": True}
        self.index = 0

    def generate(self, *, prompt, nonce, max_new_tokens):
        self.seen.append(prompt)
        body = json.loads(prompt.split("\n", 1)[1])
        answer = self.answers[min(self.index, len(self.answers) - 1)]
        self.index += 1
        proposal = {"schema_id": PROPOSAL_SCHEMA, "task_hash": identity(body["task"]), "nonce": nonce, "answer": answer}
        raw = {"kind": "GENERATED", "fresh_generation": True, "nonce": nonce, "contract_sha256": self.sha,
               "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(), "input_token_ids": [1, 3, 4],
               "generated_token_ids": [9, 2], "input_tokens": 3, "output_tokens": 2,
               "output_text": canonical_bytes(proposal).decode(), "max_new_tokens": max_new_tokens,
               "finish_reason": "EOS", "eos_token_ids": [2]}
        if self.mutate:
            self.mutate(raw)
        return raw

    def close(self):
        pass


@pytest.fixture(autouse=True)
def isolated_test_transport(monkeypatch):
    # Pytest collects the curriculum court into the same interpreter. That test
    # module is not part of a deployed runtime. Isolate only the collected test
    # file, never a training implementation or the production invariant guard.
    collected = sys.modules.get("test_curriculum_boundary")
    expected = Path(lane.__file__).resolve().parents[2] / "src/curriculum/tests/test_curriculum_boundary.py"
    if collected is not None:
        assert Path(collected.__file__).resolve() == expected
        sys.modules.pop("test_curriculum_boundary")
    prior_entries = {name: sys.modules.get(name) for name in ("kt.entrypoint", "core.spine")}
    SyntheticBackend.answers = [41, 42]
    SyntheticBackend.seen = []
    SyntheticBackend.mutate = None
    monkeypatch.setattr(lane, "LocalQwenBackend", SyntheticBackend)
    yield
    ImportTruthGuard.uninstall_for_tests()
    if collected is not None:
        sys.modules["test_curriculum_boundary"] = collected
    # Legacy courts intentionally import these entry points after redirecting
    # their registry loader. Do not leave our first-use import in their way.
    for name, module in prior_entries.items():
        if module is None:
            loaded = sys.modules.pop(name, None)
            package, child = name.rsplit(".", 1)
            parent = sys.modules.get(package)
            if loaded is not None and parent is not None and getattr(parent, child, None) is loaded:
                delattr(parent, child)


def invoke(value, operation):
    from kt.entrypoint import invoke as entry
    context = {"schema_id": RUNTIME_CONTEXT_SCHEMA_ID, "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
               "constitution_version_hash": CONSTITUTION_VERSION_HASH, "artifact_root": value["output_root"],
               "envelope": {"input": json.dumps({"schema_id": REQUEST_SCHEMA, "operation_id": operation})}}
    return entry(context)


def test_canonical_repair_consumes_diagnostic_then_observes_and_restores(tmp_path):
    path, sha, value, op = make_contract(tmp_path)
    with operator_session(path, expected_sha256=sha):
        result = invoke(value, op)
    assert result["status"] == "CHECKED_EFFECT_RESTORED", result
    assert result["attempts"] == [0, 1]
    assert result["model_calls"] == 2
    assert result["input_tokens"] == 6 and result["output_tokens"] == 4
    assert "ARITHMETIC_EQUALITY" in SyntheticBackend.seen[1]
    root = Path(value["output_root"]) / op
    assert not (root / "sandbox_state.json").exists()
    assert lab_effect.read_record(root / "effect_applied.json")["observed_state"]["answer"] == 42
    assert lane.verify_operation(root, expected_contract_sha256=sha)["status"] == "REPLAY_NO_INFERENCE_NO_EFFECT"
    with operator_session(path, expected_sha256=sha):
        assert invoke(value, op)["status"] == "REPLAY_NO_INFERENCE_NO_EFFECT"
    assert len(SyntheticBackend.seen) == 2


def current_oracle_fixture(tmp_path):
    """Synthetic data only; exercise the actual recorded-operation reader."""
    path, pin, value, op = make_contract(tmp_path, strategy="direct", attempts=1)
    SyntheticBackend.answers = [42]
    with operator_session(path, expected_sha256=pin):
        invoke(value, op)
    (tmp_path / "CONTRACT_external_run.json").write_bytes(path.read_bytes())
    freeze = {"schema_id": "kt.h4.external_engineering_run.v1", "run_id": "synthetic_current_oracle",
              "source_head": "a" * 40, "source_tree": "b" * 40,
              "contracts": {"external_run": {"name": "CONTRACT_external_run.json", "sha256": pin}}}
    (tmp_path / "RUN_FREEZE.json").write_bytes(canonical_bytes(freeze))
    return tmp_path, hashlib.sha256(canonical_bytes(freeze)).hexdigest(), value, op


def test_current_oracle_consumes_verified_rows_without_rewriting_history(tmp_path):
    from scripts.v15_oracle_harvest_common import current_checked_portfolio, oracle_gap_matrix
    before = copy.deepcopy(oracle_gap_matrix())
    root, pin, value, op = current_oracle_fixture(tmp_path)
    files_before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    report = current_checked_portfolio(root, freeze_sha256=pin, baseline_route="external_run/direct")
    assert report["status"] == "COMPLETE_RECORDED_ROSTER"
    assert report["assigned_operations"] == report["completed_operations"] == 1
    assert report["rows"][0]["effect_restored"] is True
    assert report["rows"][0]["first_attempt_success"] is True
    assert report["oracle_gap_matrix"][0]["cheapest_correct_known_tokens"] == 5
    assert report["training_authority"] is report["runtime_feature_authority"] is False
    assert report["rows"][0]["generation_seconds"] is None  # synthetic fixture omits timing
    assert oracle_gap_matrix() == before
    assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()} == files_before
    assert len(SyntheticBackend.seen) == 1  # harvesting did not call the model


def test_current_oracle_retains_missing_operation_in_assigned_denominator(tmp_path):
    from scripts.v15_oracle_harvest_common import current_checked_portfolio
    root, pin, value, op = current_oracle_fixture(tmp_path)
    # Fixture mutation simulates interrupted persistence; the original is retained.
    result = Path(value["output_root"]) / op / "result.json"
    result.rename(result.with_name("preserved_interrupted_result.json"))
    report = current_checked_portfolio(root, freeze_sha256=pin, baseline_route="external_run/direct")
    assert report["status"] == "INCOMPLETE_RECORDED_ROSTER"
    assert report["assigned_operations"] == 1 and report["completed_operations"] == 0
    assert len(report["missing"]) == 1 and report["missing"][0]["cost"] == "UNKNOWN_NOT_ZERO"
    assert report["oracle_gap_matrix"][0]["baseline_success"] is None
    assert report["oracle_gap_matrix"][0]["all_assigned_routes_failed"] is False


@pytest.mark.parametrize("mutation,reason", [
    ("freeze", "CURRENT_ORACLE_INPUT_PIN"),
    ("contract", "CURRENT_ORACLE_INPUT_PIN"),
    ("raw", "LAB_REPLAY_BYTES"),
    ("extra_operation", "CURRENT_ORACLE_EXTRA_OPERATION"),
    ("unassigned_baseline", "CURRENT_ORACLE_BASELINE_NOT_ASSIGNED"),
    ("boolean_calls", "CURRENT_ORACLE_COUNTS"),
])
def test_current_oracle_rejects_wrong_identity_or_extra_evidence(tmp_path, mutation, reason):
    from scripts.v15_oracle_harvest_common import current_checked_portfolio
    root, pin, value, op = current_oracle_fixture(tmp_path)
    baseline = "external_run/direct"
    if mutation == "freeze":
        pin = "0" * 64
    elif mutation == "contract":
        with (root / "CONTRACT_external_run.json").open("ab") as f:
            f.write(b" ")
    elif mutation == "raw":
        with (Path(value["output_root"]) / op / "attempt_0_raw.json").open("ab") as f:
            f.write(b" ")
    elif mutation == "extra_operation":
        (Path(value["output_root"]) / ("c" * 64)).mkdir()
    elif mutation == "boolean_calls":
        file = Path(value["output_root"]) / op / "result.json"
        result = json.loads(file.read_bytes())
        result["model_calls"] = True
        file.write_bytes(canonical_bytes(result))
    else:
        baseline = "unknown/direct"
    with pytest.raises((ValueError, RuntimeError), match=reason):
        current_checked_portfolio(root, freeze_sha256=pin, baseline_route=baseline)


def test_current_oracle_rejects_linked_ancestor_before_following_data(tmp_path):
    from scripts.v15_oracle_harvest_common import current_checked_portfolio
    parent = tmp_path / "actual"
    parent.mkdir()
    root, pin, _, _ = current_oracle_fixture(parent)
    linked = tmp_path / "linked"
    linked.symlink_to(parent, target_is_directory=True)
    with pytest.raises(RuntimeError, match="link/reparse"):
        current_checked_portfolio(linked, freeze_sha256=pin, baseline_route="external_run/direct")


@pytest.mark.parametrize("answers", [(41, 42), (42, 41), (41, 41)])
def test_current_oracle_computes_observed_rescue_damage_and_all_fail(tmp_path, answers):
    from scripts.v15_oracle_harvest_common import current_checked_portfolio
    bindings = {}
    for label, answer in zip(("base", "alternative"), answers):
        preparation = tmp_path / ("prepare_" + label)
        preparation.mkdir()
        path, _, value, op = make_contract(preparation, strategy="direct", attempts=1)
        destination = tmp_path / label
        destination.mkdir()
        value["output_root"] = str(destination)
        value["run_id"] = hashlib.sha256(label.encode()).hexdigest()[:32]
        path.write_bytes(canonical_bytes(value))
        pin = hashlib.sha256(path.read_bytes()).hexdigest()
        SyntheticBackend.answers = [answer]
        with operator_session(path, expected_sha256=pin):
            invoke(value, op)
        name = f"CONTRACT_{label}.json"
        (tmp_path / name).write_bytes(path.read_bytes())
        bindings[label] = {"name": name, "sha256": pin}
    freeze = {"schema_id": "kt.h4.external_engineering_run.v1", "run_id": "synthetic_pair",
              "source_head": "a" * 40, "source_tree": "b" * 40, "contracts": bindings}
    raw = canonical_bytes(freeze)
    (tmp_path / "RUN_FREEZE.json").write_bytes(raw)
    report = current_checked_portfolio(tmp_path, freeze_sha256=hashlib.sha256(raw).hexdigest())
    gap = report["oracle_gap_matrix"][0]
    assert report["assigned_operations"] == report["completed_operations"] == 2
    assert gap["rescue_over_baseline"] == (["alternative/direct"] if answers == (41, 42) else [])
    assert gap["damage_against_baseline"] == (["alternative/direct"] if answers == (42, 41) else [])
    assert gap["all_assigned_routes_failed"] is (answers == (41, 41))
    assert gap["observed_union_success"] is (42 in answers)
    assert report["ownership"].startswith("UNKNOWN_BLOCKED")


def test_operator_admission_cannot_be_supplied_by_runtime_request(tmp_path):
    _, _, value, op = make_contract(tmp_path)
    result = invoke(value, op)
    assert result["status"] == "FAIL"
    assert "LAB_OPERATOR_ADMISSION_REQUIRED" in result["error"]
    assert not SyntheticBackend.seen


def test_real_training_module_is_still_rejected_before_laboratory_generation(tmp_path, monkeypatch):
    path, sha, value, op = make_contract(tmp_path)
    monkeypatch.setitem(sys.modules, "trainer.unadmitted", types.ModuleType("trainer.unadmitted"))
    with operator_session(path, expected_sha256=sha), pytest.raises(Exception, match="Training/runtime bleed"):
        invoke(value, op)
    assert not SyntheticBackend.seen


def operator_module():
    path = Path(lane.__file__).resolve().parents[3] / "tools/operator/run_checked_lab.py"
    spec = importlib.util.spec_from_file_location("checked_lab_operator_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("original_status", ["HOLD_GENERATION_FAILED", "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED"])
def test_operator_replay_does_not_upgrade_retained_hold(tmp_path, monkeypatch, original_status):
    from kt import entrypoint
    path, sha, value, op = make_contract(tmp_path)
    monkeypatch.setattr(entrypoint, "invoke", lambda context: {
        "status": "REPLAY_NO_INFERENCE_NO_EFFECT", "original": {"status": original_status}})
    assert operator_module().main(["--contract", str(path), "--contract-sha256", sha]) == 2
    assert not (Path(value["output_root"]) / "operator_complete.json").exists()
    assert not SyntheticBackend.seen


def test_operator_replay_preserves_actual_outcome_and_execution_mode(tmp_path, monkeypatch):
    from kt import entrypoint
    path, sha, value, op = make_contract(tmp_path)
    monkeypatch.setattr(entrypoint, "invoke", lambda context: {
        "status": "REPLAY_NO_INFERENCE_NO_EFFECT", "original": {"status": "HELD_TASK_PREDICATE"}})
    assert operator_module().main(["--contract", str(path), "--contract-sha256", sha]) == 0
    receipt = lab_effect.read_record(Path(value["output_root"]) / "operator_complete.json")
    assert receipt["operation_statuses"] == {op: "HELD_TASK_PREDICATE"}
    assert receipt["operation_execution_modes"] == {op: "REPLAY_NO_INFERENCE_NO_EFFECT"}
    assert not SyntheticBackend.seen


def test_direct_spine_cannot_counterfeit_canonical_entry(tmp_path):
    from core.spine import run
    path, sha, value, op = make_contract(tmp_path)
    context = {"schema_id": RUNTIME_CONTEXT_SCHEMA_ID, "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
               "constitution_version_hash": CONSTITUTION_VERSION_HASH, "artifact_root": value["output_root"],
               "envelope": {"input": json.dumps({"schema_id": REQUEST_SCHEMA, "operation_id": op})}}
    with operator_session(path, expected_sha256=sha), pytest.raises(Exception, match="requires kt.entrypoint.invoke"):
        run(context)
    assert not SyntheticBackend.seen


@pytest.mark.parametrize("change,reason", [
    (lambda raw: raw.update(output_tokens=True), "LAB_GENERATION_USAGE"),
    (lambda raw: raw.update(nonce="0" * 32), "LAB_GENERATION_IDENTITY"),
    (lambda raw: raw.update(fresh_generation=False), "LAB_GENERATION_IDENTITY"),
    (lambda raw: raw.update(finish_reason="MAX_NEW_TOKENS"), "LAB_GENERATION_INCOMPLETE"),
    (lambda raw: raw.update(generated_token_ids=[1] * 16 + [2], output_tokens=17), "LAB_OUTPUT_CAP"),
])
def test_invalid_transport_rejected_before_effect(tmp_path, change, reason):
    SyntheticBackend.answers = [42]
    SyntheticBackend.mutate = staticmethod(change)
    path, sha, value, op = make_contract(tmp_path)
    with operator_session(path, expected_sha256=sha):
        result = invoke(value, op)
    assert result["status"] == "HOLD_GENERATION_FAILED", result
    root = Path(value["output_root"]) / op
    assert reason in lab_effect.read_record(root / "attempt_0_failure.json")["reason"]
    assert not (root / "effect_prepared.json").exists()


@pytest.mark.parametrize("control", ["revoked", "expired"])
def test_permission_rechecked_after_proposal_before_effect(tmp_path, monkeypatch, control):
    SyntheticBackend.answers = [42]
    path, sha, value, op = make_contract(tmp_path)
    original = lab_effect.write_record
    def change_at_prepared(target, record):
        result = original(target, record)
        if target.name == "effect_prepared.json":
            if control == "revoked":
                (Path(value["output_root"]) / "REVOKED").write_text("operator revocation")
            else:
                monkeypatch.setattr(time, "time", lambda: value["expires_at"] + 1)
        return result
    monkeypatch.setattr(lab_effect, "write_record", change_at_prepared)
    with operator_session(path, expected_sha256=sha):
        result = invoke(value, op)
    assert result["status"] == "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED", result
    root = Path(value["output_root"]) / op
    assert not (root / "effect_applied.json").exists()
    assert not (root / "sandbox_state.json").exists()


def test_unknown_interrupted_attempt_is_not_regenerated(tmp_path):
    path, sha, value, op = make_contract(tmp_path)
    with operator_session(path, expected_sha256=sha) as session:
        session.reserve(op, 0, "c" * 64)
    with operator_session(path, expected_sha256=sha):
        result = invoke(value, op)
    assert result["status"] == "HOLD_INTERRUPTED_OPERATION_NO_RETRY"
    assert not SyntheticBackend.seen


def test_recovery_removes_only_the_exact_owned_state(tmp_path):
    state = {"answer": 42}
    prepared = {"state": state}
    lab_effect.write_record(tmp_path / "effect_prepared.json", prepared)
    lab_effect.write_record(tmp_path / "sandbox_state.json", state)
    recovered = lab_effect.recover_effect(tmp_path)
    assert recovered["restored_absence_observed"] and not recovered["reapplied"]
    assert lab_effect.recover_effect(tmp_path) == recovered
    (tmp_path / "sandbox_state.json").write_text('{"someone_else":true}')
    with pytest.raises(RuntimeError, match="COLLISION_PRESERVED"):
        lab_effect.recover_effect(tmp_path)
    assert (tmp_path / "sandbox_state.json").exists()


def test_nonconsuming_control_uses_same_diagnostic_but_has_no_effect(tmp_path):
    path, sha, value, op = make_contract(tmp_path, strategy="nonconsuming", consume=False)
    with operator_session(path, expected_sha256=sha):
        result = invoke(value, op)
    assert result["status"] == "CHECKED_NONCONSUMING"
    assert len(SyntheticBackend.seen) == 2 and "ARITHMETIC_EQUALITY" in SyntheticBackend.seen[1]
    assert not (Path(value["output_root"]) / op / "effect_prepared.json").exists()


def test_wall_budget_is_not_reset_by_resume(tmp_path):
    path, sha, value, op = make_contract(tmp_path)
    with operator_session(path, expected_sha256=sha) as first:
        started = first.started_at
    with operator_session(path, expected_sha256=sha) as second:
        assert second.started_at == started
        assert 0 < second.remaining_seconds() <= 5


def test_traversal_output_alias_is_rejected(tmp_path):
    path, sha, value, op = make_contract(tmp_path)
    child = tmp_path / "child"
    child.mkdir()
    value["output_root"] = str(child / ".." / "external_run")
    path.write_bytes(canonical_bytes(value))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="LAB_ROOT_NONCANONICAL"):
        LabSession(path, sha)


def _rewrite_record(root, name, edit):
    path = root / name
    value = json.loads(path.read_bytes())
    edit(value)
    path.write_bytes(canonical_bytes(value))
    result_path = root / "result.json"
    result = json.loads(result_path.read_bytes())
    result["files"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    result_path.write_bytes(canonical_bytes(result))


def test_detached_replay_rejects_rehashed_cap_violation_at_cap_predicate(tmp_path):
    SyntheticBackend.answers = [42]
    path, sha, value, op = make_contract(tmp_path)
    with operator_session(path, expected_sha256=sha):
        assert invoke(value, op)["status"] == "CHECKED_EFFECT_RESTORED"
    root = Path(value["output_root"]) / op
    _rewrite_record(root, "attempt_0_raw.json", lambda raw: raw.update(generated_token_ids=[1]*16+[2], output_tokens=17))
    with pytest.raises(RuntimeError, match="LAB_OUTPUT_CAP"):
        lane.verify_operation(root, expected_contract_sha256=sha)


def test_detached_replay_rejects_false_success_label(tmp_path):
    SyntheticBackend.answers = [41]
    path, sha, value, op = make_contract(tmp_path, strategy="direct", attempts=1, consume=False)
    with operator_session(path, expected_sha256=sha):
        assert invoke(value, op)["status"] == "HELD_TASK_PREDICATE"
    root = Path(value["output_root"]) / op
    result = lab_effect.read_record(root / "result.json")
    result["status"] = "CHECKED_NONCONSUMING"
    (root / "result.json").write_bytes(canonical_bytes(result))
    with pytest.raises(RuntimeError, match="LAB_REPLAY_FALSE_ACCEPTANCE"):
        lane.verify_operation(root, expected_contract_sha256=sha)


def test_effect_record_cannot_substitute_different_checked_answer(tmp_path):
    SyntheticBackend.answers = [42]
    path, sha, value, op = make_contract(tmp_path)
    with operator_session(path, expected_sha256=sha):
        assert invoke(value, op)["status"] == "CHECKED_EFFECT_RESTORED"
    root = Path(value["output_root"]) / op
    applied = lab_effect.read_record(root / "effect_applied.json")
    applied["observed_state"]["answer"] = 99
    altered = identity(applied["observed_state"])
    _rewrite_record(root, "effect_applied.json", lambda record: record.update(observed_state=applied["observed_state"], state_hash=altered))
    _rewrite_record(root, "effect_receipt.json", lambda record: record.update(state_hash=altered))
    with pytest.raises(RuntimeError, match="LAB_REPLAY_EFFECT"):
        lane.verify_operation(root, expected_contract_sha256=sha)


def test_terminal_held_effect_is_recovered_on_canonical_resume(tmp_path, monkeypatch):
    SyntheticBackend.answers = [42]
    path, sha, value, op = make_contract(tmp_path)
    restore = lab_effect._restore_owned_target
    failed = [False]
    def fail_once(root, prepared):
        if not failed[0]:
            failed[0] = True
            raise OSError("synthetic interrupted rollback")
        return restore(root, prepared)
    monkeypatch.setattr(lab_effect, "_restore_owned_target", fail_once)
    with operator_session(path, expected_sha256=sha):
        result = invoke(value, op)
    assert result["status"] == "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED"
    root = Path(value["output_root"]) / op
    assert (root / "sandbox_state.json").exists()
    with operator_session(path, expected_sha256=sha):
        resumed = invoke(value, op)
    assert resumed["status"] == "RECOVERED_HELD_OPERATION_NO_RETRY", resumed
    assert not (root / "sandbox_state.json").exists()
    assert len(SyntheticBackend.seen) == 1
    assert lane.verify_operation(root, expected_contract_sha256=sha)["original"]["status"] == "HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED"


def test_self_review_replay_cannot_shorten_the_declared_attempt_roster(tmp_path):
    SyntheticBackend.answers = [42]
    path, sha, value, op = make_contract(tmp_path, strategy="self_review", attempts=3, consume=False)
    with operator_session(path, expected_sha256=sha):
        assert invoke(value, op)["status"] == "CHECKED_NONCONSUMING"
    root = Path(value["output_root"]) / op
    result = lab_effect.read_record(root / "result.json")
    # Construct a detached tamper fixture, preserving the original evidence files.
    altered = tmp_path / "tampered" / op
    altered.mkdir(parents=True)
    (altered.parent / "operator_contract.json").write_bytes(path.read_bytes())
    keep = {name: sha for name, sha in result["files"].items() if name.startswith("attempt_0_")}
    for name in keep:
        (altered / name).write_bytes((root / name).read_bytes())
    result.update(files=keep, attempts=[0], model_calls=1, input_tokens=3, output_tokens=2)
    (altered / "result.json").write_bytes(canonical_bytes(result))
    with pytest.raises(RuntimeError, match="LAB_REPLAY_TRUNCATED_ROSTER"):
        lane.verify_operation(altered, expected_contract_sha256=sha)



def test_fixed_inference_worker_is_outside_runtime_and_exactly_pinned():
    from council.providers import local_qwen
    worker = local_qwen._verified_worker_path()
    source = Path(lane.__file__).resolve().parents[1]
    assert not worker.is_relative_to(source)
    assert hashlib.sha256(worker.read_bytes()).hexdigest() == local_qwen.WORKER_SHA256


@pytest.mark.parametrize("tamper", ["bytes", "symlink"])
def test_fixed_worker_tamper_is_rejected_before_process_launch(tmp_path, monkeypatch, tamper):
    from council.providers import local_qwen
    actual = local_qwen._verified_worker_path()
    fake_provider = tmp_path / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/local_qwen.py"
    worker = tmp_path / "KT_PROD_CLEANROOM/tools/operator/local_qwen_worker.py"
    worker.parent.mkdir(parents=True)
    if tamper == "bytes":
        worker.write_bytes(actual.read_bytes() + b"\n# changed\n")
    else:
        worker.symlink_to(actual)
    monkeypatch.setattr(local_qwen, "__file__", str(fake_provider))
    monkeypatch.setattr(local_qwen, "validate_backend", lambda value: None)
    launched = []
    monkeypatch.setattr(local_qwen.subprocess, "Popen", lambda *a, **kw: launched.append(True))
    with pytest.raises((RuntimeError, ValueError, OSError)):
        local_qwen.LocalQwenBackend(contract_path=tmp_path / "unused.json", contract_sha256="a" * 64,
                                   output_root=tmp_path, backend={}, timeout=1)
    assert launched == []
