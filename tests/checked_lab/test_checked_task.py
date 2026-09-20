from __future__ import annotations

import itertools
import json

import pytest

from schemas.checked_task import (
    CheckedTaskError, PROPOSAL_SCHEMA, TASK_SCHEMA, build_prompt, canonical_bytes,
    check_proposal, identity, parse_proposal, strict_json, validate_task,
)

NONCE = "a" * 32


def arithmetic():
    return {"schema_id": TASK_SCHEMA, "task_id": "addition", "kind": "integer_arithmetic",
            "problem": {"left": 17, "operation": "add", "right": 25}}


def plan():
    return {"schema_id": TASK_SCHEMA, "task_id": "plan", "kind": "constrained_plan", "problem": {
        "projects": [{"id": "A", "cost": 2, "time": 2, "value": 2},
                     {"id": "B", "cost": 3, "time": 1, "value": 7},
                     {"id": "C", "cost": 1, "time": 3, "value": 4}],
        "budget": 5, "time_budget": 5, "max_projects": 2, "mandatory": ["A"],
        "requires": [["B", "A"]], "excludes": [["B", "C"]], "exactly_one": [["B", "C"]]}}


def proposal(task, answer):
    return {"schema_id": PROPOSAL_SCHEMA, "task_hash": identity(task), "nonce": NONCE, "answer": answer}


def checked(task, answer):
    return check_proposal(task, proposal(task, answer), nonce=NONCE)


def test_authentic_shape_does_not_make_wrong_answer_correct():
    task = arithmetic()
    wrong = parse_proposal(canonical_bytes(proposal(task, 41)), task, nonce=NONCE)
    result = check_proposal(task, wrong, nonce=NONCE)
    assert result["diagnostics"] == ["ARITHMETIC_EQUALITY"]
    assert result["satisfied"] is False
    assert checked(task, 42)["satisfied"] is True
    assert result["execution_permission"] == "NOT_GRANTED"
    assert result["metrics"] == {}
    assert set(result) == {"schema_id", "task_hash", "proposal_hash", "scope", "satisfied",
                           "diagnostics", "metrics", "optimality", "execution_permission"}


@pytest.mark.parametrize("operation,left,right,expected", [
    ("add", 10**12, 10**12, 2 * 10**12), ("subtract", -10**12, 10**12, -2 * 10**12),
    ("multiply", 10**12, -10**12, -(10**24)), ("multiply", 0, -8, 0),
])
def test_integer_boundaries_are_exact(operation, left, right, expected):
    task = arithmetic()
    task["problem"] = {"operation": operation, "left": left, "right": right}
    assert checked(task, expected)["satisfied"]
    assert not checked(task, expected + 1)["satisfied"]


@pytest.mark.parametrize("raw", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}',
                                 '{"x":1e999}', '{} {}', '[1,', b'\xff', 'x' * 32769])
def test_transport_rejects_ambiguous_or_unbounded_json(raw):
    with pytest.raises(CheckedTaskError):
        strict_json(raw)


@pytest.mark.parametrize("value", [True, False, 42.0, "42", None, [], {}])
def test_typed_arithmetic_answer_not_coerced(value):
    with pytest.raises(CheckedTaskError):
        checked(arithmetic(), value)


@pytest.mark.parametrize("field,value", [("task_hash", "0" * 64), ("nonce", "b" * 32),
                                        ("schema_id", "other"), ("extra", "PASS")])
def test_proposal_is_bound_to_one_exact_task_and_attempt(field, value):
    task = arithmetic()
    candidate = proposal(task, 42)
    candidate[field] = value
    with pytest.raises(CheckedTaskError):
        parse_proposal(canonical_bytes(candidate), task, nonce=NONCE)


def test_feasible_suboptimal_plan_does_not_claim_optimality():
    task = plan()
    optimal = checked(task, ["A", "B"])
    suboptimal = checked(task, ["A", "C"])
    assert optimal["satisfied"] and suboptimal["satisfied"]
    assert optimal["metrics"]["value"] == 9
    assert suboptimal["metrics"]["value"] == 6
    assert suboptimal["scope"] == "DECLARED_PLAN_FEASIBILITY_ONLY"
    assert suboptimal["optimality"] == "NOT_CHECKED"
    assert suboptimal["execution_permission"] == "NOT_GRANTED"


@pytest.mark.parametrize("update,answer,diagnostic", [
    ({"budget": 4}, ["A", "B"], "BUDGET"),
    ({"time_budget": 2}, ["A", "B"], "TIME_BUDGET"),
    ({"max_projects": 1}, ["A", "B"], "MAX_PROJECTS"),
    ({}, ["B"], "MANDATORY"), ({}, ["B"], "REQUIRES"),
    ({}, ["A", "B", "C"], "EXCLUDES"), ({}, ["A"], "EXACTLY_ONE"),
])
def test_each_declared_constraint_has_behavioral_denial(update, answer, diagnostic):
    task = plan()
    task["problem"].update(update)
    result = checked(task, answer)
    assert not result["satisfied"]
    assert diagnostic in result["diagnostics"]


def test_all_subsets_agree_with_independently_stated_public_problem():
    # This independent predicate does not call producer helpers or its set-based implementation.
    for flags in itertools.product((0, 1), repeat=3):
        a, b, c = flags
        expected = (2*a+3*b+c <= 5 and 2*a+b+3*c <= 5 and a+b+c <= 2
                    and a == 1 and b <= a and b+c <= 1 and b+c == 1)
        answer = [name for name, flag in zip("ABC", flags) if flag]
        assert checked(plan(), answer)["satisfied"] is bool(expected)


@pytest.mark.parametrize("answer", [["A", "A"], ["A", "UNKNOWN"], [True], "A,B", None])
def test_plan_selection_rejects_aliases_and_unknowns_before_set_conversion(answer):
    with pytest.raises(CheckedTaskError):
        checked(plan(), answer)


@pytest.mark.parametrize("field,value", [("budget", True), ("time_budget", -1), ("max_projects", 4),
                                        ("requires", [["A", "Z"]]), ("excludes", [["A", "A"]]),
                                        ("exactly_one", [[]]), ("mandatory", ["A", "A"])])
def test_problem_schema_fails_closed(field, value):
    task = plan()
    task["problem"][field] = value
    with pytest.raises(CheckedTaskError):
        validate_task(task)


def test_task_detached_after_validation_and_prompt_contains_no_solution():
    task = plan()
    admitted = validate_task(task)
    task["problem"]["projects"][0]["value"] = 100
    assert admitted["problem"]["projects"][0]["value"] == 2
    prompt = build_prompt(admitted, nonce=NONCE, history=[])
    assert "optimal_plan" not in prompt and "expected_answer" not in prompt
    assert identity(admitted) in prompt
    with pytest.raises(CheckedTaskError):
        build_prompt(admitted, nonce=NONCE, history=[{}, {}, {}])


def test_symmetric_relation_alias_is_rejected_but_requires_is_directed():
    task = plan()
    task["problem"]["excludes"] = [["B", "C"], ["C", "B"]]
    with pytest.raises(CheckedTaskError, match="DUPLICATE_RELATION"):
        validate_task(task)
    task = plan()
    task["problem"]["requires"] = [["A", "B"], ["B", "A"]]
    assert validate_task(task) == task


def test_unsupported_truth_returns_no_acceptance():
    task = arithmetic()
    task["kind"] = "arbitrary_claim"
    with pytest.raises(CheckedTaskError, match="UNSUPPORTED_TASK_KIND"):
        validate_task(task)


def test_history_reconstructs_feedback_and_does_not_accept_injected_oracles():
    task = plan()
    with pytest.raises(CheckedTaskError, match="HISTORY_FIELDS"):
        build_prompt(task, nonce=NONCE, history=[{"expected_answer": ["A", "B"]}])
    history = [{"raw": canonical_bytes(proposal(task, ["B"])).decode(),
                "nonce": NONCE, "feedback_mode": "kt_diagnostic"}]
    prompt = build_prompt(task, nonce="b" * 32, history=history)
    body = strict_json(prompt.split("\n", 1)[1])
    assert body["prior_attempts"][0]["feedback"] == ["MANDATORY", "REQUIRES"]
    history[0]["raw"] = '{"optimal_plan":["A","B"]}'
    prompt = build_prompt(task, nonce="b" * 32, history=history)
    assert "optimal_plan" not in prompt
    task = arithmetic()
    task["problem"]["operation"] = "eval"
    with pytest.raises(CheckedTaskError, match="UNSUPPORTED_ARITHMETIC"):
        validate_task(task)


@pytest.mark.parametrize("task,answer_type", [(arithmetic(), "JSON integer, not quoted and not null"),
                                             (plan(), "JSON array of selected project ID strings")])
def test_prompt_states_complete_task_specific_response_contract(task, answer_type):
    prompt = build_prompt(task, nonce=NONCE, history=[])
    instruction, encoded = prompt.split("\n", 1)
    body = strict_json(encoded)
    required = body["required_output"]
    assert set(required) == {"schema_id", "task_hash", "nonce", "answer"}
    assert required["schema_id"] == PROPOSAL_SCHEMA
    assert required["task_hash"] == identity(task) and required["nonce"] == NONCE
    assert required["answer"] == answer_type
    assert "all four keys: schema_id, task_hash, nonce, answer" in instruction
    assert "Copy schema_id, task_hash and nonce exactly" in instruction
    # The model still has to solve the task. No computed answer or optimum is supplied.
    assert set(body) == {"task", "prior_attempts", "required_output"}
    assert body["task"] == task and body["prior_attempts"] == []


@pytest.mark.parametrize("missing", [("schema_id", "task_hash"), ("task_hash",)])
def test_observed_missing_metadata_remains_denied_after_prompt_repair(missing):
    task = arithmetic()
    candidate = proposal(task, 42)
    for field in missing:
        candidate.pop(field)
    with pytest.raises(CheckedTaskError, match="PROPOSAL_FIELDS"):
        parse_proposal(canonical_bytes(candidate), task, nonce=NONCE)
