"""Public, bounded task predicates for the laboratory semantic successor.

This checker establishes integer arithmetic equality or declared plan feasibility.
It does not establish optimality, arbitrary subject truth, or execution permission.
Planning predicates preserve the qualified external scorer's constraint semantics;
strict input validation precedes set conversion and no optimal plan is computed.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any


TASK_SCHEMA = "kt.lab.checked_task.v1"
PROPOSAL_SCHEMA = "kt.lab.task_proposal.v1"
MAX_BYTES = 32 * 1024
MAX_INTEGER = 10**12
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")


class CheckedTaskError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def identity(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json(raw: str | bytes, *, max_bytes: int = MAX_BYTES) -> Any:
    if not isinstance(raw, (str, bytes)) or len(raw.encode("utf-8") if isinstance(raw, str) else raw) > max_bytes:
        raise CheckedTaskError("JSON_SIZE_OR_TYPE")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise CheckedTaskError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise CheckedTaskError("NONFINITE_JSON")

    def floating(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise CheckedTaskError("NONFINITE_JSON")
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=floating)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, CheckedTaskError):
            raise
        raise CheckedTaskError("INVALID_JSON") from exc


def _keys(value: Any, keys: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != keys:
        raise CheckedTaskError(label + "_FIELDS")


def _integer(value: Any, label: str, *, low: int = 0, high: int = MAX_INTEGER) -> int:
    if type(value) is not int or not low <= value <= high:
        raise CheckedTaskError(label + "_INTEGER_RANGE")
    return value


def _ids(value: Any, allowed: set[str], label: str, *, nonempty: bool = False) -> list[str]:
    if (type(value) is not list or len(value) > len(allowed)
            or (nonempty and not value)
            or any(type(item) is not str or item not in allowed for item in value)
            or len(value) != len(set(value))):
        raise CheckedTaskError(label + "_IDS")
    return value


def validate_task(task: Any) -> dict[str, Any]:
    _keys(task, {"schema_id", "task_id", "kind", "problem"}, "TASK")
    if task["schema_id"] != TASK_SCHEMA:
        raise CheckedTaskError("TASK_SCHEMA")
    if type(task["task_id"]) is not str or not _ID.fullmatch(task["task_id"]):
        raise CheckedTaskError("TASK_ID")
    problem = task["problem"]
    if task["kind"] == "integer_arithmetic":
        _keys(problem, {"left", "operation", "right"}, "ARITHMETIC")
        _integer(problem["left"], "LEFT", low=-MAX_INTEGER)
        _integer(problem["right"], "RIGHT", low=-MAX_INTEGER)
        if problem["operation"] not in ("add", "subtract", "multiply"):
            raise CheckedTaskError("UNSUPPORTED_ARITHMETIC")
    elif task["kind"] == "constrained_plan":
        _keys(problem, {"projects", "budget", "time_budget", "max_projects", "mandatory",
                        "requires", "excludes", "exactly_one"}, "PLAN")
        projects = problem["projects"]
        if type(projects) is not list or not 1 <= len(projects) <= 16:
            raise CheckedTaskError("PROJECT_COUNT")
        ids: set[str] = set()
        for project in projects:
            _keys(project, {"id", "cost", "time", "value"}, "PROJECT")
            key = project["id"]
            if type(key) is not str or not _ID.fullmatch(key) or key in ids:
                raise CheckedTaskError("PROJECT_ID")
            ids.add(key)
            for field in ("cost", "time", "value"):
                _integer(project[field], "PROJECT_" + field.upper())
        _integer(problem["budget"], "BUDGET")
        _integer(problem["time_budget"], "TIME_BUDGET")
        _integer(problem["max_projects"], "MAX_PROJECTS", high=len(ids))
        _ids(problem["mandatory"], ids, "MANDATORY")
        for relation in ("requires", "excludes", "exactly_one"):
            groups = problem[relation]
            if type(groups) is not list or len(groups) > 64:
                raise CheckedTaskError("RELATION_COUNT")
            seen: set[tuple[str, ...]] = set()
            for group in groups:
                _ids(group, ids, relation.upper(), nonempty=True)
                if relation != "exactly_one" and len(group) != 2:
                    raise CheckedTaskError("RELATION_PAIR")
                key = tuple(group if relation == "requires" else sorted(group))
                if key in seen:
                    raise CheckedTaskError("DUPLICATE_RELATION")
                seen.add(key)
    else:
        raise CheckedTaskError("UNSUPPORTED_TASK_KIND")
    if len(canonical_bytes(task)) > MAX_BYTES:
        raise CheckedTaskError("TASK_SIZE")
    # Return a detached value, not an alias that the caller can mutate after admission.
    return strict_json(canonical_bytes(task))


def parse_proposal(raw: str | bytes, task: dict[str, Any], *, nonce: str) -> dict[str, Any]:
    task = validate_task(task)
    if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise CheckedTaskError("NONCE")
    value = strict_json(raw)
    _keys(value, {"schema_id", "task_hash", "nonce", "answer"}, "PROPOSAL")
    if value["schema_id"] != PROPOSAL_SCHEMA:
        raise CheckedTaskError("PROPOSAL_SCHEMA")
    if value["task_hash"] != identity(task) or value["nonce"] != nonce:
        raise CheckedTaskError("PROPOSAL_BINDING")
    if task["kind"] == "integer_arithmetic":
        _integer(value["answer"], "ANSWER", low=-(MAX_INTEGER**2), high=MAX_INTEGER**2)
    else:
        _ids(value["answer"], {p["id"] for p in task["problem"]["projects"]}, "ANSWER")
    return value


def check_proposal(task: dict[str, Any], proposal: dict[str, Any], *, nonce: str) -> dict[str, Any]:
    task = validate_task(task)
    proposal = parse_proposal(canonical_bytes(proposal), task, nonce=nonce)
    problem, answer = task["problem"], proposal["answer"]
    diagnostics: list[str] = []
    metrics: dict[str, int] = {}
    if task["kind"] == "integer_arithmetic":
        left, right = problem["left"], problem["right"]
        expected = {"add": lambda: left + right, "subtract": lambda: left - right,
                    "multiply": lambda: left * right}[problem["operation"]]()
        if answer != expected:
            diagnostics.append("ARITHMETIC_EQUALITY")
        scope = "DECLARED_INTEGER_OPERATION_EQUALITY"
    else:
        selected = set(answer)
        projects = {p["id"]: p for p in problem["projects"]}
        metrics = {key: sum(projects[p][key] for p in selected) for key in ("cost", "time", "value")}
        if metrics["cost"] > problem["budget"]:
            diagnostics.append("BUDGET")
        if metrics["time"] > problem["time_budget"]:
            diagnostics.append("TIME_BUDGET")
        if len(selected) > problem["max_projects"]:
            diagnostics.append("MAX_PROJECTS")
        if not set(problem["mandatory"]) <= selected:
            diagnostics.append("MANDATORY")
        if any(a in selected and b not in selected for a, b in problem["requires"]):
            diagnostics.append("REQUIRES")
        if any(a in selected and b in selected for a, b in problem["excludes"]):
            diagnostics.append("EXCLUDES")
        if any(len(selected.intersection(group)) != 1 for group in problem["exactly_one"]):
            diagnostics.append("EXACTLY_ONE")
        scope = "DECLARED_PLAN_FEASIBILITY_ONLY"
    return {"schema_id": "kt.lab.task_check.v1", "task_hash": identity(task),
            "proposal_hash": identity(proposal), "scope": scope,
            "satisfied": not diagnostics, "diagnostics": diagnostics, "metrics": metrics,
            "optimality": "NOT_CHECKED", "execution_permission": "NOT_GRANTED"}


def build_prompt(task: dict[str, Any], *, nonce: str, history: list[dict[str, Any]]) -> str:
    task = validate_task(task)
    if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise CheckedTaskError("NONCE")
    if type(history) is not list or len(history) > 2:
        raise CheckedTaskError("REVISION_LIMIT")
    sanitized = []
    for entry in history:
        _keys(entry, {"raw", "nonce", "feedback_mode"}, "HISTORY")
        if entry["feedback_mode"] not in ("self_review", "kt_diagnostic", "sham", "nonconsuming"):
            raise CheckedTaskError("HISTORY_MODE")
        try:
            previous = parse_proposal(entry["raw"], task, nonce=entry["nonce"])
        except CheckedTaskError:
            # Preserve raw attempts in the journal, but do not relay unknown fields as feedback.
            previous = None
        feedback = "Review your prior answer independently against the public task."
        if entry["feedback_mode"] in ("kt_diagnostic", "nonconsuming"):
            feedback = (check_proposal(task, previous, nonce=entry["nonce"])["diagnostics"]
                        if previous is not None else ["MALFORMED_OR_UNBOUND_PROPOSAL"])
        elif entry["feedback_mode"] == "sham":
            feedback = "A diagnostic stage ran. No task-specific diagnostic is supplied."
        sanitized.append({"previous_proposal": previous, "feedback": feedback})
    body = {"task": task, "prior_attempts": sanitized,
            "required_output": {"schema_id": PROPOSAL_SCHEMA, "task_hash": identity(task),
                                "nonce": nonce, "answer": "integer or array of selected project IDs"}}
    raw = canonical_bytes(body)
    if len(raw) > MAX_BYTES:
        raise CheckedTaskError("PROMPT_SIZE")
    return ("Solve the public task. Return exactly one JSON object matching required_output. "
            "For constrained_plan maximize value subject to every declared constraint. "
            "No commentary or additional keys.\n" + raw.decode("utf-8"))
