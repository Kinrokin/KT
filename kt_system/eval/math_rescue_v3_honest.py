from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, DivisionByZero, InvalidOperation
from typing import Any

FAIL_OBVIOUS_GARBAGE = "FAIL_OBVIOUS_GARBAGE"
ABSTAIN_KEEP_ORIGINAL = "ABSTAIN_KEEP_ORIGINAL"
RESCUE_APPLIED = "RESCUE_APPLIED"
RESCUE_UNSUPPORTED = "RESCUE_UNSUPPORTED"

_NUM = r"([-+]?\d+(?:\.\d+)?)"
_PATTERNS = [
    (re.compile(rf"{_NUM}\s*\+\s*{_NUM}", re.IGNORECASE), "add"),
    (re.compile(rf"{_NUM}\s*-\s*{_NUM}", re.IGNORECASE), "subtract_left"),
    (re.compile(rf"{_NUM}\s*\*\s*{_NUM}", re.IGNORECASE), "multiply"),
    (re.compile(rf"{_NUM}\s*/\s*{_NUM}", re.IGNORECASE), "divide"),
    (re.compile(rf"total\s+of\s+{_NUM}\s+and\s+{_NUM}", re.IGNORECASE), "add"),
    (re.compile(rf"sum\s+of\s+{_NUM}\s+and\s+{_NUM}", re.IGNORECASE), "add"),
    (re.compile(rf"difference\s+between\s+{_NUM}\s+and\s+{_NUM}", re.IGNORECASE), "absolute_difference"),
    (re.compile(rf"subtract\s+{_NUM}\s+from\s+{_NUM}", re.IGNORECASE), "subtract_second_minus_first"),
]


@dataclass(frozen=True)
class RescueResult:
    status: str
    rescue_answer: str | None
    reason: str
    rescue_attempted: bool
    expected_answer_used: bool = False
    model_generation_invoked: bool = False
    first_pass_mutated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": "kt.v17_7_4.math_rescue_v3_honest_result.v1",
            "status": self.status,
            "rescue_answer": self.rescue_answer,
            "reason": self.reason,
            "rescue_attempted": self.rescue_attempted,
            "expected_answer_used": self.expected_answer_used,
            "model_generation_invoked": self.model_generation_invoked,
            "first_pass_mutated": self.first_pass_mutated,
        }


def _normalize_problem(problem_text: str) -> str:
    text = " ".join(str(problem_text or "").strip().split())
    return re.sub(r"[?.!]\s*$", "", text)


def _fmt(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text == "-0" else text


def _compute(op: str, left: str, right: str) -> str | None:
    try:
        a = Decimal(left)
        b = Decimal(right)
        if op == "add":
            return _fmt(a + b)
        if op == "subtract_left":
            return _fmt(a - b)
        if op == "multiply":
            return _fmt(a * b)
        if op == "divide":
            if b == 0:
                return None
            return _fmt(a / b)
        if op == "absolute_difference":
            return _fmt(abs(a - b))
        if op == "subtract_second_minus_first":
            return _fmt(b - a)
    except (InvalidOperation, DivisionByZero):
        return None
    return None


def rescue_trivial_arithmetic(
    problem_text: str,
    verifier_status: str,
    verifier_reason: str | None = None,
) -> dict[str, Any]:
    if verifier_status != FAIL_OBVIOUS_GARBAGE:
        return RescueResult(
            ABSTAIN_KEEP_ORIGINAL,
            None,
            "RESCUE_NOT_TRIGGERED_UNLESS_FAIL_OBVIOUS_GARBAGE",
            False,
        ).to_dict()

    normalized = _normalize_problem(problem_text)
    for pattern, op in _PATTERNS:
        match = pattern.fullmatch(normalized)
        if not match:
            continue
        answer = _compute(op, match.group(1), match.group(2))
        if answer is None:
            return RescueResult(RESCUE_UNSUPPORTED, None, "TRIVIAL_PATTERN_UNSUPPORTED", True).to_dict()
        return RescueResult(RESCUE_APPLIED, answer, f"FULLMATCH_{op.upper()}", True).to_dict()

    return RescueResult(ABSTAIN_KEEP_ORIGINAL, None, "NO_FULLMATCH_WHITELIST_PATTERN", True).to_dict()
