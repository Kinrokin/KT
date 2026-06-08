from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Literal


RescueStatus = Literal[
    "RESCUE_CANDIDATE_EMITTED",
    "ANSWER_SURFACE_CANDIDATE_AUDIT_ONLY",
    "ABSTAIN_NO_DETERMINISTIC_RULE",
    "ABSTAIN_AMBIGUOUS_MULTIPLE_CANDIDATES",
    "ABSTAIN_UNSAFE_EXPRESSION",
    "ABSTAIN_NO_FULLMATCH",
    "RULE_ERROR_BLOCKED",
]


@dataclass(frozen=True)
class RescueCandidate:
    status: RescueStatus
    candidate: str | None
    candidate_source: str
    rule_id: str
    rule_confidence: str
    source_surface: str | None
    answer_surface_audit_only: bool
    notes: tuple[str, ...]


class SafeArithmeticEvaluator:
    """AST-whitelisted arithmetic evaluator for explicit numeric expressions only."""

    _allowed_binops = (ast.Add, ast.Sub, ast.Mult, ast.Div)
    _allowed_unaryops = (ast.UAdd, ast.USub)

    def evaluate(self, expression: str) -> str | None:
        normalized = self._normalize(expression)
        if not normalized:
            return None
        if re.search(r"[A-Za-z_]", normalized):
            return None
        if "**" in normalized or "^" in normalized:
            return None
        if re.search(r"[^0-9+\-*/().\s]", normalized):
            return None
        try:
            tree = ast.parse(normalized, mode="eval")
            value = self._eval_node(tree.body)
        except (SyntaxError, ValueError, ZeroDivisionError, InvalidOperation, OverflowError):
            return None
        return self._format(value)

    def _normalize(self, expression: str) -> str:
        text = expression.strip()
        text = text.replace(",", "")
        text = text.replace("×", "*").replace("x", "*").replace("X", "*").replace("÷", "/")
        text = text.replace("$", "")
        return text

    def _eval_node(self, node: ast.AST) -> Fraction:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
                raise ValueError("unsupported constant")
            return self._number_to_fraction(str(node.value))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, self._allowed_unaryops):
            value = self._eval_node(node.operand)
            return value if isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp) and isinstance(node.op, self._allowed_binops):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if right == 0:
                raise ZeroDivisionError("division by zero")
            return left / right
        raise ValueError("unsafe node")

    def _number_to_fraction(self, value: str) -> Fraction:
        return Fraction(Decimal(value))

    def _format(self, value: Fraction) -> str:
        if value.denominator == 1:
            return str(value.numerator)
        return f"{value.numerator}/{value.denominator}"


class DeterministicRescueV4:
    """Offline-only deterministic candidate extractor for frozen GSM8K raw outputs."""

    explicit_equation_pattern = re.compile(
        r"^\s*(?:\d+[\).]\s*)?(\(?\s*-?\$?\d[\d,]*(?:\.\d+)?\s*\)?(?:\s*[+\-*/×÷]\s*\(?\s*-?\$?\d[\d,]*(?:\.\d+)?\s*\)?)+)\s*=\s*(-?\$?\d[\d,]*(?:\.\d+)?|-?\d+/\d+)\s*\.?\s*$"
    )
    final_assignment_pattern = re.compile(
        r"^\s*(?:final\s+answer|answer|the\s+answer\s+is)\s*[:=]?\s*(-?\$?\d[\d,]*(?:\.\d+)?|-?\d+/\d+)\s*\.?\s*$",
        re.IGNORECASE,
    )
    trivial_expression_pattern = re.compile(
        r"^\s*(?:what\s+is\s+)?(-?\d+(?:\.\d+)?\s*[+\-*/×÷]\s*-?\d+(?:\.\d+)?)\s*\??\s*$",
        re.IGNORECASE,
    )
    trivial_phrase_pattern = re.compile(
        r"^\s*(?:the\s+)?(?P<op>sum|total|difference)\s+(?:of|between)\s+(?P<a>-?\d+(?:\.\d+)?)\s+(?:and)\s+(?P<b>-?\d+(?:\.\d+)?)\s*\??\s*$",
        re.IGNORECASE,
    )
    subtract_phrase_pattern = re.compile(
        r"^\s*subtract\s+(?P<b>-?\d+(?:\.\d+)?)\s+from\s+(?P<a>-?\d+(?:\.\d+)?)\s*\??\s*$",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self.evaluator = SafeArithmeticEvaluator()

    def rescue_from_output(self, raw_output: str) -> RescueCandidate:
        candidates: list[RescueCandidate] = []
        for raw_line in raw_output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if self._unsafe_context(line):
                continue
            equation = self._explicit_equation_candidate(line)
            if equation is not None:
                candidates.append(equation)
            final_assignment = self._final_assignment_candidate(line)
            if final_assignment is not None:
                candidates.append(final_assignment)
        return self._select(candidates)

    def rescue_from_problem_text(self, problem_text: str) -> RescueCandidate:
        text = problem_text.strip().rstrip(".")
        expression = self.trivial_expression_pattern.fullmatch(text)
        if expression:
            value = self.evaluator.evaluate(expression.group(1))
            if value is None:
                return self._abstain("ABSTAIN_UNSAFE_EXPRESSION", "PROBLEM_TEXT_FULLMATCH_TRIVIAL_ARITHMETIC")
            return RescueCandidate(
                status="RESCUE_CANDIDATE_EMITTED",
                candidate=value,
                candidate_source="PROBLEM_TEXT_FULLMATCH_TRIVIAL_ARITHMETIC",
                rule_id="PROBLEM_TEXT_FULLMATCH_TRIVIAL_EXPRESSION",
                rule_confidence="HIGH",
                source_surface=text,
                answer_surface_audit_only=False,
                notes=("fullmatch_trivial_expression_only",),
            )
        phrase = self.trivial_phrase_pattern.fullmatch(text)
        if phrase:
            a = phrase.group("a")
            b = phrase.group("b")
            op = "+" if phrase.group("op").lower() in {"sum", "total"} else "-"
            value = self.evaluator.evaluate(f"{a}{op}{b}")
            return RescueCandidate(
                status="RESCUE_CANDIDATE_EMITTED" if value is not None else "ABSTAIN_UNSAFE_EXPRESSION",
                candidate=value,
                candidate_source="PROBLEM_TEXT_FULLMATCH_TRIVIAL_ARITHMETIC",
                rule_id="PROBLEM_TEXT_FULLMATCH_TRIVIAL_PHRASE",
                rule_confidence="HIGH",
                source_surface=text,
                answer_surface_audit_only=False,
                notes=("fullmatch_trivial_phrase_only",),
            )
        subtract = self.subtract_phrase_pattern.fullmatch(text)
        if subtract:
            value = self.evaluator.evaluate(f"{subtract.group('a')}-{subtract.group('b')}")
            return RescueCandidate(
                status="RESCUE_CANDIDATE_EMITTED" if value is not None else "ABSTAIN_UNSAFE_EXPRESSION",
                candidate=value,
                candidate_source="PROBLEM_TEXT_FULLMATCH_TRIVIAL_ARITHMETIC",
                rule_id="PROBLEM_TEXT_FULLMATCH_SUBTRACT_PHRASE",
                rule_confidence="HIGH",
                source_surface=text,
                answer_surface_audit_only=False,
                notes=("fullmatch_subtract_phrase_only",),
            )
        return self._abstain("ABSTAIN_NO_FULLMATCH", "PROBLEM_TEXT_FULLMATCH_TRIVIAL_ARITHMETIC")

    def _explicit_equation_candidate(self, line: str) -> RescueCandidate | None:
        match = self.explicit_equation_pattern.fullmatch(line)
        if not match:
            return None
        left = match.group(1)
        right = match.group(2).replace("$", "").replace(",", "")
        left_value = self.evaluator.evaluate(left)
        right_value = self.evaluator.evaluate(right)
        if left_value is None or right_value is None:
            return self._abstain("ABSTAIN_UNSAFE_EXPRESSION", "MODEL_OUTPUT_EXPLICIT_ARITHMETIC_LINE")
        if left_value != right_value:
            return self._abstain("ABSTAIN_UNSAFE_EXPRESSION", "MODEL_OUTPUT_EXPLICIT_ARITHMETIC_LINE")
        return RescueCandidate(
            status="RESCUE_CANDIDATE_EMITTED",
            candidate=right_value,
            candidate_source="MODEL_OUTPUT_EXPLICIT_ARITHMETIC_LINE",
            rule_id="MODEL_OUTPUT_EXPLICIT_EQUATION_VERIFIED",
            rule_confidence="HIGH",
            source_surface=line,
            answer_surface_audit_only=False,
            notes=("explicit_equation_verified",),
        )

    def _final_assignment_candidate(self, line: str) -> RescueCandidate | None:
        if self._unsafe_context(line):
            return None
        match = self.final_assignment_pattern.fullmatch(line)
        if not match:
            return None
        value = self.evaluator.evaluate(match.group(1).replace("$", "").replace(",", ""))
        if value is None:
            return self._abstain("ABSTAIN_UNSAFE_EXPRESSION", "MODEL_OUTPUT_EXPLICIT_FINAL_ASSIGNMENT")
        return RescueCandidate(
            status="ANSWER_SURFACE_CANDIDATE_AUDIT_ONLY",
            candidate=value,
            candidate_source="MODEL_OUTPUT_EXPLICIT_FINAL_ASSIGNMENT",
            rule_id="MODEL_OUTPUT_EXPLICIT_FINAL_ASSIGNMENT_AUDIT_ONLY",
            rule_confidence="AUDIT_ONLY",
            source_surface=line,
            answer_surface_audit_only=True,
            notes=("answer_surface_not_math_rescue",),
        )

    def _select(self, candidates: list[RescueCandidate]) -> RescueCandidate:
        rescue = [candidate for candidate in candidates if candidate.status == "RESCUE_CANDIDATE_EMITTED"]
        audit = [candidate for candidate in candidates if candidate.status == "ANSWER_SURFACE_CANDIDATE_AUDIT_ONLY"]
        unique_rescue_values = {candidate.candidate for candidate in rescue}
        if len(unique_rescue_values) > 1:
            return self._abstain("ABSTAIN_AMBIGUOUS_MULTIPLE_CANDIDATES", "MULTIPLE_EXPLICIT_CANDIDATES")
        if rescue:
            return rescue[0]
        unique_audit_values = {candidate.candidate for candidate in audit}
        if len(unique_audit_values) > 1:
            return self._abstain("ABSTAIN_AMBIGUOUS_MULTIPLE_CANDIDATES", "MULTIPLE_AUDIT_CANDIDATES")
        if audit:
            return audit[0]
        return self._abstain("ABSTAIN_NO_DETERMINISTIC_RULE", "MODEL_OUTPUT")

    def _abstain(self, status: RescueStatus, source: str) -> RescueCandidate:
        return RescueCandidate(
            status=status,
            candidate=None,
            candidate_source=source,
            rule_id=status,
            rule_confidence="NONE",
            source_surface=None,
            answer_surface_audit_only=False,
            notes=(status.lower(),),
        )

    def _unsafe_context(self, line: str) -> bool:
        lowered = line.lower()
        return any(marker in lowered for marker in (" not ", "however", " but ", "if ", " were ", "first computed"))
