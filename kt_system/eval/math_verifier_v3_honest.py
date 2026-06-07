from __future__ import annotations

import math
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any


ABSTAIN_UNVERIFIED_ACCEPT = "ABSTAIN_UNVERIFIED_ACCEPT"
FAIL_OBVIOUS_GARBAGE = "FAIL_OBVIOUS_GARBAGE"
UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"

FAIL_REASONS = {
    "NONFINITE_NUMBER",
    "MALFORMED_NUMERIC_SURFACE",
    "NUMERIC_REQUIRED_BUT_NO_SURFACE",
    "BOUND_DOMAIN_IMPOSSIBLE",
}

_FINAL_SURFACE_RE = re.compile(
    r"(?:final\s+(?:answer|numeric\s+answer)\s*:|final\s+(?:answer|numeric\s+answer)|answer\s+is|answer\s*:|final\s*:)\s*([^\s,;]+)",
    re.IGNORECASE,
)
_NUMBER_RE = re.compile(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?")
_NONFINITE_RE = re.compile(r"[-+]?(?:nan|inf|infinity)", re.IGNORECASE)
_MALFORMED_NUMERIC_RE = re.compile(r"[-+]?(?:\d+\.\.\d+|\d+\.\d+\.|\d+\.\.|(?:\d+,){2,}\d*)")


@dataclass(frozen=True)
class VerifierResult:
    status: str
    reason: str
    candidate_number: str | None
    expected_answer_used: bool = False
    model_generation_invoked: bool = False
    first_pass_mutated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": "kt.v17_7_4.math_verifier_v3_honest_result.v1",
            "status": self.status,
            "reason": self.reason,
            "candidate_number": self.candidate_number,
            "expected_answer_used": self.expected_answer_used,
            "model_generation_invoked": self.model_generation_invoked,
            "first_pass_mutated": self.first_pass_mutated,
        }


def _manifest_bool(row_manifest: dict[str, Any] | None, *keys: str) -> bool:
    manifest = row_manifest or {}
    return any(manifest.get(key) is True for key in keys)


def _manifest_number(row_manifest: dict[str, Any] | None, key: str) -> Decimal | None:
    manifest = row_manifest or {}
    if key not in manifest:
        return None
    try:
        return Decimal(str(manifest[key]))
    except (InvalidOperation, ValueError):
        return None


def _normalize_number(surface: str) -> str | None:
    cleaned = str(surface or "").strip().replace(",", "")
    if not cleaned:
        return None
    try:
        value = Decimal(cleaned)
    except (InvalidOperation, ValueError):
        return None
    # Decimal.is_finite keeps very large finite answers from being mislabeled
    # as garbage merely because they cannot be represented as a Python float.
    if not value.is_finite():
        return None
    normalized = format(value.normalize(), "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    if normalized == "-0":
        normalized = "0"
    return normalized


def _explicit_final_surface(raw_output: str) -> str | None:
    matches = _FINAL_SURFACE_RE.findall(str(raw_output or ""))
    return matches[-1] if matches else None


def _candidate_surface(raw_output: str) -> str | None:
    explicit = _explicit_final_surface(raw_output)
    if explicit is not None and (
        _NUMBER_RE.fullmatch(explicit.strip())
        or _NONFINITE_RE.search(explicit.strip())
        or _MALFORMED_NUMERIC_RE.fullmatch(explicit.strip())
    ):
        return explicit
    numbers = _NUMBER_RE.findall(str(raw_output or ""))
    return numbers[-1] if numbers else None


def verify_numeric_surface(raw_output: str, row_manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """Gold-blind corruption detector.

    This verifier intentionally does not prove correctness. It only fails on
    mechanically corrupt numeric surfaces or manifest-bound impossibility.
    Everything ambiguous becomes ABSTAIN_UNVERIFIED_ACCEPT.
    """

    text = str(raw_output or "")
    numeric_required = _manifest_bool(row_manifest, "numeric_answer_required", "numeric_only_answer_required")
    nonnegative_required = _manifest_bool(row_manifest, "nonnegative_answer_required", "answer_must_be_nonnegative")
    max_value = _manifest_number(row_manifest, "max_answer_value")

    explicit = _explicit_final_surface(text)
    if explicit and (_NONFINITE_RE.fullmatch(explicit.strip()) or _NONFINITE_RE.search(explicit.strip())):
        return VerifierResult(FAIL_OBVIOUS_GARBAGE, "NONFINITE_NUMBER", explicit).to_dict()
    if explicit and _MALFORMED_NUMERIC_RE.fullmatch(explicit.strip()):
        return VerifierResult(FAIL_OBVIOUS_GARBAGE, "MALFORMED_NUMERIC_SURFACE", explicit).to_dict()

    surface = _candidate_surface(text)
    if surface is None:
        if numeric_required:
            return VerifierResult(FAIL_OBVIOUS_GARBAGE, "NUMERIC_REQUIRED_BUT_NO_SURFACE", None).to_dict()
        return VerifierResult(ABSTAIN_UNVERIFIED_ACCEPT, "NO_NUMERIC_SURFACE_UNVERIFIED", None).to_dict()

    normalized = _normalize_number(surface)
    if normalized is None:
        return VerifierResult(FAIL_OBVIOUS_GARBAGE, "MALFORMED_NUMERIC_SURFACE", surface).to_dict()

    value = Decimal(normalized)
    if value < 0 and nonnegative_required:
        return VerifierResult(FAIL_OBVIOUS_GARBAGE, "BOUND_DOMAIN_IMPOSSIBLE", normalized).to_dict()
    if max_value is not None and value > max_value:
        return VerifierResult(FAIL_OBVIOUS_GARBAGE, "BOUND_DOMAIN_IMPOSSIBLE", normalized).to_dict()

    return VerifierResult(ABSTAIN_UNVERIFIED_ACCEPT, "NUMERIC_SURFACE_UNVERIFIED", normalized).to_dict()


def fail_semantics_too_broad(result: dict[str, Any]) -> bool:
    return result.get("status") == FAIL_OBVIOUS_GARBAGE and str(result.get("reason")) not in FAIL_REASONS
