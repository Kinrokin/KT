from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any


EXPLICIT_FINAL_MARKER = "EXPLICIT_FINAL_MARKER"
FINAL_LINE = "FINAL_LINE"
ISOLATED_NUMERIC_LINE = "ISOLATED_NUMERIC_LINE"
CURRENT_SCORER = "CURRENT_SCORER"
LAST_NUMERIC_AUDIT_ONLY = "LAST_NUMERIC_AUDIT_ONLY"

RUNTIME_ADMISSIBLE_SURFACES = {
    EXPLICIT_FINAL_MARKER,
    FINAL_LINE,
    ISOLATED_NUMERIC_LINE,
    CURRENT_SCORER,
}
AUDIT_ONLY_SURFACES = {LAST_NUMERIC_AUDIT_ONLY}

FROZEN_CANDIDATE_ORDER = [
    CURRENT_SCORER,
    EXPLICIT_FINAL_MARKER,
    FINAL_LINE,
    ISOLATED_NUMERIC_LINE,
    LAST_NUMERIC_AUDIT_ONLY,
]

CANONICALIZER_TOGGLES = {
    "comma_strip": True,
    "currency_symbol_strip": True,
    "decimal_zero_to_integer": True,
    "percent_symbol_strip": False,
    "word_number_conversion": False,
    "fraction_to_decimal": False,
    "broad_unit_strip": False,
    "last_numeric_runtime_fallback": False,
}

_FINAL_RE = re.compile(
    r"(?:^|\n)\s*(?:final\s+(?:answer|numeric\s+answer)|answer|final)\s*[:=]\s*([^\n\r]+)",
    re.IGNORECASE,
)
_NUMBER_RE = re.compile(r"[-+]?\$?\d[\d,]*(?:\.\d+)?%?")
_ISOLATED_NUMERIC_RE = re.compile(r"^\s*[-+]?\$?\d[\d,]*(?:\.\d+)?%?\s*$")


@dataclass(frozen=True)
class AnswerSurface:
    surface_id: str
    raw_surface: str
    canonical_surface: str
    canonical_rule: str
    runtime_admissible: bool
    audit_only: bool
    span_start: int
    span_end: int
    span_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_id": self.surface_id,
            "raw_surface": self.raw_surface,
            "canonical_surface": self.canonical_surface,
            "canonical_rule": self.canonical_rule,
            "runtime_admissible": self.runtime_admissible,
            "audit_only": self.audit_only,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "span_sha256": self.span_sha256,
        }


def sha256_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _squash(text: str) -> str:
    return " ".join(str(text or "").strip().split())


def _decimal_zero_to_integer(text: str) -> str:
    try:
        value = Decimal(text)
    except (InvalidOperation, ValueError):
        return text
    if not value.is_finite():
        return text
    normalized = format(value.normalize(), "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return "0" if normalized == "-0" else normalized


def canonicalize_surface(surface: str, *, answer_kind: str = "numeric") -> tuple[str, str]:
    """Gold-blind, deterministic surface canonicalization.

    This intentionally avoids expected answers, NLP libraries, symbolic math,
    and semantic repairs. It only performs narrow answer-surface cleanup.
    """

    original = _squash(surface)
    text = original
    applied: list[str] = []

    if CANONICALIZER_TOGGLES["currency_symbol_strip"] and text.startswith("$"):
        text = text[1:]
        applied.append("currency_symbol_strip")

    if answer_kind == "numeric" and CANONICALIZER_TOGGLES["comma_strip"]:
        stripped = text.replace(",", "")
        if stripped != text:
            text = stripped
            applied.append("comma_strip")

    if answer_kind == "numeric" and CANONICALIZER_TOGGLES["decimal_zero_to_integer"]:
        normalized = _decimal_zero_to_integer(text)
        if normalized != text:
            text = normalized
            applied.append("decimal_zero_to_integer")

    if answer_kind == "multiple_choice":
        match = re.search(r"\b([A-D])\b", text, re.IGNORECASE)
        if match:
            text = match.group(1).upper()
            applied.append("mcq_letter_extract")

    if answer_kind != "numeric" and answer_kind != "multiple_choice":
        text = text.lower()
        applied.append("short_answer_lowercase")

    return text, "+".join(applied) if applied else "identity"


def _answer_kind(row: dict[str, Any] | None = None) -> str:
    row = row or {}
    dataset = str(row.get("dataset", "")).lower()
    task_family = str(row.get("task_family", "")).lower()
    answer_type = str(row.get("answer_type") or row.get("answer_format_contract") or "").lower()
    if "gsm8k" in dataset or "math" in task_family or "numeric" in answer_type:
        return "numeric"
    if "arc" in dataset or "hellaswag" in dataset or "choice" in answer_type:
        return "multiple_choice"
    return "short_answer"


def _surface(
    surface_id: str,
    raw_output: str,
    raw_surface: str,
    span_start: int,
    span_end: int,
    answer_kind: str,
) -> AnswerSurface:
    canonical, rule = canonicalize_surface(raw_surface, answer_kind=answer_kind)
    return AnswerSurface(
        surface_id=surface_id,
        raw_surface=_squash(raw_surface),
        canonical_surface=canonical,
        canonical_rule=rule,
        runtime_admissible=surface_id in RUNTIME_ADMISSIBLE_SURFACES,
        audit_only=surface_id in AUDIT_ONLY_SURFACES,
        span_start=span_start,
        span_end=span_end,
        span_sha256=sha256_text(raw_output[span_start:span_end] if span_start >= 0 and span_end >= span_start else raw_surface),
    )


def extract_answer_surfaces(raw_output: str, row: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return frozen-order answer surfaces without consulting gold labels."""

    text = str(raw_output or "")
    answer_kind = _answer_kind(row)
    surfaces: dict[str, AnswerSurface] = {}

    final_matches = list(_FINAL_RE.finditer(text))
    if final_matches:
        match = final_matches[-1]
        raw = match.group(1).strip()
        number_match = list(_NUMBER_RE.finditer(raw))
        if answer_kind == "numeric" and number_match:
            nm = number_match[-1]
            raw = nm.group(0)
            start = match.start(1) + nm.start()
            end = match.start(1) + nm.end()
        else:
            start = match.start(1)
            end = match.end(1)
        surfaces[EXPLICIT_FINAL_MARKER] = _surface(EXPLICIT_FINAL_MARKER, text, raw, start, end, answer_kind)

    nonempty_lines = [(line.strip(), idx) for idx, line in enumerate(text.splitlines()) if line.strip()]
    if nonempty_lines:
        line, _ = nonempty_lines[-1]
        start = text.rfind(line)
        surfaces[FINAL_LINE] = _surface(FINAL_LINE, text, line, start, start + len(line), answer_kind)

    isolated = [(m.group(0).strip(), m.start(), m.end()) for m in re.finditer(r"^.*$", text, re.MULTILINE) if _ISOLATED_NUMERIC_RE.fullmatch(m.group(0))]
    if isolated:
        raw, start, end = isolated[-1]
        surfaces[ISOLATED_NUMERIC_LINE] = _surface(ISOLATED_NUMERIC_LINE, text, raw, start, end, answer_kind)

    current = str((row or {}).get("parsed_answer") or (row or {}).get("visible_answer") or "").strip()
    if current:
        surfaces[CURRENT_SCORER] = _surface(CURRENT_SCORER, text, current, -1, -1, answer_kind)

    numbers = list(_NUMBER_RE.finditer(text))
    if numbers:
        match = numbers[-1]
        surfaces[LAST_NUMERIC_AUDIT_ONLY] = _surface(
            LAST_NUMERIC_AUDIT_ONLY,
            text,
            match.group(0),
            match.start(),
            match.end(),
            answer_kind,
        )

    return [surfaces[surface_id].to_dict() for surface_id in FROZEN_CANDIDATE_ORDER if surface_id in surfaces]


def select_frozen_candidate(raw_output: str, row: dict[str, Any] | None = None) -> dict[str, Any]:
    surfaces = extract_answer_surfaces(raw_output, row)
    for surface in surfaces:
        if surface["runtime_admissible"] and not surface["audit_only"]:
            return {
                "schema_id": "kt.v17_7_4.parser_canonicalizer_result.v1",
                "status": "SELECTED_RUNTIME_ADMISSIBLE_SURFACE",
                "selected_surface": surface,
                "candidate_surfaces": surfaces,
                "candidate_order": list(FROZEN_CANDIDATE_ORDER),
                "canonicalizer_toggles": dict(CANONICALIZER_TOGGLES),
                "expected_answer_used": False,
                "model_generation_invoked": False,
                "first_pass_mutated": False,
            }
    return {
        "schema_id": "kt.v17_7_4.parser_canonicalizer_result.v1",
        "status": "NO_RUNTIME_ADMISSIBLE_SURFACE",
        "selected_surface": None,
        "candidate_surfaces": surfaces,
        "candidate_order": list(FROZEN_CANDIDATE_ORDER),
        "canonicalizer_toggles": dict(CANONICALIZER_TOGGLES),
        "expected_answer_used": False,
        "model_generation_invoked": False,
        "first_pass_mutated": False,
    }


__all__ = [
    "AUDIT_ONLY_SURFACES",
    "CANONICALIZER_TOGGLES",
    "FROZEN_CANDIDATE_ORDER",
    "RUNTIME_ADMISSIBLE_SURFACES",
    "canonicalize_surface",
    "extract_answer_surfaces",
    "select_frozen_candidate",
    "sha256_text",
]
