from __future__ import annotations

from decimal import Decimal, InvalidOperation
from fractions import Fraction
import re


NUMBER_PATTERN = re.compile(
    r"""
    (?<![\w.])
    [-+]?
    (?:\$)?
    (?:
      \d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?
      |
      \d+\s*/\s*\d+
    )
    %?
    (?![\w.])
    """,
    re.VERBOSE,
)


def _decimal_to_string(value: Decimal) -> str:
    if value == value.to_integral():
        return str(value.quantize(Decimal(1)))
    rendered = format(value.normalize(), "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def normalize_number(text: object, *, percent_as_fraction: bool = False) -> str:
    raw = str(text).strip().replace(",", "")
    if "####" in raw:
        raw = raw.split("####", 1)[-1].strip()
    raw = raw.replace("$", "")
    percent = raw.endswith("%")
    if percent:
        raw = raw[:-1].strip()
    try:
        value = Decimal(raw)
    except InvalidOperation:
        try:
            frac = Fraction(raw.replace(" ", ""))
            value = Decimal(frac.numerator) / Decimal(frac.denominator)
        except Exception:
            matches = NUMBER_PATTERN.findall(str(text))
            if not matches:
                return ""
            return normalize_number(matches[-1], percent_as_fraction=percent_as_fraction)
    if percent and percent_as_fraction:
        value = value / Decimal(100)
    return _decimal_to_string(value)


def extract_expected_answer(answer: str) -> str:
    return normalize_number(answer, percent_as_fraction=False)


def extract_prediction(text: str) -> str:
    marker = re.search(r"FINAL_ANSWER:\s*([^\n\r]+)", text or "")
    payload = marker.group(1) if marker else text
    return normalize_number(payload, percent_as_fraction=False)


def score_prediction(prediction: str, expected: str) -> bool:
    return normalize_number(prediction) == normalize_number(expected)


def oracle_fixture_suite() -> dict:
    fixtures = {
        "#### 1,234": "1234",
        "$-12.50": "-12.5",
        "3/4": "0.75",
        "1.2e3": "1200",
        "FINAL_ANSWER: 42\ntrailer": "42",
        "12%": "12",
    }
    failures = {source: (normalize_number(source), expected) for source, expected in fixtures.items() if normalize_number(source) != expected}
    return {
        "schema_id": "kt.stop300.v4.numeric_oracle_fixture_suite.v1",
        "status": "PASS" if not failures else "FAIL",
        "fixture_count": len(fixtures),
        "failures": failures,
    }
