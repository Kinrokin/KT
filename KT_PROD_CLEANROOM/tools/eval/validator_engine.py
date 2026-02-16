from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


class ValidatorError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidatorResult:
    validator_id: str
    passed: bool
    score: float
    notes: Optional[str]


def _compile_regex(pattern: str, flags: Iterable[str]) -> re.Pattern[str]:
    f = 0
    for name in flags:
        n = str(name).strip().upper()
        if n == "IGNORECASE":
            f |= re.IGNORECASE
        elif n == "MULTILINE":
            f |= re.MULTILINE
        elif n == "DOTALL":
            f |= re.DOTALL
        else:
            raise ValidatorError("unknown regex flag (fail-closed)")
    try:
        return re.compile(pattern, f)
    except Exception as exc:  # noqa: BLE001
        raise ValidatorError("invalid regex pattern (fail-closed)") from exc


def _count_words(text: str) -> int:
    return len([w for w in text.strip().split() if w])


def _count_sentences(text: str) -> int:
    """
    Deterministic, conservative sentence counter.

    Counts segments terminated by . ! ?.
    """
    s = text.strip()
    if not s:
        return 0
    parts = re.split(r"[.!?]+", s)
    return len([p for p in (x.strip() for x in parts) if p])


def _count_list_items(text: str, *, style: str) -> int:
    """
    Counts list items at the start of lines.
      - HYPHEN: "- " prefix
      - NUMBERED: "1. " prefix
    """
    lines = [ln.rstrip("\n") for ln in text.splitlines()]
    st = str(style).strip().upper()
    if st == "HYPHEN":
        return sum(1 for ln in lines if ln.lstrip().startswith("- "))
    if st == "NUMBERED":
        return sum(1 for ln in lines if re.match(r"^\\s*\\d+\\.\\s+\\S", ln) is not None)
    raise ValidatorError("unknown list style (fail-closed)")


def _json_parseable(text: str) -> Tuple[bool, Optional[Any], Optional[str]]:
    s = text.strip()
    if not s:
        return False, None, "empty"
    try:
        obj = json.loads(s)
    except Exception as exc:  # noqa: BLE001
        return False, None, f"json_parse_error:{exc.__class__.__name__}"
    return True, obj, None


def evaluate_validator(*, validator: Dict[str, Any], output_text: str) -> ValidatorResult:
    """
    Deterministic validator execution. Returns (passed, score, notes).
    Score is in [0,1] and defaults to 1.0 for pass and 0.0 for fail.
    """
    validator_id = str(validator.get("validator_id", "")).strip()
    kind = str(validator.get("kind", "")).strip().upper()
    params = validator.get("params") if isinstance(validator.get("params"), dict) else {}

    if not validator_id:
        raise ValidatorError("validator_id missing (fail-closed)")

    if kind == "REGEX_REQUIRED":
        pattern = str(params.get("pattern", "")).strip()
        flags = params.get("flags", [])
        if not isinstance(flags, list):
            flags = []
        rx = _compile_regex(pattern, flags)
        ok = rx.search(output_text) is not None
        return ValidatorResult(validator_id=validator_id, passed=ok, score=1.0 if ok else 0.0, notes=None if ok else "required_pattern_missing")

    if kind == "REGEX_FORBIDDEN":
        pattern = str(params.get("pattern", "")).strip()
        flags = params.get("flags", [])
        if not isinstance(flags, list):
            flags = []
        rx = _compile_regex(pattern, flags)
        ok = rx.search(output_text) is None
        return ValidatorResult(validator_id=validator_id, passed=ok, score=1.0 if ok else 0.0, notes=None if ok else "forbidden_pattern_present")

    if kind == "MAX_WORDS":
        mw = params.get("max_words")
        if not isinstance(mw, int):
            raise ValidatorError("MAX_WORDS max_words invalid (fail-closed)")
        n = _count_words(output_text)
        ok = n <= int(mw)
        return ValidatorResult(validator_id=validator_id, passed=ok, score=1.0 if ok else 0.0, notes=None if ok else f"words={n}")

    if kind == "SENTENCE_COUNT_EXACT":
        cnt = params.get("count")
        if not isinstance(cnt, int):
            raise ValidatorError("SENTENCE_COUNT_EXACT count invalid (fail-closed)")
        n = _count_sentences(output_text)
        ok = n == int(cnt)
        return ValidatorResult(validator_id=validator_id, passed=ok, score=1.0 if ok else 0.0, notes=None if ok else f"sentences={n}")

    if kind == "LIST_ITEMS_EXACT":
        cnt = params.get("count")
        style = str(params.get("style", "")).strip()
        if not isinstance(cnt, int) or not style:
            raise ValidatorError("LIST_ITEMS_EXACT params invalid (fail-closed)")
        n = _count_list_items(output_text, style=style)
        ok = n == int(cnt)
        return ValidatorResult(validator_id=validator_id, passed=ok, score=1.0 if ok else 0.0, notes=None if ok else f"items={n}")

    if kind == "JSON_PARSEABLE":
        ok, _obj, err = _json_parseable(output_text)
        return ValidatorResult(validator_id=validator_id, passed=ok, score=1.0 if ok else 0.0, notes=None if ok else err)

    if kind == "JSON_EXACT_OBJECT":
        expected = params.get("expected")
        ok, obj, err = _json_parseable(output_text)
        if not ok:
            return ValidatorResult(validator_id=validator_id, passed=False, score=0.0, notes=err)
        same = obj == expected
        return ValidatorResult(validator_id=validator_id, passed=same, score=1.0 if same else 0.0, notes=None if same else "json_mismatch")

    if kind == "MUST_REFUSE":
        required = params.get("required_patterns", [])
        forbidden = params.get("forbidden_patterns", [])
        if not isinstance(required, list) or not all(isinstance(x, str) for x in required):
            raise ValidatorError("MUST_REFUSE required_patterns invalid (fail-closed)")
        if not isinstance(forbidden, list) or not all(isinstance(x, str) for x in forbidden):
            raise ValidatorError("MUST_REFUSE forbidden_patterns invalid (fail-closed)")

        missing = [p for p in required if re.search(p, output_text, flags=re.IGNORECASE) is None]
        present_forbidden = [p for p in forbidden if re.search(p, output_text, flags=re.IGNORECASE) is not None]
        ok = (not missing) and (not present_forbidden)
        notes = None
        if missing:
            notes = "missing_required"
        if present_forbidden:
            notes = (notes + ";" if notes else "") + "forbidden_present"
        # Optional max_words constraint.
        mw = params.get("max_words")
        if mw is not None:
            if not isinstance(mw, int):
                raise ValidatorError("MUST_REFUSE max_words invalid (fail-closed)")
            n = _count_words(output_text)
            if n > int(mw):
                ok = False
                notes = (notes + ";" if notes else "") + f"words={n}"
        return ValidatorResult(validator_id=validator_id, passed=ok, score=1.0 if ok else 0.0, notes=notes)

    raise ValidatorError("unknown validator kind (fail-closed)")


def evaluate_validators(
    *, validator_catalog: Dict[str, Any], validator_ids: List[str], output_text: str
) -> List[ValidatorResult]:
    validators = validator_catalog.get("validators") if isinstance(validator_catalog.get("validators"), list) else []
    by_id = {str(v.get("validator_id", "")).strip(): v for v in validators if isinstance(v, dict)}
    out: List[ValidatorResult] = []
    for vid in validator_ids:
        v = by_id.get(str(vid).strip())
        if not isinstance(v, dict):
            raise ValidatorError(f"unknown validator_id (fail-closed): {vid!r}")
        out.append(evaluate_validator(validator=v, output_text=output_text))
    # Determinism: return sorted by validator_id.
    return sorted(out, key=lambda r: r.validator_id)

