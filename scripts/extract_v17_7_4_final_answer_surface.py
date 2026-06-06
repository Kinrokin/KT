from __future__ import annotations

import re


FINAL_MARKER_RE = re.compile(r"(?:^|\n)\s*(?:final|answer)\s*[:=]\s*(.+?)(?=\n\s*(?:final|answer)\s*[:=]|\Z)", re.IGNORECASE | re.DOTALL)
MCQ_RE = re.compile(r"\b([A-D])\b", re.IGNORECASE)
NUMBER_RE = re.compile(r"[-+]?\d+(?:\.\d+)?(?:/\d+)?")


def normalize_answer_surface(text: str) -> str:
    return " ".join(str(text or "").strip().split())


def extract_final_answer_surface(text: str, answer_type: str = "") -> str:
    """Extract the last explicit final answer surface without consulting the gold label."""
    raw = str(text or "")
    matches = list(FINAL_MARKER_RE.finditer(raw))
    if matches:
        surface = matches[-1].group(1).strip()
    else:
        nonempty = [line.strip() for line in raw.splitlines() if line.strip()]
        surface = nonempty[-1] if nonempty else raw.strip()
    answer_type_l = answer_type.lower()
    if "multiple" in answer_type_l or "choice" in answer_type_l:
        letters = MCQ_RE.findall(surface)
        if letters:
            return letters[-1].upper()
    if "numeric" in answer_type_l or "math" in answer_type_l:
        numbers = NUMBER_RE.findall(surface.replace(",", ""))
        if numbers:
            return numbers[-1]
    return normalize_answer_surface(surface)


__all__ = ["extract_final_answer_surface", "normalize_answer_surface"]
