from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


def normalize_numeric(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.strip().replace(",", "")
    if not text:
        return ""
    match = re.search(r"[-+]?\d+(?:\.\d+)?", text)
    if not match:
        return ""
    number = match.group(0)
    if "." in number:
        number = number.rstrip("0").rstrip(".")
    return number


def extract_numeric_candidates(output_text: str) -> list[str]:
    text = str(output_text or "")
    candidates = [normalize_numeric(match) for match in re.findall(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?", text)]
    return [candidate for candidate in candidates if candidate]


def extract_final_surface(output_text: str, parsed_answer: Any = None, visible_answer: Any = None) -> dict[str, Any]:
    text = str(output_text or "")
    explicit_patterns = [
        r"(?:final\s+(?:answer|numeric answer)|answer\s+is|answer\s*:|final\s*:)\s*\$?\s*([-+]?\d+(?:,\d{3})*(?:\.\d+)?)",
        r"(?:therefore|thus).*?(?:=|is)\s*\$?\s*([-+]?\d+(?:,\d{3})*(?:\.\d+)?)",
    ]
    for pattern in explicit_patterns:
        matches = re.findall(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if matches:
            return {
                "source": "EXPLICIT_FINAL_MARKER",
                "surface": normalize_numeric(matches[-1]),
                "candidate_count": len(extract_numeric_candidates(text)),
            }
    visible = normalize_numeric(visible_answer)
    if visible:
        return {"source": "VISIBLE_ANSWER_FIELD", "surface": visible, "candidate_count": len(extract_numeric_candidates(text))}
    parsed = normalize_numeric(parsed_answer)
    if parsed:
        return {"source": "PARSED_ANSWER_FIELD", "surface": parsed, "candidate_count": len(extract_numeric_candidates(text))}
    candidates = extract_numeric_candidates(text)
    return {
        "source": "LAST_NUMERIC_CANDIDATE" if candidates else "NO_NUMERIC_SURFACE",
        "surface": candidates[-1] if candidates else "",
        "candidate_count": len(candidates),
    }


def likely_prompt_echo(output_text: str) -> bool:
    text = str(output_text or "")
    echo_markers = ["Compact mode:", "Mode rule:", "Question:", "Answer format:"]
    return sum(1 for marker in echo_markers if marker in text) >= 2


def verify_gsm8k_math_sidecar(row: dict[str, Any]) -> dict[str, Any]:
    output_text = str(row.get("output_text") or "")
    surface = extract_final_surface(output_text, row.get("parsed_answer"), row.get("visible_answer"))
    candidates = extract_numeric_candidates(output_text)
    prompt_echo = likely_prompt_echo(output_text)
    final_marker = bool(row.get("final_answer_marker_present"))
    parser_failure = bool(row.get("parser_format_failure"))
    if not surface["surface"]:
        verdict = "ABSTAIN_NO_NUMERIC_SURFACE"
        rescue_eligible = True
    elif prompt_echo:
        verdict = "ABSTAIN_PROMPT_ECHO_RISK"
        rescue_eligible = True
    elif parser_failure and not final_marker:
        verdict = "ABSTAIN_PARSER_SURFACE_UNSTABLE"
        rescue_eligible = True
    elif surface["candidate_count"] > 8 and not final_marker:
        verdict = "ABSTAIN_MANY_NUMERIC_CANDIDATES"
        rescue_eligible = True
    else:
        verdict = "VERIFIER_PASS_FIRST_PASS_INTACT"
        rescue_eligible = False
    return {
        "schema_id": "kt.v17_7_4.math_verifier_sidecar_result.v1",
        "sample_id": row.get("sample_id"),
        "arm_id": row.get("arm_id"),
        "dataset": row.get("dataset"),
        "task_family": row.get("task_family"),
        "verdict": verdict,
        "rescue_eligible": rescue_eligible,
        "first_pass_answer_surface": surface["surface"],
        "surface_source": surface["source"],
        "numeric_candidate_count": len(candidates),
        "prompt_echo_risk": prompt_echo,
        "final_answer_marker_present": final_marker,
        "parser_format_failure": parser_failure,
        "expected_answer_used": False,
        "model_generation_invoked": False,
        "first_pass_mutated": False,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python scripts/verify_v17_7_4_gsm8k_math_sidecar.py ROW_JSON", file=sys.stderr)
        return 2
    row_path = Path(argv[1])
    row = json.loads(row_path.read_text(encoding="utf-8-sig"))
    print(json.dumps(verify_gsm8k_math_sidecar(row), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
