from __future__ import annotations

import re
import zipfile
from collections import Counter
from pathlib import Path

from ktstop300_common import EVIDENCE, REPORTS, authority_payload, load_zip_jsonl, rel, sha256_file, write_json


MARKER_RE = re.compile(r"(?m)^[ \t]*FINAL_ANSWER\s*:\s*([^\r\n]*)")


def normalize_answer(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).replace(",", "").replace("$", "").strip()
    if not text:
        return None
    return text.lower()


def extract_numeric(text: str) -> str | None:
    fractions = re.findall(r"[-+]?\d[\d,]*\s*/\s*\d[\d,]*", text)
    if fractions:
        return normalize_answer(fractions[-1].replace(" ", ""))
    numbers = re.findall(r"[-+]?\$?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?", text)
    return normalize_answer(numbers[-1]) if numbers else None


def final_answer_candidates(raw_output: str) -> list[str | None]:
    return [extract_numeric(match.group(1)) for match in MARKER_RE.finditer(raw_output)]


def classify_trace(row: dict) -> str:
    candidates = final_answer_candidates(row.get("raw_output", ""))
    if not candidates:
        return "NO_VALID_FIRST_SEGMENT"
    first = normalize_answer(candidates[0])
    last = normalize_answer(candidates[-1])
    extracted = normalize_answer(row.get("extracted_answer"))
    correct = bool(row.get("correct"))
    if first is None or last is None:
        return "NO_VALID_FIRST_SEGMENT"
    if first == last and correct:
        return "FIRST_AND_LAST_SAME_CORRECT"
    if first == last and not correct:
        return "FIRST_AND_LAST_SAME_WRONG"
    if correct and last == extracted and first != extracted:
        return "FIRST_WRONG_LATER_CORRECT"
    if not correct and first == extracted and first != last:
        return "FIRST_CORRECT_LATER_WRONG"
    return "FIRST_AND_LAST_DIFFERENT_BOTH_WRONG"


def source_signature(source_name: str, row: dict) -> dict:
    if "KT_STOP50" in source_name:
        prompt_family = "STOP50_CURRENT_PROMPT"
        grammar = "FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"
    elif "STOPRT" in source_name:
        prompt_family = "STOPRT_CURRENT_PROMPT"
        grammar = "FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"
    else:
        prompt_family = "UNKNOWN_OR_CROSS_PROTOCOL"
        grammar = "UNKNOWN_OR_CROSS_PROTOCOL"
    return {
        "model_revision": "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
        "tokenizer_revision": "same_as_model_unpinned_in_historical_assessment",
        "rendered_prompt_template_hash": prompt_family,
        "final_answer_grammar_hash": grammar,
        "generation_config_hash": "do_sample_false_max_new_tokens_512",
        "scorer_canonicalizer_hash": "historical_assessment_embedded",
        "arm_id": row.get("arm_id"),
    }


def prediction_members(zip_path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(zip_path) as zf:
            return [name for name in zf.namelist() if name.endswith("predictions.jsonl")]
    except zipfile.BadZipFile:
        return []


def main() -> int:
    rows = []
    coverage = []
    signatures = {}
    for zip_path in sorted(EVIDENCE.glob("*.zip")):
        members = prediction_members(zip_path)
        if not members:
            coverage.append(
                {
                    "source": rel(zip_path),
                    "sha256": sha256_file(zip_path),
                    "status": "NO_COMPATIBLE_PREDICTIONS_MEMBER",
                    "processed_rows": 0,
                }
            )
            continue
        processed = 0
        for member in members:
            try:
                prediction_rows = load_zip_jsonl(zip_path, member)
            except Exception as exc:
                coverage.append(
                    {
                        "source": rel(zip_path),
                        "member": member,
                        "status": "UNREADABLE_PREDICTIONS",
                        "error": str(exc),
                        "processed_rows": 0,
                    }
                )
                continue
            for pred in prediction_rows:
                if "raw_output" not in pred:
                    continue
                classification = classify_trace(pred)
                signature = source_signature(zip_path.name, pred)
                signature_key = "|".join(str(signature[key]) for key in sorted(signature))
                signatures[signature_key] = signature
                rows.append(
                    {
                        "source": rel(zip_path),
                        "member": member,
                        "row_id": pred.get("row_id"),
                        "arm_id": pred.get("arm_id"),
                        "repetition": pred.get("repetition"),
                        "classification": classification,
                        "output_protocol_signature": signature_key,
                        "exact_stop300_protocol_family": "KT_STOP50" in zip_path.name,
                    }
                )
                processed += 1
        coverage.append(
            {
                "source": rel(zip_path),
                "sha256": sha256_file(zip_path),
                "status": "PROCESSED" if processed else "NO_SCORABLE_RAW_OUTPUT_ROWS",
                "processed_rows": processed,
                "prediction_members": members,
            }
        )

    exact_rows = [row for row in rows if row["exact_stop300_protocol_family"]]
    exact_counts = Counter(row["classification"] for row in exact_rows)
    all_counts = Counter(row["classification"] for row in rows)
    replay = {
        "schema_id": "kt.stop300.historical_first_vs_last_answer_counterfactual_replay.v1",
        "status": "PASS_EXACT_PROTOCOL_FIRST_WRONG_LATER_CORRECT_ZERO"
        if exact_counts.get("FIRST_WRONG_LATER_CORRECT", 0) == 0
        else "BLOCK_EXACT_PROTOCOL_FIRST_WRONG_LATER_CORRECT",
        "total_processed_traces": len(rows),
        "exact_protocol_processed_traces": len(exact_rows),
        "classification_counts_all": dict(all_counts),
        "classification_counts_exact_protocol": dict(exact_counts),
        "rows": rows,
        **authority_payload(),
    }
    write_json(REPORTS / "historical_first_vs_last_answer_counterfactual_replay.json", replay)

    coverage_payload = {
        "schema_id": "kt.stop300.historical_trace_source_coverage.v1",
        "status": "PASS_WITH_NAMED_COVERAGE_LEDGER",
        "sources": coverage,
        "known_corpus_families_requested": [
            "STOP10",
            "STOP50",
            "KTCF_CFFIX",
            "BUD",
            "512BASE",
            "PARETO",
            "ReproLock",
            "shuffle_generalization_controls",
            "Oracle_Academy",
        ],
        **authority_payload(),
    }
    write_json(REPORTS / "historical_trace_source_coverage.json", coverage_payload)

    signature_payload = {
        "schema_id": "kt.stop300.output_protocol_signature_registry.v1",
        "status": "PASS",
        "signatures": signatures,
        **authority_payload(),
    }
    write_json(REPORTS / "output_protocol_signature_registry.json", signature_payload)

    scope = {
        "schema_id": "kt.stop300.first_answer_safety_scope_decision.v1",
        "status": replay["status"],
        "exact_protocol_first_wrong_later_correct": exact_counts.get("FIRST_WRONG_LATER_CORRECT", 0),
        "cross_protocol_first_wrong_later_correct": all_counts.get("FIRST_WRONG_LATER_CORRECT", 0)
        - exact_counts.get("FIRST_WRONG_LATER_CORRECT", 0),
        "if_blocked_next_lane": "AUTHOR_KTSTOP_SAFE_STRATUM_GRAMMAR_REPAIR_V1",
        **authority_payload(),
    }
    write_json(REPORTS / "first_answer_safety_scope_decision.json", scope)
    if scope["exact_protocol_first_wrong_later_correct"] != 0:
        raise SystemExit("exact protocol FIRST_WRONG_LATER_CORRECT is nonzero")
    print("historical first-vs-last replay PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
