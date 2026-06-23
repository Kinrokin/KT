from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import math
import re
import statistics
import zipfile
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ASSESSMENT = ROOT / "evidence/stop300/KT_STOP300_V4_1_ASSESSMENT_ONLY_HF_RECOVERED.zip"
EXPECTED_ASSESSMENT_SHA256 = "e8152d7f08b668e3ac1d0d173140872a48a0eea2849cfa45da84568725305143"
L0 = "L0_LEGACY_NO_DETECTOR"
S1 = "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"
PASS_STATUS = "PASS_CORE_RESULT__PAIRWISE_RAW_TRACE_COURT"
PRECEDENCE = [
    "BLOCK_CORRECTNESS_DAMAGE",
    "BLOCK_FIRST_ANSWER_CORRECTION_CUT",
    "BLOCK_PREFIX_EQUIVALENCE",
    "BLOCK_RUNTIME_REFERENCE_DISAGREEMENT",
    "BLOCK_UNSAFE_STOP",
    "BLOCK_SCOPE_MISMATCH",
    "PARTIAL_WALL_TIME_CHECKPOINTED",
    "BLOCK_TOKEN_ECONOMICS",
    "BLOCK_TIMING_PROTOCOL_VIOLATION",
]
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return sha256_bytes(data)


def decimal_to_string(value: Decimal) -> str:
    if value == value.to_integral():
        return str(value.quantize(Decimal(1)))
    rendered = format(value.normalize(), "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def normalize_number(text: object) -> str:
    raw = str(text).strip().replace(",", "")
    if "####" in raw:
        raw = raw.split("####", 1)[-1].strip()
    raw = raw.replace("$", "")
    if raw.endswith("%"):
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
            return normalize_number(matches[-1])
    return decimal_to_string(value)


def extract_prediction_from_raw(raw_generated_text: str) -> str:
    marker = re.search(r"FINAL_ANSWER:\s*([^\n\r]+)", raw_generated_text or "")
    payload = marker.group(1) if marker else raw_generated_text
    return normalize_number(payload)


def derive_reference_boundary(record: dict[str, Any], marker: str = "FINAL_ANSWER:") -> dict[str, Any]:
    text = str(record.get("raw_generated_text", ""))
    terminal = record.get("terminal_token_id")
    eos_ids = {int(x) for x in record.get("effective_eos_token_ids", [])}
    ended_on_eos = bool(record.get("ended_on_eos")) or (terminal is not None and int(terminal) in eos_ids)
    ended_on_max = bool(record.get("ended_on_max_new_tokens"))
    custom_stop = bool(record.get("custom_stop_fired"))
    raw_hash = sha256_text(text)

    marker_match = re.search(r"(?m)^[ \t]*" + re.escape(marker), text)
    if marker_match is None:
        return {
            "semantic_boundary_type": "NO_VALID_BOUNDARY",
            "visible_text": text,
            "lawful": False,
            "correction_present": False,
            "unsafe_reason": "NO_LINE_ANCHORED_MARKER",
            "ended_on_eos": ended_on_eos,
            "ended_on_max_new_tokens": ended_on_max,
            "custom_stop_fired": custom_stop,
            "raw_generated_text_hash": raw_hash,
            "delivered_visible_text_hash": raw_hash,
        }

    tail = text[marker_match.end() :]
    payload_start = re.search(r"\S", tail)
    if payload_start is None:
        return {
            "semantic_boundary_type": "MALFORMED_FINAL",
            "visible_text": text,
            "lawful": False,
            "correction_present": False,
            "unsafe_reason": "EMPTY_PAYLOAD",
            "ended_on_eos": ended_on_eos,
            "ended_on_max_new_tokens": ended_on_max,
            "custom_stop_fired": custom_stop,
            "raw_generated_text_hash": raw_hash,
            "delivered_visible_text_hash": raw_hash,
        }

    answer_start = marker_match.end() + payload_start.start()
    rest = text[answer_start:]
    newline = re.search(r"\r\n|\n|\r", rest)
    second_marker = rest.find(marker)
    correction = bool(re.search(r"\b(correction|actually|instead|retract|wrong|wait)\b", rest, re.I))

    if second_marker >= 0 and (newline is None or second_marker < newline.start()):
        visible = text[: answer_start + second_marker].rstrip()
        lawful = bool(rest[:second_marker].strip()) and not correction
        return {
            "semantic_boundary_type": "SECOND_MARKER_CLOSE",
            "visible_text": visible,
            "lawful": lawful,
            "correction_present": correction,
            "unsafe_reason": None if lawful else "EMPTY_OR_CORRECTIVE_FIRST_SEGMENT",
            "ended_on_eos": ended_on_eos,
            "ended_on_max_new_tokens": ended_on_max,
            "custom_stop_fired": custom_stop,
            "raw_generated_text_hash": raw_hash,
            "delivered_visible_text_hash": sha256_text(visible),
        }
    if newline is not None:
        visible = text[: answer_start + newline.end()]
        return {
            "semantic_boundary_type": "FINAL_LINE_CLOSE",
            "visible_text": visible,
            "lawful": True,
            "correction_present": correction,
            "unsafe_reason": None,
            "ended_on_eos": ended_on_eos,
            "ended_on_max_new_tokens": ended_on_max,
            "custom_stop_fired": custom_stop,
            "raw_generated_text_hash": raw_hash,
            "delivered_visible_text_hash": sha256_text(visible),
        }
    if ended_on_eos and not ended_on_max:
        visible = text.rstrip()
        lawful = bool(visible.strip())
        return {
            "semantic_boundary_type": "SAFE_EOS_CLOSURE",
            "visible_text": visible,
            "lawful": lawful,
            "correction_present": correction,
            "unsafe_reason": None if lawful else "EMPTY_EOS_CLOSURE",
            "ended_on_eos": ended_on_eos,
            "ended_on_max_new_tokens": ended_on_max,
            "custom_stop_fired": custom_stop,
            "raw_generated_text_hash": raw_hash,
            "delivered_visible_text_hash": sha256_text(visible),
        }
    reason = "MAX_NEW_TOKENS_NOT_EOS" if ended_on_max else "NO_CLOSE"
    return {
        "semantic_boundary_type": "NO_VALID_BOUNDARY",
        "visible_text": text,
        "lawful": False,
        "correction_present": correction,
        "unsafe_reason": reason,
        "ended_on_eos": ended_on_eos,
        "ended_on_max_new_tokens": ended_on_max,
        "custom_stop_fired": custom_stop,
        "raw_generated_text_hash": raw_hash,
        "delivered_visible_text_hash": raw_hash,
    }


def median(values: list[int]) -> float:
    if not values:
        return 0.0
    return float(sorted(values)[len(values) // 2])


def trimmed_mean(values: list[int], trim: float = 0.10) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    cut = int(len(ordered) * trim)
    body = ordered[cut : len(ordered) - cut] if len(ordered) - 2 * cut > 0 else ordered
    return sum(body) / len(body)


def primary_status(active: set[str]) -> str:
    for status in PRECEDENCE:
        if status in active:
            return status
    return PASS_STATUS


def load_records(assessment: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(assessment) as zf:
        names = sorted(n for n in zf.namelist() if n.startswith("records/") and n.endswith(".json"))
        return [json.loads(zf.read(name)) for name in names]


def verify_raw_record_integrity(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    prompt_ids = [int(x) for x in record.get("prompt_token_ids", [])]
    raw_ids = [int(x) for x in record.get("raw_generated_token_ids", [])]
    prefix_ids = [int(x) for x in record.get("physical_stopped_generated_token_ids", [])]
    ceil = record.get("boundary_token_index_ceil")
    expected_stop = len(raw_ids) if ceil is None else max(0, min(len(raw_ids), int(ceil)))
    if record.get("prompt_token_count") != len(prompt_ids):
        errors.append("prompt_token_count_mismatch")
    if record.get("raw_generated_token_count") != len(raw_ids):
        errors.append("raw_generated_token_count_mismatch")
    if record.get("physical_stopped_generated_token_count") != len(prefix_ids):
        errors.append("physical_stopped_token_count_mismatch")
    if prefix_ids != raw_ids[:expected_stop]:
        errors.append("physical_prefix_mismatch")
    if record.get("raw_token_sha256") != sha256_json(raw_ids):
        errors.append("raw_token_hash_mismatch")
    if record.get("prefix_token_sha256") != sha256_json(prefix_ids):
        errors.append("prefix_token_hash_mismatch")
    if record.get("work_key") and record.get("work_key_sha256") != sha256_text(str(record.get("work_key"))):
        errors.append("work_key_hash_mismatch")
    return errors


def clean_record(record: dict[str, Any]) -> dict[str, Any]:
    prediction = extract_prediction_from_raw(str(record.get("raw_generated_text", "")))
    expected = normalize_number(record.get("expected_answer", ""))
    reference = derive_reference_boundary(record)
    return {
        "row_id": str(record.get("row_id")),
        "arm_id": str(record.get("arm_id")),
        "phase": str(record.get("phase")),
        "work_key": str(record.get("work_key", "")),
        "raw_text_sha256": sha256_text(str(record.get("raw_generated_text", ""))),
        "expected_normalized": expected,
        "prediction_recomputed": prediction,
        "correct_recomputed": prediction == expected,
        "reference_boundary": reference,
        "integrity_errors": verify_raw_record_integrity(record) if record.get("phase") != "warmup" else [],
    }


def exact_no_intervention_fallback(l0: dict[str, Any], s1: dict[str, Any], l0_clean: dict[str, Any], s1_clean: dict[str, Any]) -> bool:
    return all(
        [
            not bool(s1.get("custom_stop_fired")),
            list(s1.get("raw_generated_token_ids", [])) == list(l0.get("raw_generated_token_ids", [])),
            str(s1.get("raw_generated_text", "")) == str(l0.get("raw_generated_text", "")),
            s1_clean["prediction_recomputed"] == l0_clean["prediction_recomputed"],
            s1_clean["correct_recomputed"] == l0_clean["correct_recomputed"],
            bool(s1.get("ended_on_eos")) == bool(l0.get("ended_on_eos")),
            bool(s1.get("ended_on_max_new_tokens")) == bool(l0.get("ended_on_max_new_tokens")),
        ]
    )


def derive(assessment: Path, rows_output: Path | None = None) -> dict[str, Any]:
    assessment_sha = sha256_file(assessment)
    if assessment_sha != EXPECTED_ASSESSMENT_SHA256:
        raise SystemExit(f"assessment SHA mismatch: {assessment_sha}")
    records = load_records(assessment)
    clean = [clean_record(record) for record in records]
    by_work = {item["work_key"]: item for item in clean if item["work_key"]}
    clean_by_key = {item["work_key"]: item for item in clean}
    record_by_key = {str(record.get("work_key", "")): record for record in records}

    integrity_errors = [
        {"work_key": item["work_key"], "errors": item["integrity_errors"]}
        for item in clean
        if item["integrity_errors"]
    ]
    if integrity_errors:
        raise SystemExit(json.dumps({"raw_record_integrity_errors": integrity_errors[:20]}, sort_keys=True))

    natural_records = [record for record in records if record.get("phase") == "natural"]
    clean_natural = [clean_by_key[str(record.get("work_key", ""))] for record in natural_records]
    by_row: dict[str, dict[str, tuple[dict[str, Any], dict[str, Any]]]] = collections.defaultdict(dict)
    for record, derived in zip(natural_records, clean_natural):
        by_row[str(record["row_id"])][str(record["arm_id"])] = (record, derived)

    pair_rows: list[dict[str, Any]] = []
    official_active: set[str] = set()
    repaired_active: set[str] = set()
    for row_id, arms in sorted(by_row.items()):
        if L0 not in arms or S1 not in arms:
            continue
        l0, lc = arms[L0]
        s1, sc = arms[S1]
        l0_ids = [int(x) for x in l0.get("raw_generated_token_ids", [])]
        s1_ids = [int(x) for x in s1.get("raw_generated_token_ids", [])]
        l0_text = str(l0.get("raw_generated_text", ""))
        s1_text = str(s1.get("raw_generated_text", ""))
        runtime = s1.get("runtime_first_boundary") or {}
        reference = sc["reference_boundary"]
        raw_prefix = s1_ids == l0_ids[: len(s1_ids)]
        byte_prefix = l0_text.encode("utf-8").startswith(s1_text.encode("utf-8"))
        runtime_agreement = runtime.get("semantic_boundary_type") == reference["semantic_boundary_type"] if runtime else True
        semantic_trailer = bool(s1.get("custom_stop_fired")) and len(s1_text) > len(str(reference["visible_text"]))
        dangling_marker = str(reference["visible_text"]).count("FINAL_ANSWER:") > 1
        unsafe_official = not bool(reference["lawful"])
        fallback = exact_no_intervention_fallback(l0, s1, lc, sc)
        unsafe_repaired = unsafe_official and not fallback
        row = {
            "row_id": row_id,
            "l0_correct_recomputed": lc["correct_recomputed"],
            "s1_correct_recomputed": sc["correct_recomputed"],
            "correctness_damage": lc["correct_recomputed"] and not sc["correct_recomputed"],
            "raw_token_prefix_equivalence": raw_prefix,
            "decoded_byte_prefix_equivalence": byte_prefix,
            "runtime_reference_agreement": runtime_agreement,
            "official_reference_boundary_type": reference["semantic_boundary_type"],
            "official_unsafe_stop": unsafe_official,
            "repaired_unsafe_stop": unsafe_repaired,
            "exact_no_intervention_fallback": fallback,
            "semantic_trailer_present": semantic_trailer,
            "dangling_marker_present": dangling_marker,
            "correction_present": bool(reference["correction_present"]),
            "token_boundary_error_count": len(s1.get("token_boundary_errors", [])),
            "physical_output_token_savings": len(l0_ids) - len(s1_ids),
            "full_token_savings": (int(l0.get("prompt_token_count", 0)) + len(l0_ids)) - (int(s1.get("prompt_token_count", 0)) + len(s1_ids)),
            "l0_raw_text_sha256": lc["raw_text_sha256"],
            "s1_raw_text_sha256": sc["raw_text_sha256"],
        }
        pair_rows.append(row)

    physical = [row["physical_output_token_savings"] for row in pair_rows]
    full = [row["full_token_savings"] for row in pair_rows]
    duplicate_work_keys = len(records) - len({str(record.get("work_key", "")) for record in records})
    phase_counts = collections.Counter(str(record.get("phase")) for record in records)
    timing_triplets = len(
        {
            (str(record.get("row_id")), int(record.get("repetition", 0)))
            for record in records
            if record.get("phase") == "timing"
        }
    )

    def arm_tpc(arm_id: str) -> float:
        rows = [(record, clean_by_key[str(record.get("work_key", ""))]) for record in natural_records if record.get("arm_id") == arm_id]
        correct = sum(1 for _, item in rows if item["correct_recomputed"])
        if not correct:
            return math.inf
        total = sum(int(record.get("prompt_token_count", 0)) + len(record.get("raw_generated_token_ids", [])) for record, _ in rows)
        return total / correct

    if any(row["correctness_damage"] for row in pair_rows):
        official_active.add("BLOCK_CORRECTNESS_DAMAGE")
    if any(row["correction_present"] for row in pair_rows):
        official_active.add("BLOCK_FIRST_ANSWER_CORRECTION_CUT")
    if any(not row["raw_token_prefix_equivalence"] or not row["decoded_byte_prefix_equivalence"] for row in pair_rows):
        official_active.add("BLOCK_PREFIX_EQUIVALENCE")
    if any(not row["runtime_reference_agreement"] for row in pair_rows):
        official_active.add("BLOCK_RUNTIME_REFERENCE_DISAGREEMENT")
    if any(row["official_unsafe_stop"] or row["token_boundary_error_count"] or row["semantic_trailer_present"] or row["dangling_marker_present"] for row in pair_rows):
        official_active.add("BLOCK_UNSAFE_STOP")
    if duplicate_work_keys:
        official_active.add("BLOCK_SCOPE_MISMATCH")
    if len(by_row) != 300 or phase_counts != collections.Counter({"natural": 600, "timing": 540, "edge": 36, "warmup": 9}):
        official_active.add("PARTIAL_WALL_TIME_CHECKPOINTED")
    if any(value < 0 for value in physical) or median(physical) <= 0 or trimmed_mean(physical) <= 0 or sum(full) <= 0 or not arm_tpc(S1) < arm_tpc(L0):
        official_active.add("BLOCK_TOKEN_ECONOMICS")
    if any(int(record.get("detector_telemetry", {}).get("full_sequence_rescan_count", 0)) for record in records):
        official_active.add("BLOCK_TIMING_PROTOCOL_VIOLATION")

    repaired_active = set(official_active)
    if not any(row["repaired_unsafe_stop"] or row["token_boundary_error_count"] for row in pair_rows):
        repaired_active.discard("BLOCK_UNSAFE_STOP")

    scorer_mismatch_count = 0
    for record in natural_records:
        derived = clean_by_key[str(record.get("work_key", ""))]
        # Comparison happens after independent derivation and is not a verdict input.
        recorded_prediction = record.get("prediction")
        recorded_correct = record.get("correct")
        if str(recorded_prediction or "") != derived["prediction_recomputed"] or bool(recorded_correct) != derived["correct_recomputed"]:
            scorer_mismatch_count += 1

    summary = {
        "schema_id": "kt.stop300.v41.cleanroom_recomputation.v2",
        "source_assessment_sha256": assessment_sha,
        "record_count_total": len(records),
        "measured_record_count": len([record for record in records if record.get("phase") != "warmup"]),
        "natural_pair_count": len(pair_rows),
        "timing_triplet_count": timing_triplets,
        "edge_execution_count": phase_counts.get("edge", 0),
        "l0_correct": sum(1 for item in clean_natural if item["arm_id"] == L0 and item["correct_recomputed"]),
        "s1_correct": sum(1 for item in clean_natural if item["arm_id"] == S1 and item["correct_recomputed"]),
        "paired_correctness_damage": sum(1 for row in pair_rows if row["correctness_damage"]),
        "output_tokens_saved": sum(physical),
        "negative_savings_rows": sum(1 for value in physical if value < 0),
        "raw_prefix_mismatch_count": sum(1 for row in pair_rows if not row["raw_token_prefix_equivalence"]),
        "duplicate_work_key_count": duplicate_work_keys,
        "official_unlawful_reference_count": sum(1 for row in pair_rows if row["official_unsafe_stop"]),
        "official_recomputed_status": primary_status(official_active),
        "official_active_statuses": sorted(official_active),
        "repaired_counterfactual_status": primary_status(repaired_active),
        "derived_field_dependency_count": 0,
        "scorer_reconciliation_mismatch_count": scorer_mismatch_count,
        "claim_ceiling_status": "PRESERVED",
        "predicate_vector": {
            "phase_counts": dict(sorted(phase_counts.items())),
            "l0_full_tokens_per_correct": arm_tpc(L0),
            "s1_full_tokens_per_correct": arm_tpc(S1),
            "median_physical_output_token_savings": median(physical),
            "trimmed_mean_physical_output_token_savings": trimmed_mean(physical),
            "semantic_post_boundary_trailers": sum(1 for row in pair_rows if row["semantic_trailer_present"]),
            "dangling_repeated_markers": sum(1 for row in pair_rows if row["dangling_marker_present"]),
            "exact_no_intervention_fallback_count": sum(1 for row in pair_rows if row["exact_no_intervention_fallback"]),
            "repaired_unsafe_stop_count": sum(1 for row in pair_rows if row["repaired_unsafe_stop"]),
        },
    }

    expected = {
        "record_count_total": 1185,
        "measured_record_count": 1176,
        "natural_pair_count": 300,
        "timing_triplet_count": 180,
        "edge_execution_count": 36,
        "l0_correct": 261,
        "s1_correct": 261,
        "paired_correctness_damage": 0,
        "output_tokens_saved": 1500,
        "negative_savings_rows": 0,
        "raw_prefix_mismatch_count": 0,
        "duplicate_work_key_count": 0,
        "official_unlawful_reference_count": 3,
        "official_recomputed_status": "BLOCK_UNSAFE_STOP",
        "official_active_statuses": ["BLOCK_TOKEN_ECONOMICS", "BLOCK_UNSAFE_STOP"],
        "repaired_counterfactual_status": "BLOCK_TOKEN_ECONOMICS",
        "derived_field_dependency_count": 0,
        "scorer_reconciliation_mismatch_count": 0,
    }
    for key, value in expected.items():
        if summary[key] != value:
            raise AssertionError((key, summary[key], value))

    if rows_output:
        rows_output.parent.mkdir(parents=True, exist_ok=True)
        with rows_output.open("w", encoding="utf-8", newline="\n") as fh:
            for row in pair_rows:
                fh.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--rows-out", type=Path)
    args = parser.parse_args()
    result = derive(args.assessment, args.rows_out)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    print("stop300_cleanroom_recompute_pass")


if __name__ == "__main__":
    main()
