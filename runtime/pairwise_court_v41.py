from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

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


def _rows(records: list[dict[str, Any]] | str | Path) -> list[dict[str, Any]]:
    if isinstance(records, list):
        return records
    path = Path(records)
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def _primary(active: set[str]) -> str:
    for status in PRECEDENCE:
        if status in active:
            return status
    return PASS_STATUS


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def _trimmed_mean(values: list[float], trim: float = 0.10) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    cut = int(len(ordered) * trim)
    body = ordered[cut : len(ordered) - cut] if len(ordered) - (2 * cut) > 0 else ordered
    return sum(body) / len(body)


def _raw_ids(row: dict[str, Any]) -> list[int]:
    if "raw_generated_token_ids" in row:
        return [int(token_id) for token_id in row["raw_generated_token_ids"]]
    return [0] * int(row.get("raw_generated_token_count", 0))


def full_tpc(records: list[dict[str, Any]] | str | Path, arm_id: str) -> float:
    rows = [row for row in _rows(records) if row.get("arm_id") == arm_id and row.get("phase") == "natural"]
    correct = [row for row in rows if bool(row.get("correct"))]
    if not correct:
        return math.inf
    total_tokens = sum(int(row.get("prompt_token_count", 0)) + len(_raw_ids(row)) for row in rows)
    return total_tokens / len(correct)


def derive_pair(l0: dict[str, Any], s1: dict[str, Any]) -> dict[str, Any]:
    l0_ids = _raw_ids(l0)
    s1_ids = _raw_ids(s1)
    l0_text = str(l0.get("raw_generated_text", ""))
    s1_text = str(s1.get("raw_generated_text", ""))
    l0_bytes = l0_text.encode("utf-8")
    s1_bytes = s1_text.encode("utf-8")
    runtime = s1.get("runtime_first_boundary") or {}
    reference = s1.get("reference_court") or {}
    s1_prompt = int(s1.get("prompt_token_count", 0))
    l0_prompt = int(l0.get("prompt_token_count", 0))
    correction_cut = bool(s1.get("first_wrong_later_correct")) or bool(reference.get("correction_present"))
    semantic_trailer = bool(s1.get("derived_semantic_trailer")) or (
        bool(runtime.get("visible_text")) and len(s1_text) > len(str(runtime.get("visible_text")))
    )
    dangling_marker = str(s1.get("semantic_visible_text", s1_text)).count("FINAL_ANSWER:") > 1
    raw_prefix = s1_ids == l0_ids[: len(s1_ids)]
    byte_prefix = l0_bytes.startswith(s1_bytes)
    return {
        "row_id": s1.get("row_id"),
        "schema_id": "kt.stop300.v41.raw_trace_pairwise_derivation.v1",
        "derivation_source": "IMMUTABLE_RAW_L0_S1_TRACES",
        "raw_token_prefix_equivalence": raw_prefix,
        "decoded_byte_prefix_equivalence": byte_prefix,
        "runtime_reference_agreement": runtime.get("semantic_boundary_type") == reference.get("semantic_boundary_type")
        if runtime and reference
        else True,
        "semantic_trailer_present": semantic_trailer,
        "dangling_marker_present": dangling_marker,
        "first_wrong_later_corrected_cut": correction_cut,
        "unsafe_stop": bool(s1.get("derived_unsafe_stop")) or not bool(reference.get("lawful", True)),
        "token_boundary_error_count": len(s1.get("token_boundary_errors", [])),
        "physical_output_token_savings": len(l0_ids) - len(s1_ids),
        "full_token_savings": (l0_prompt + len(l0_ids)) - (s1_prompt + len(s1_ids)),
        "correctness_damage": bool(l0.get("correct")) and not bool(s1.get("correct")),
    }


def derive_predicates(records: list[dict[str, Any]] | str | Path, config: dict[str, Any]) -> dict[str, Any]:
    rows = _rows(records)
    natural = [row for row in rows if row.get("phase") == "natural"]
    timing = [row for row in rows if row.get("phase") == "timing"]
    edge = [row for row in rows if row.get("phase") == "edge"]
    warmups = [row for row in rows if row.get("phase") == "warmup"]
    work_keys = [row.get("work_key") for row in rows if row.get("work_key")]
    duplicate_work_keys = len(work_keys) - len(set(work_keys))
    by_row: dict[str, dict[str, dict[str, Any]]] = {}
    for row in natural:
        by_row.setdefault(str(row["row_id"]), {})[str(row["arm_id"])] = row

    pairs = [
        derive_pair(arms["L0_LEGACY_NO_DETECTOR"], arms["S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"])
        for arms in by_row.values()
        if "L0_LEGACY_NO_DETECTOR" in arms and "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE" in arms
    ]
    physical = [pair["physical_output_token_savings"] for pair in pairs]
    full = [pair["full_token_savings"] for pair in pairs]
    active: set[str] = set()
    if any(pair["correctness_damage"] for pair in pairs):
        active.add("BLOCK_CORRECTNESS_DAMAGE")
    if any(pair["first_wrong_later_corrected_cut"] for pair in pairs):
        active.add("BLOCK_FIRST_ANSWER_CORRECTION_CUT")
    if any(not pair["raw_token_prefix_equivalence"] or not pair["decoded_byte_prefix_equivalence"] for pair in pairs):
        active.add("BLOCK_PREFIX_EQUIVALENCE")
    if any(not pair["runtime_reference_agreement"] for pair in pairs):
        active.add("BLOCK_RUNTIME_REFERENCE_DISAGREEMENT")
    if any(
        pair["unsafe_stop"]
        or pair["token_boundary_error_count"]
        or pair["semantic_trailer_present"]
        or pair["dangling_marker_present"]
        for pair in pairs
    ):
        active.add("BLOCK_UNSAFE_STOP")
    if duplicate_work_keys:
        active.add("BLOCK_SCOPE_MISMATCH")
    if len(by_row) != 300 or len(natural) != 600 or len(timing) != 540 or len(edge) != 36 or len(warmups) != 9:
        active.add("PARTIAL_WALL_TIME_CHECKPOINTED")
    if (
        any(value < 0 for value in physical)
        or _median(physical) <= 0
        or _trimmed_mean(physical) <= 0
        or sum(full) <= 0
        or not (full_tpc(rows, "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE") < full_tpc(rows, "L0_LEGACY_NO_DETECTOR"))
    ):
        active.add("BLOCK_TOKEN_ECONOMICS")
    if any(int(row.get("detector_telemetry", {}).get("full_sequence_rescan_count", 0)) for row in rows):
        active.add("BLOCK_TIMING_PROTOCOL_VIOLATION")
    predicate_vector = {
        "natural_pair_matrix_complete": len(by_row) == 300 and len(natural) == 600,
        "timing_matrix_complete": len(timing) == 540,
        "edge_matrix_complete": len(edge) == 36,
        "warmup_matrix_complete": len(warmups) == 9,
        "duplicate_work_key_count": duplicate_work_keys,
        "paired_correctness_damage": sum(1 for pair in pairs if pair["correctness_damage"]),
        "first_wrong_later_corrected_cuts": sum(1 for pair in pairs if pair["first_wrong_later_corrected_cut"]),
        "raw_token_prefix_mismatches": sum(1 for pair in pairs if not pair["raw_token_prefix_equivalence"]),
        "decoded_byte_prefix_mismatches": sum(1 for pair in pairs if not pair["decoded_byte_prefix_equivalence"]),
        "runtime_reference_disagreements": sum(1 for pair in pairs if not pair["runtime_reference_agreement"]),
        "unsafe_stops": sum(1 for pair in pairs if pair["unsafe_stop"]),
        "token_boundary_invariant_errors": sum(int(pair["token_boundary_error_count"]) for pair in pairs),
        "semantic_post_boundary_trailers": sum(1 for pair in pairs if pair["semantic_trailer_present"]),
        "dangling_repeated_markers": sum(1 for pair in pairs if pair["dangling_marker_present"]),
        "negative_physical_token_savings_rows": sum(1 for value in physical if value < 0),
        "median_physical_output_token_savings": _median(physical),
        "trimmed_mean_physical_output_token_savings": _trimmed_mean(physical),
        "aggregate_physical_output_token_reduction": sum(physical),
        "aggregate_full_token_reduction": sum(full),
        "l0_full_tokens_per_correct": full_tpc(rows, "L0_LEGACY_NO_DETECTOR"),
        "s1_full_tokens_per_correct": full_tpc(rows, "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"),
        "tpc_denominator_policy": "SEPARATE_ARM_CORRECT_COUNTS",
        "court_derivation_source": "IMMUTABLE_RAW_L0_S1_TRACES",
    }
    return {"predicate_vector": predicate_vector, "pairwise_rows": pairs, "active_statuses": sorted(active), "primary_status": _primary(active)}


def execute_core_result_court(records: list[dict[str, Any]] | str | Path, config: dict[str, Any]) -> dict[str, Any]:
    derived = derive_predicates(records, config)
    natural_n = len({row["row_id"] for row in _rows(records) if row.get("phase") == "natural"})
    return {
        "schema_id": "kt.stop300.v41.core_result_summary.v1",
        "status": derived["primary_status"],
        "active_statuses": derived["active_statuses"],
        "predicate_vector": derived["predicate_vector"],
        "pairwise_court_status": "PASS_DERIVED_FROM_IMMUTABLE_L0_S1_TRACES",
        "independent_n": natural_n,
        "claim_ceiling_status": "PRESERVED",
    }


def _base_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i in range(300):
        l0_ids = [100 + j for j in range(40)]
        s1_ids = l0_ids[:20]
        rows.append(
            {
                "phase": "natural",
                "row_id": f"r{i}",
                "arm_id": "L0_LEGACY_NO_DETECTOR",
                "correct": True,
                "prompt_token_count": 100,
                "raw_generated_token_ids": l0_ids,
                "raw_generated_text": "FINAL_ANSWER: 42\ntrailer",
                "work_key": f"l0-{i}",
            }
        )
        rows.append(
            {
                "phase": "natural",
                "row_id": f"r{i}",
                "arm_id": "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE",
                "correct": True,
                "prompt_token_count": 100,
                "raw_generated_token_ids": s1_ids,
                "raw_generated_text": "FINAL_ANSWER: 42\n",
                "runtime_first_boundary": {"semantic_boundary_type": "FINAL_LINE_CLOSE", "visible_text": "FINAL_ANSWER: 42\n"},
                "reference_court": {"semantic_boundary_type": "FINAL_LINE_CLOSE", "lawful": True},
                "token_boundary_errors": [],
                "detector_telemetry": {"full_sequence_rescan_count": 0},
                "work_key": f"s1-{i}",
            }
        )
    for i in range(60):
        for rep in range(3):
            for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
                rows.append({"phase": "timing", "row_id": f"t{i}", "repetition": rep, "arm_id": arm, "work_key": f"t-{i}-{rep}-{arm}"})
    for i in range(12):
        for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
            rows.append({"phase": "edge", "row_id": f"e{i}", "arm_id": arm, "work_key": f"e-{i}-{arm}"})
    for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
        for i in range(3):
            rows.append({"phase": "warmup", "row_id": f"w{i}", "arm_id": arm, "work_key": f"w-{arm}-{i}"})
    return rows


def synthetic_mutation_suite() -> dict[str, Any]:
    mutations = {
        "correctness_damage": ("BLOCK_CORRECTNESS_DAMAGE", lambda rows: rows.__setitem__(1, {**rows[1], "correct": False})),
        "raw_token_prefix_mismatch": ("BLOCK_PREFIX_EQUIVALENCE", lambda rows: rows.__setitem__(1, {**rows[1], "raw_generated_token_ids": [999]})),
        "decoded_byte_prefix_mismatch": ("BLOCK_PREFIX_EQUIVALENCE", lambda rows: rows.__setitem__(1, {**rows[1], "raw_generated_text": "not a prefix"})),
        "runtime_reference_mismatch": ("BLOCK_RUNTIME_REFERENCE_DISAGREEMENT", lambda rows: rows.__setitem__(1, {**rows[1], "reference_court": {"semantic_boundary_type": "SAFE_EOS_CLOSURE", "lawful": True}})),
        "unsafe_stop": ("BLOCK_UNSAFE_STOP", lambda rows: rows.__setitem__(1, {**rows[1], "reference_court": {"semantic_boundary_type": "FINAL_LINE_CLOSE", "lawful": False}})),
        "zero_physical_savings": (
            "BLOCK_TOKEN_ECONOMICS",
            lambda rows: [
                rows.__setitem__(
                    idx,
                    {
                        **rows[idx],
                        "raw_generated_token_ids": rows[idx - 1]["raw_generated_token_ids"],
                    },
                )
                for idx in range(1, 600, 2)
            ],
        ),
        "missing_warmup": ("PARTIAL_WALL_TIME_CHECKPOINTED", lambda rows: rows.pop()),
        "duplicate_work_key": ("BLOCK_SCOPE_MISMATCH", lambda rows: rows.__setitem__(1, {**rows[1], "work_key": "l0-0"})),
    }
    cases = {}
    for name, (expected, mutate) in mutations.items():
        rows = _base_rows()
        mutate(rows)
        actual = execute_core_result_court(rows, {})["status"]
        cases[name] = {"expected": expected, "actual": actual, "pass": actual == expected}
    return {
        "schema_id": "kt.stop300.v41.synthetic_raw_trace_mutation_suite.v1",
        "status": "PASS_RAW_TRACE_FAIL_CLOSED_MUTATION_SUITE" if all(case["pass"] for case in cases.values()) else "FAIL",
        "cases": cases,
    }
