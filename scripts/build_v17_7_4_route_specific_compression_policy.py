from __future__ import annotations

from collections import defaultdict
from typing import Any


def build_route_specific_compression_policy(arm_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        by_sample[str(row["sample_id"])].append(row)
    rows = []
    oracle_correct = 0
    oracle_tokens = 0
    stable_correct = 0
    stable_tokens = 0
    for sample_id, sample_rows in sorted(by_sample.items()):
        stable = next((row for row in sample_rows if row.get("arm_id") == "A_true_known_good_math_act_byte_repro"), sample_rows[0])
        correct = [row for row in sample_rows if row.get("correct") is True]
        oracle = sorted(correct or sample_rows, key=lambda row: (-int(bool(row.get("correct"))), int(row.get("total_tokens", 10**9)), str(row.get("arm_id"))))[0]
        oracle_correct += int(bool(oracle.get("correct")))
        oracle_tokens += int(oracle.get("total_tokens", 0))
        stable_correct += int(bool(stable.get("correct")))
        stable_tokens += int(stable.get("total_tokens", 0))
        rows.append(
            {
                "sample_id": sample_id,
                "stable_control_arm": stable.get("arm_id"),
                "teacher_oracle_arm": oracle.get("arm_id"),
                "teacher_oracle_correct": bool(oracle.get("correct")),
                "teacher_oracle_tokens": int(oracle.get("total_tokens", 0)),
                "stable_control_correct": bool(stable.get("correct")),
                "stable_control_tokens": int(stable.get("total_tokens", 0)),
                "oracle_correctness_used_as_runtime_feature": False,
                "runtime_admissible": False,
            }
        )
    return {
        "schema_id": "kt.v17_7_4.route_specific_compression_policy.v1",
        "status": "PASS_CANDIDATE_ONLY",
        "row_count": len(rows),
        "rows": rows,
        "stable_correct": stable_correct,
        "stable_tokens_per_correct": stable_tokens / stable_correct if stable_correct else None,
        "oracle_mix_correct": oracle_correct,
        "oracle_mix_tokens_per_correct": oracle_tokens / oracle_correct if oracle_correct else None,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
    }


__all__ = ["build_route_specific_compression_policy"]
