from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def authority(**extra: Any) -> dict[str, Any]:
    payload = {
        "claim_ceiling_preserved": True,
        "promotion_authority": False,
        "runtime_authority": False,
        "oracle_correctness_used_as_runtime_feature": False,
        "learned_router_superiority_claim": False,
    }
    payload.update(extra)
    return payload


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def build(input_path: Path | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if input_path is None or not input_path.exists():
        return [], authority(
            schema_id="kt.v17_7_4.oracle_route_table_receipt.v1",
            status="BLOCKED",
            outcome="KT_BLOCKED__ROW_LEVEL_REALBENCH_ASSESSMENT_MISSING",
            reason="Provide truegen_arm_result_matrix.jsonl to build row-level oracle route table.",
        )
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(input_path):
        by_sample[row["sample_id"]].append(row)
    rows = []
    for sample_id, arm_rows in sorted(by_sample.items()):
        best = sorted(arm_rows, key=lambda row: (-float(row.get("score", 0)), int(row.get("total_tokens", 10**9)), row["arm_id"]))[0]
        base = next((row for row in arm_rows if row["arm_id"] == "base_raw"), arm_rows[0])
        chosen = next((row for row in arm_rows if row["arm_id"] == "math_act_adapter_global"), best)
        rows.append(
            authority(
                schema_id="kt.v17_7_4.oracle_route_row.v1",
                sample_id=sample_id,
                dataset=best.get("dataset"),
                task_family=best.get("task_family"),
                answer_type=best.get("answer_type", ""),
                pre_generation_features={},
                chosen_arm=chosen["arm_id"],
                best_arm=best["arm_id"],
                oracle_arm=best["arm_id"],
                oracle_correct=bool(best.get("correct")),
                chosen_correct=bool(chosen.get("correct")),
                route_regret=max(float(best.get("score", 0)) - float(chosen.get("score", 0)), 0.0),
                token_regret=max(int(chosen.get("total_tokens", 0)) - int(best.get("total_tokens", 0)), 0),
                latency_regret=max(int(chosen.get("latency_ms", 0)) - int(best.get("latency_ms", 0)), 0),
                base_raw_correct=bool(base.get("correct")),
                admission_rule_candidate="math_act_default_candidate_unless_feature_gate_disagrees",
            )
        )
    return rows, authority(
        schema_id="kt.v17_7_4.oracle_route_table_receipt.v1",
        status="PASS",
        outcome="ORACLE_ROUTE_TABLE_BUILT_FROM_ROW_LEVEL_ASSESSMENT",
        input_path=input_path.as_posix(),
        row_count=len(rows),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    args = parser.parse_args()
    rows, receipt = build(args.input)
    write_jsonl(ROOT / "reports" / "v17_7_4_oracle_route_table.jsonl", rows)
    write_json(ROOT / "reports" / "v17_7_4_oracle_route_table_receipt.json", receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
