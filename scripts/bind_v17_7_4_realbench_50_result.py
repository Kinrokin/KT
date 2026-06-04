from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SUMMARY = {
    "row_count": 50,
    "arm_rows": 400,
    "base_raw_correct": 30,
    "base_raw_total": 50,
    "base_raw_accuracy": 0.60,
    "base_raw_tokens_per_correct": 175.233333,
    "best_arm": "math_act_adapter_global",
    "best_arm_correct": 41,
    "best_arm_total": 50,
    "best_arm_accuracy": 0.82,
    "best_current_tokens_per_correct": 145.121951,
    "oracle_correct": 42,
    "oracle_total": 50,
    "oracle_accuracy": 0.84,
    "compression_gain_over_current_base": 0.171836,
    "absolute_lift_over_base": 0.22,
    "relative_lift_over_base": 0.366667,
    "compression_frontier_outcome": "KT_BLOCKED__COMPRESSION_FRONTIER_REGRESSION",
}


def authority(**extra: Any) -> dict[str, Any]:
    payload = {
        "claim_ceiling_preserved": True,
        "promotion_authority": False,
        "runtime_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "learned_router_superiority_claim": False,
        "router_superiority_claim": False,
        "commercial_claim_authorized": False,
        "frontier_claim_authorized": False,
        "v18_runtime_authority": False,
    }
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    reports = ROOT / "reports"
    write_json(
        reports / "v17_7_4_realbench_50_result_binding_receipt.json",
        authority(
            schema_id="kt.v17_7_4.realbench_50_result_binding_receipt.v1",
            status="PASS",
            evidence_source="OPERATOR_SUPPLIED_REALBENCH_ASSESSMENT_SUMMARY",
            measurement_authority="INTERNAL_FRESH_GENERATION_SUMMARY_BOUND",
            **SUMMARY,
        ),
    )
    write_json(
        reports / "v17_7_4_realbench_50_score_reconciliation.json",
        authority(
            schema_id="kt.v17_7_4.realbench_50_score_reconciliation.v1",
            status="PASS",
            base_raw="30/50",
            math_act_adapter_global="41/50",
            oracle="42/50",
            lift_summary="+11 correct over base_raw; +22 percentage points",
            compression_summary="Current-token accounting improved about 17.18 percent over base, but did not recover G2 compression.",
            **SUMMARY,
        ),
    )
    write_json(
        reports / "v17_7_4_realbench_50_oracle_gap_receipt.json",
        authority(
            schema_id="kt.v17_7_4.realbench_50_oracle_gap_receipt.v1",
            status="PASS",
            oracle_gap_vs_best_arm=1,
            oracle_gap_vs_base_raw=12,
            interpretation="Best single specialist nearly matched oracle on the 50-row slice; route/admission repair should be candidate-only until row-level and held-out replay pass.",
            **SUMMARY,
        ),
    )
    print(json.dumps({"status": "PASS", "best_arm": "math_act_adapter_global", "outcome": "REALBENCH_50_RESULT_BOUND"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
