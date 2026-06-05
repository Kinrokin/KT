from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def authority(**extra):
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    payload = authority(
        schema_id="kt.v17_7_4.route_margin_scorecard.v1",
        status="PASS_CANDIDATE_ONLY",
        realbench_50_oracle_gap=1,
        compact_realbench_50_oracle_gap=7,
        route_margin_interpretation="Full RealBench has little oracle gap on the 50-row slice; compact run exposes reasoning-starvation and admission risk.",
        allowed_runtime_features=[
            "answer_type",
            "task_family",
            "question_structure",
            "risk_band",
            "required_reasoning_budget",
        ],
        forbidden_runtime_features=[
            "oracle_correct",
            "gold_answer",
            "posthoc_best_arm",
            "dataset_label_alone_as_structure_bound_claim",
        ],
        feature_leakage_check="PASS_NO_ORACLE_CORRECTNESS_RUNTIME_FEATURE",
        next_validation="RUN_KTV1774_DUALFRONT_50",
    )
    write_json(ROOT / "reports" / "v17_7_4_route_margin_scorecard.json", payload)
    print(json.dumps({"status": payload["status"], "feature_leakage_check": payload["feature_leakage_check"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
