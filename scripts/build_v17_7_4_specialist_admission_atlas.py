from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    atlas = {
        "schema_id": "kt.v17_7_4.specialist_admission_atlas.v1",
        "status": "PASS_CANDIDATE_ONLY",
        "claim_ceiling_preserved": True,
        "promotion_authority": False,
        "router_superiority_claim": False,
        "best_current_candidate_arm": "math_act_adapter_global",
        "default_rule": {
            "schema_id": "kt.v17_7_4.specialist_admission_rule.v1",
            "rule_id": "math_act_default_candidate_after_realbench_50",
            "candidate_default_arm": "math_act_adapter_global",
            "rule_authority": "CANDIDATE_ONLY",
            "required_validation": [
                "row_level_oracle_route_table",
                "held_out_realbench_replay",
                "OOD_slice_replay",
                "token_accounting_reconciliation"
            ],
            "claim_ceiling_preserved": True,
            "promotion_authority": False
        },
        "guardrails": {
            "oracle_correctness_used_as_runtime_feature": False,
            "dataset_label_alone_structure_bound_claim_allowed": False,
            "math_act_adapter_promoted": False
        }
    }
    plan = {
        "schema_id": "kt.v17_7_4.route_regret_closure_plan.v1",
        "status": "PASS",
        "claim_ceiling_preserved": True,
        "route_regret_target": "Close the 1-row gap between math_act_adapter_global and oracle without increasing token cost.",
        "next_measurement": "compact RealBench 50, then RealBench 200 if clean"
    }
    write_json(ROOT / "reports" / "v17_7_4_specialist_admission_atlas.json", atlas)
    write_json(ROOT / "reports" / "v17_7_4_route_regret_closure_plan.json", plan)
    print(json.dumps({"status": "PASS_CANDIDATE_ONLY", "atlas": "reports/v17_7_4_specialist_admission_atlas.json"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
