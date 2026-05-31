from __future__ import annotations

import json

from v16_crossroad_shadow_common import build_policy, load_v15, replay_policy, repo_root, write_json, write_jsonl


def main() -> int:
    root = repo_root()
    v15 = load_v15(root)
    policy_path = root / "admission/v16_shadow_route_policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8")) if policy_path.exists() else build_policy(v15)[0]
    replay = replay_policy(v15, policy)
    write_jsonl(root / "admission/v16_shadow_route_replay_predictions.jsonl", replay["predictions"])
    write_jsonl(root / "admission/v16_route_value_decisions.jsonl", replay["route_decisions"])
    write_jsonl(root / "admission/v16_policy_vs_oracle_matrix.jsonl", replay["policy_vs_oracle"])
    write_jsonl(root / "admission/v16_policy_vs_feature_route_matrix.jsonl", replay["policy_vs_feature"])
    write_jsonl(root / "admission/v16_policy_vs_best_static_adapter_matrix.jsonl", replay["policy_vs_best_static"])
    write_json(root / "reports/v16_shadow_replay_scorecard.json", replay["scorecard"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
