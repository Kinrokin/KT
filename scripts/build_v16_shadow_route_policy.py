from __future__ import annotations

from v16_crossroad_shadow_common import build_policy, load_v15, repo_root, write_json


def main() -> int:
    root = repo_root()
    policy, provenance, importance, receipt = build_policy(load_v15(root))
    write_json(root / "admission/v16_shadow_route_policy.json", policy)
    write_json(root / "admission/v16_route_value_feature_provenance.json", provenance)
    write_json(root / "reports/v16_feature_importance.json", importance)
    write_json(root / "reports/v16_shadow_policy_build_receipt.json", receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
