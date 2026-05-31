from __future__ import annotations

import json

from v16_crossroad_shadow_common import build_policy, load_v15, repo_root, scan_oracle_leakage, write_json


def main() -> int:
    root = repo_root()
    v15 = load_v15(root)
    policy_path = root / "admission/v16_shadow_route_policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8")) if policy_path.exists() else build_policy(v15)[0]
    receipt = scan_oracle_leakage(policy, v15["route_rows"])
    write_json(root / "reports/v16_oracle_leakage_scan.json", receipt)
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
