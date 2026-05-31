from __future__ import annotations

import json

from v17_canary_coalition_common import V17_FORBIDDEN_RUNTIME_FEATURES, read_json, repo_root


def main() -> int:
    root = repo_root()
    failures: list[str] = []
    for rel_path in [
        "admission/v17_canary_policy_config.json",
        "admission/v17_runtime_feature_contract.json",
        "admission/v17_route_value_feature_contract.json",
    ]:
        data = read_json(root / rel_path)
        allowed = data.get("allowed_runtime_features", []) + data.get("allowed_source_feature_families", [])
        for feature in allowed:
            if feature in V17_FORBIDDEN_RUNTIME_FEATURES:
                failures.append(f"{rel_path}: {feature}")
    result = {"schema_id": "kt.v17_forbidden_runtime_feature_scan.v1", "failures": failures, "status": "PASS" if not failures else "FAIL"}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
