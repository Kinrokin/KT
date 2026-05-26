from __future__ import annotations

import json

from accountability_common import build_specialist_routing, repo_root


if __name__ == "__main__":
    result = build_specialist_routing(repo_root())
    print(
        json.dumps(
            {
                "bench_status": "SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED",
                "router_contract": result["router_contract"],
                "isolation": result["isolation"],
            },
            indent=2,
            sort_keys=True,
        )
    )
