from __future__ import annotations

import json
from pathlib import Path

from accountability_common import repo_root


REQUIRED = [
    "accountability/accountability_kernel_receipt.json",
    "accountability/failure_confession_receipt.json",
    "accountability/success_admissibility_receipt.json",
    "accountability/self_deception_risk_scorecard.json",
    "reports/formal_math_specialist_router_plan.json",
    "reports/adapter_ecological_niche_registry.json",
    "reports/kt_fmea_repair_bid_matrix.json",
    "packets/ktg3full_v12.zip",
]


def main() -> int:
    root = repo_root()
    missing = [path for path in REQUIRED if not (root / path).exists()]
    kernel = json.loads((root / "accountability/accountability_kernel_receipt.json").read_text(encoding="utf-8-sig")) if not missing else {}
    failures = []
    if missing:
        failures.append({"missing": missing})
    if kernel and not kernel.get("claim_ceiling_preserved"):
        failures.append({"claim_ceiling_preserved": False})
    print(json.dumps({"schema_id": "kt.accountability_gate_result.v1", "status": "PASS" if not failures else "FAIL", "failures": failures}, indent=2, sort_keys=True))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
