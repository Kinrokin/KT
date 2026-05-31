from __future__ import annotations

import json

from v16_crossroad_shadow_common import load_v15, repo_root, write_json


def main() -> int:
    root = repo_root()
    v15 = load_v15(root)
    scorecard = json.loads((root / "reports/v16_shadow_replay_scorecard.json").read_text(encoding="utf-8"))
    write_json(
        root / "reports/v16_oracle_conversion_rate_scorecard.json",
        {
            "schema_id": "kt.v16_oracle_conversion_rate_scorecard.v1",
            "baseline_ocr": v15["baseline_ocr"],
            "oracle_conversion_rate": scorecard["oracle_conversion_rate"],
            "ocr_improved": scorecard["oracle_conversion_rate"] > v15["baseline_ocr"],
            "acceptable": scorecard["oracle_conversion_rate"] >= 0.50,
            "breakthrough": scorecard["oracle_conversion_rate"] >= 0.70,
            "status": "PASS" if scorecard["oracle_conversion_rate"] > v15["baseline_ocr"] else "FAIL",
        },
    )
    write_json(
        root / "reports/v16_route_regret_closure_scorecard.json",
        {
            "schema_id": "kt.v16_route_regret_closure_scorecard.v1",
            "route_regret_closure": scorecard["route_regret_closure"],
            "acceptable": scorecard["route_regret_closure"] >= 0.30,
            "strong": scorecard["route_regret_closure"] >= 0.50,
            "excellent": scorecard["route_regret_closure"] >= 0.70,
            "status": "PASS" if scorecard["route_regret_closure"] >= 0.30 else "FAIL",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
