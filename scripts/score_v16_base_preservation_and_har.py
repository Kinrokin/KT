from __future__ import annotations

import json

from v16_crossroad_shadow_common import repo_root, write_json


def main() -> int:
    root = repo_root()
    scorecard = json.loads((root / "reports/v16_shadow_replay_scorecard.json").read_text(encoding="utf-8"))
    write_json(
        root / "reports/v16_base_preservation_receipt.json",
        {
            "schema_id": "kt.v16_base_preservation.v1",
            "base_preservation_rate": scorecard["base_preservation_rate"],
            "minimum_required": 0.95,
            "status": "PASS" if scorecard["base_preservation_rate"] >= 0.95 else "FAIL",
        },
    )
    write_json(
        root / "reports/v16_harmful_activation_receipt.json",
        {
            "schema_id": "kt.v16_harmful_activation_receipt.v1",
            "harmful_activation_rate": scorecard["harmful_activation_rate"],
            "maximum_allowed": 0.10,
            "status": "PASS" if scorecard["harmful_activation_rate"] <= 0.10 else "FAIL",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
