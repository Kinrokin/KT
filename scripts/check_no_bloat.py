from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def main() -> int:
    census = read_json("reports/repo_pristine_census_v1.json")
    path_risks = read_json("reports/repo_path_length_risk_index_v1.json")
    if census.get("duplicate_current_authority_status") != "PASS":
        raise SystemExit("duplicate current authority blocker")
    if path_risks.get("blocker_count", 0) != 0:
        raise SystemExit("path length blocker")
    print(json.dumps({"schema_id": "kt.no_bloat_check.v1", "status": "PASS"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
