import json
from pathlib import Path

ROOT = Path.cwd()


def test_oracle_conversion_rate_matches_v15_delta():
    obj = json.loads((ROOT / "reports/oracle_conversion_rate_scorecard.json").read_text(encoding="utf-8"))
    assert obj["base_raw_correct"] == 143
    assert obj["feature_bound_route_correct"] == 159
    assert obj["oracle_correct"] == 187
    assert round(obj["oracle_conversion_rate"], 6) == round(16 / 44, 6)
