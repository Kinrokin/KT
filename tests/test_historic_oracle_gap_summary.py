import json
from pathlib import Path

ROOT = Path.cwd()


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_historic_oracle_gap_trend_includes_v15_and_prior_runs():
    rows = read_jsonl("admission/all_historic_oracle_gap_matrix.jsonl")
    runs = {row["run"] for row in rows}
    assert {"G2_v2", "G3FULL_v14", "G3FULL_v15"} <= runs
    trend = json.loads((ROOT / "reports/historic_oracle_gap_trend.json").read_text(encoding="utf-8"))
    assert trend["persistent_oracle_gap_present"] is True
