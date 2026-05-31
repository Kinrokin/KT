import json
from pathlib import Path

ROOT = Path.cwd()


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_oracle_winner_attribution_covers_gap_rows():
    gaps = read_jsonl("admission/oracle_gap_matrix.jsonl")
    rows = read_jsonl("admission/oracle_winner_attribution.jsonl")
    assert len(rows) == len(gaps)
    assert {row["rescuer_family"] for row in rows} >= {"base", "hat", "formal_math", "route_regret", "math_act"}
