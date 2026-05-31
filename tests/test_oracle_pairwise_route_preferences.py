import json
from pathlib import Path

ROOT = Path.cwd()


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_pairwise_preferences_are_shadow_only_and_oracle_labeled():
    rows = read_jsonl("admission/oracle_pairwise_route_preferences.jsonl")
    assert len(rows) == 28
    assert all(row["winner"] == "route_a" for row in rows)
    assert all(row["adapter_training_forbidden"] is True for row in rows)
    assert all(row["promotion_authority"] is False for row in rows)
    assert all(row["oracle_correctness_used_as_feature"] is False for row in rows)
