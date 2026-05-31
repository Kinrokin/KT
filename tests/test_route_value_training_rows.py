import json
from pathlib import Path

ROOT = Path.cwd()


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_route_value_rows_are_not_adapter_training_rows():
    rows = read_jsonl("admission/route_value_training_rows.jsonl")
    kinds = {row["preference_kind"] for row in rows}
    assert {"oracle_rescue", "base_preservation"} <= kinds
    assert all(row["runtime_legal_features_only"] is True for row in rows)
    assert all(row["oracle_correctness_used_as_feature"] is False for row in rows)
    assert all(row["adapter_training_forbidden"] is True for row in rows)
    assert all(row["claim_authority"] == "NONE" for row in rows)
