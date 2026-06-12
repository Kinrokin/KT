from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_no_unregistered_controlling_artifacts() -> None:
    report = read_json("reports/repo_unregistered_controlling_artifact_index_v1.json")

    assert report["status"] == "PASS"
    assert report["unregistered_count"] == 0
