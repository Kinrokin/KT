from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_no_duplicate_current_authority() -> None:
    census = json.loads((ROOT / "reports/repo_pristine_census_v1.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "registry/artifact_authority_registry.json").read_text(encoding="utf-8"))

    assert census["duplicate_current_authority_status"] == "PASS"
    current_packets = [
        artifact["path"]
        for artifact in registry["artifacts"]
        if artifact["primary_class"] == "CANONICAL_PACKET_CURRENT"
    ]
    assert current_packets == ["packets/ktbud100_v1.zip"]
