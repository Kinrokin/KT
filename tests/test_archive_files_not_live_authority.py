from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_archive_files_do_not_control_execution() -> None:
    registry = json.loads((ROOT / "registry/artifact_authority_registry.json").read_text(encoding="utf-8"))
    offenders = [
        artifact["path"]
        for artifact in registry["artifacts"]
        if artifact["primary_class"] == "ARCHIVE_HISTORY" and artifact["controls_execution"]
    ]

    assert offenders == []
