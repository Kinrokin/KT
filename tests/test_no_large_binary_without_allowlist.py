from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PREFIXES = ("packets/", "KT_PROD_CLEANROOM/reports/")
ALLOWLIST_FILES = {"registry/artifact_authority_registry.json"}


def test_large_binaries_are_allowlisted_or_pointer_classified() -> None:
    report = json.loads((ROOT / "reports/repo_large_file_index_v1.json").read_text(encoding="utf-8"))
    offenders = []
    for row in report["rows"]:
        if row["size_bytes"] < 5_000_000:
            continue
        if row["path"] in ALLOWLIST_FILES:
            continue
        if row["primary_class"] in {"HEAVY_ARTIFACT_POINTER", "ARCHIVE_HISTORY", "CANONICAL_PACKET_CURRENT"}:
            continue
        if row["path"].startswith(ALLOWLIST_PREFIXES):
            continue
        offenders.append(row["path"])

    assert offenders == []
