from __future__ import annotations

import zipfile
import json
from pathlib import Path

from scripts import ktbud100_common as bud


def test_bud100_packet_generation_shape_and_sha() -> None:
    decision = bud.read_json(bud.REPORTS / "bud100_packet_decision.json")
    packet = Path(decision["packet_path"])

    assert decision["status"] == "GENERATED"
    assert packet.exists()
    assert bud.sha256_file(packet) == decision["packet_sha256"]

    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
        sha_manifest = json.loads(zf.read("SHA256_MANIFEST.json"))
        row_manifest = json.loads(zf.read("row_manifest.json"))
    assert "runtime/KT_CANONICAL_RUNNER.py" in names
    assert "KAGGLE_BOOTSTRAP_CELL.py" in names
    assert "PACKET_MANIFEST.json" in names
    assert "SHA256_MANIFEST.json" in names
    assert "row_manifest.json" in names
    assert "packet_sha256" not in sha_manifest
    assert sha_manifest["packet_sha256_authority"] == "reports/bud100_packet_decision.json"
    assert row_manifest["source"] == "openai/gsm8k:test[25:125]"
    assert row_manifest["overlap_with_bud25"] is False
