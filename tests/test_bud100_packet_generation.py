from __future__ import annotations

import zipfile
from pathlib import Path

from scripts import ktbud100_common as bud


def test_bud100_packet_generation_shape_and_sha() -> None:
    summary = bud.build_all()
    packet = Path(summary["packet_path_if_any"])

    assert summary["bud100_packet_generation_status"] == "GENERATED"
    assert packet.exists()
    assert bud.sha256_file(packet) == summary["packet_sha256_if_any"]

    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
    assert "runtime/KT_CANONICAL_RUNNER.py" in names
    assert "KAGGLE_BOOTSTRAP_CELL.py" in names
    assert "PACKET_MANIFEST.json" in names
    assert "SHA256_MANIFEST.json" in names
    assert "row_manifest.json" in names
