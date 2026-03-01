from __future__ import annotations

from pathlib import Path

from tools.verification.validate_council_packet_v1 import main


def test_validate_council_packet_v1_passes(tmp_path: Path) -> None:
    assert main(["--out-dir", str(tmp_path)]) == 0

