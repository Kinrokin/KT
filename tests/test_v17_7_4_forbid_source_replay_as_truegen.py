from __future__ import annotations

import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_new_packet_forbids_source_route_replay_as_terminal_truegen_authority() -> None:
    packet = ROOT / "packets" / "ktv1774_truegen_e2e_v1.zip"
    with zipfile.ZipFile(packet) as archive:
        core = archive.read("KT_V1774_TRUEGEN_ARM_CORE.py").decode("utf-8")
    forbidden_set_section = core.split("FORBIDDEN_SUCCESS_STATUSES", 1)[1].split("FRESH_SOURCE", 1)[0]
    assert "SOURCE_ROUTE_OUTCOME_REPLAY" in forbidden_set_section
    assert 'FRESH_SOURCE = "FRESH_MODEL_GENERATION"' in core
