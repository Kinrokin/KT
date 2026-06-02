from __future__ import annotations

import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_new_packet_does_not_emit_config_bound_success() -> None:
    packet = ROOT / "packets" / "ktv1774_truegen_e2e_v1.zip"
    with zipfile.ZipFile(packet) as archive:
        text = "\n".join(
            archive.read(name).decode("utf-8", errors="ignore")
            for name in archive.namelist()
            if name.endswith((".py", ".json", ".md"))
        )
    assert '"status": "CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE"' not in text
    assert "status='CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE'" not in text
    assert "status=CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE" not in text
    assert "FRESH_MODEL_GENERATION" in text
    assert "MODEL_GENERATED_AND_SCORED" in text
