from __future__ import annotations

import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_stop50_generation_config_is_singular_effective_runtime_receipt() -> None:
    with zipfile.ZipFile(ROOT / "packets/ktstop50_v1.zip") as zf:
        source = zf.read("runtime/effective_config_receipt.py").decode("utf-8-sig")
    assert "PASS_SINGULAR_EFFECTIVE_GENERATION_CONFIG_BOUND" in source
    assert "runtime_bitsandbytes_config_allowed" in source
    assert "False" in source
