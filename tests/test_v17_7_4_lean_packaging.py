from __future__ import annotations

import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_truegen_packet_is_lean_and_contains_no_weights_or_caches() -> None:
    packet = ROOT / "packets" / "ktv1774_truegen_e2e_v1.zip"
    assert packet.stat().st_size < 500_000
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
    assert {
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py",
        "KT_V1774_TRUEGEN_ARM_CORE.py",
        "runtime_inputs/truegen_row_manifest.json",
        "runtime_inputs/arm_model_config.example.json",
        "run_manifest.json",
    }.issubset(names)
    assert not any(name.endswith((".safetensors", ".bin", ".pt")) or "cache" in name.lower() for name in names)
