from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compression_frontier_packet_is_distinct_from_loadfix_packet() -> None:
    packet = ROOT / "packets" / "ktv1774_compression_frontier_v1.zip"
    assert packet.exists()
    assert packet.stat().st_size < 750_000
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("run_manifest.json").decode("utf-8"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))
    assert manifest["run_mode"] == "RUN_KTV1774_COMPRESSION_FRONTIER_TRUEGEN_MINIFURNACE"
    assert manifest["compression_frontier_gate_required"] is True
    assert len(config["arms"]) >= 8
    assert "KT_V1774_TRUEGEN_ARM_CORE.py" in names
    assert not any(name.endswith((".safetensors", ".bin", ".pt")) or "cache" in name.lower() for name in names)


def test_hf_vault_memory_packet_carries_safe_execution_contract() -> None:
    packet = ROOT / "packets" / "ktv1774_hf_vault_memory_v1.zip"
    assert packet.exists()
    assert packet.stat().st_size < 750_000
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("run_manifest.json").decode("utf-8"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))
    assert manifest["run_mode"] == "RUN_KTV1774_COMPRESSION_FRONTIER_TRUEGEN_MINIFURNACE"
    assert manifest["hf_vault_source_of_truth"] is True
    assert manifest["arm_isolation_mode"] == "ARM_MAJOR_UNLOAD_AFTER_EACH_ARM"
    assert manifest["default_row_ladder_stage"] == 3
    assert manifest["partial_output_rescue_required"] is True
    assert config["adapter_source_preference"] == "HF_VAULT_FIRST"
    assert config["default_row_ladder_stage"] == 3
    assert all(arm["max_new_tokens"] <= 64 for arm in config["arms"])
    assert not any(name.endswith((".safetensors", ".bin", ".pt")) or "cache" in name.lower() for name in names)
