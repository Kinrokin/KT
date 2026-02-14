from __future__ import annotations

from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.fl3_canonical import sha256_json, sha256_text  # noqa: E402
from tools.verification.run_protocol_generator import (  # noqa: E402
    build_run_protocol,
    render_run_protocol_markdown,
    verify_run_protocol_pair,
    write_run_protocol_pair,
)
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402


def test_build_run_protocol_hash_surfaces() -> None:
    payload = {
        "run_id": "RUN_001",
        "lane_id": "FL4_SEAL",
        "timestamp_utc": "2026-02-14T00:00:00Z",
        "determinism_mode": "STRICT",
        "execution_environment_hash": "1" * 64,
        "governed_phase_start_hash": "2" * 64,
        "io_guard_status": "GUARDED",
        "base_model_id": "mistral-7b",
        "active_adapters": [{"adapter_id": "lobe.architect.v1", "adapter_hash": "3" * 64}],
        "active_laws": ["LAW_A", "LAW_B"],
        "datasets": [{"relpath": "job_dir/dataset.json", "sha256": "4" * 64}],
        "replay_command": "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json",
        "replay_script_hash": "5" * 64,
        "secret_scan_result": "PASS",
        "bundle_root_hash": "6" * 64,
    }
    obj = build_run_protocol(payload)
    markdown = render_run_protocol_markdown(obj)

    assert obj["run_protocol_md_hash"] == sha256_text(markdown)
    assert obj["run_protocol_json_hash"] == sha256_json({k: v for k, v in obj.items() if k != "run_protocol_json_hash"})


def test_write_and_verify_protocol_pair(tmp_path: Path) -> None:
    payload = {
        "run_id": "RUN_002",
        "lane_id": "FL4_SEAL",
        "timestamp_utc": "2026-02-14T00:00:00Z",
        "determinism_mode": "STRICT",
        "execution_environment_hash": "7" * 64,
        "governed_phase_start_hash": "8" * 64,
        "io_guard_status": "GUARDED",
        "base_model_id": "mistral-7b",
        "active_adapters": [{"adapter_id": "lobe.critic.v1", "adapter_hash": "9" * 64}],
        "replay_command": "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json",
        "replay_script_hash": "a" * 64,
        "secret_scan_result": "PASS",
        "bundle_root_hash": "b" * 64,
    }
    obj = build_run_protocol(payload)
    json_path, md_path = write_run_protocol_pair(out_dir=tmp_path, protocol=obj)
    assert json_path.exists()
    assert md_path.exists()
    verified = verify_run_protocol_pair(json_path=json_path, md_path=md_path)
    assert verified["run_id"] == "RUN_002"


def test_run_protocol_id_stable_across_builds() -> None:
    payload = {
        "run_id": "RUN_STABLE",
        "lane_id": "FL4_SEAL",
        "created_at": "2026-02-14T00:00:00Z",
        "timestamp_utc": "2026-02-14T00:00:00Z",
        "determinism_mode": "STRICT",
        "execution_environment_hash": "c" * 64,
        "governed_phase_start_hash": "d" * 64,
        "io_guard_status": "GUARDED",
        "base_model_id": "mistral-7b",
        "active_adapters": [{"adapter_id": "lobe.scout.v1", "adapter_hash": "e" * 64}],
        "active_laws": ["LAW_A"],
        "datasets": [{"relpath": "job_dir/dataset.json", "sha256": "f" * 64}],
        "replay_command": "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json",
        "replay_script_hash": "1" * 64,
        "secret_scan_result": "PASS",
        "bundle_root_hash": "2" * 64,
    }

    a = build_run_protocol(payload)
    b = build_run_protocol(payload)

    assert a["run_protocol_id"] == b["run_protocol_id"]
    assert a["run_protocol_json_hash"] == b["run_protocol_json_hash"]
    assert a["run_protocol_md_hash"] == b["run_protocol_md_hash"]


def test_run_protocol_pair_write_noops_if_identical(tmp_path: Path) -> None:
    payload = {
        "run_id": "RUN_003",
        "lane_id": "FL4_SEAL",
        "timestamp_utc": "2026-02-14T00:00:00Z",
        "determinism_mode": "STRICT",
        "execution_environment_hash": "7" * 64,
        "governed_phase_start_hash": "8" * 64,
        "io_guard_status": "GUARDED",
        "base_model_id": "mistral-7b",
        "active_adapters": [{"adapter_id": "lobe.muse.v1", "adapter_hash": "9" * 64}],
        "replay_command": "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json",
        "replay_script_hash": "a" * 64,
        "secret_scan_result": "PASS",
        "bundle_root_hash": "b" * 64,
    }
    obj = build_run_protocol(payload)
    write_run_protocol_pair(out_dir=tmp_path, protocol=obj)
    # Second identical write must no-op (WORM semantics without punishing deterministic reruns).
    write_run_protocol_pair(out_dir=tmp_path, protocol=obj)


def test_run_protocol_pair_write_fails_closed_on_mismatch(tmp_path: Path) -> None:
    payload = {
        "run_id": "RUN_004",
        "lane_id": "FL4_SEAL",
        "timestamp_utc": "2026-02-14T00:00:00Z",
        "determinism_mode": "STRICT",
        "execution_environment_hash": "c" * 64,
        "governed_phase_start_hash": "d" * 64,
        "io_guard_status": "GUARDED",
        "base_model_id": "mistral-7b",
        "active_adapters": [{"adapter_id": "lobe.muse.v1", "adapter_hash": "e" * 64}],
        "replay_command": "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json",
        "replay_script_hash": "f" * 64,
        "secret_scan_result": "PASS",
        "bundle_root_hash": "1" * 64,
    }
    obj1 = build_run_protocol(payload)
    write_run_protocol_pair(out_dir=tmp_path, protocol=obj1)

    payload2 = dict(payload)
    payload2["base_model_id"] = "mistral-7b-CHANGED"
    obj2 = build_run_protocol(payload2)
    try:
        write_run_protocol_pair(out_dir=tmp_path, protocol=obj2)
        assert False, "expected FAIL_CLOSED"
    except FL3ValidationError:
        pass
