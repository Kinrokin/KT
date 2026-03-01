from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from tools.verification.seal_mode_test_roots import write_root


def _py_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"),
            str(repo_root / "KT_PROD_CLEANROOM"),
        ]
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)


def _law_hash(repo_root: Path) -> str:
    return (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").read_text(encoding="utf-8").strip()


def test_mve1_runner_determinism_same_seed(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    unique = f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base = write_root(repo_root=repo_root) / "titan_mve1" / "determinism_same_seed" / unique
    out1 = base / "run1"
    out2 = base / "run2"
    out1.mkdir(parents=True, exist_ok=False)
    out2.mkdir(parents=True, exist_ok=False)

    pack = repo_root / "KT-Codex" / "packs" / "KT_CORE_PRESSURE_PACK_v1" / "pack_manifest.json"
    law = _law_hash(repo_root)
    env = _py_env(repo_root)

    r1 = _run(
        [
            "python",
            "-m",
            "tools.eval.mve_runner",
            "--mode",
            "mve1",
            "--pack-manifest",
            str(pack),
            "--adapter-id",
            "ADAPTER_TEST_V1",
            "--seed",
            "123",
            "--law-bundle-hash-in-force",
            law,
            "--out-dir",
            str(out1),
        ],
        cwd=repo_root,
        env=env,
    )
    assert r1.returncode == 0, r1.stderr

    r2 = _run(
        [
            "python",
            "-m",
            "tools.eval.mve_runner",
            "--mode",
            "mve1",
            "--pack-manifest",
            str(pack),
            "--adapter-id",
            "ADAPTER_TEST_V1",
            "--seed",
            "123",
            "--law-bundle-hash-in-force",
            law,
            "--out-dir",
            str(out2),
        ],
        cwd=repo_root,
        env=env,
    )
    assert r2.returncode == 0, r2.stderr

    m1 = json.loads((out1 / "mve" / "mve_sha256_manifest.json").read_text(encoding="utf-8"))
    m2 = json.loads((out2 / "mve" / "mve_sha256_manifest.json").read_text(encoding="utf-8"))
    assert m1 == m2
    assert (out1 / "mve" / "mve_drift_report.json").is_file()
    assert (out1 / "mve" / "mve_capture_resistance_report.json").is_file()


def test_temporal_fitness_ledger_blocks_regression(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    unique = f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base = write_root(repo_root=repo_root) / "titan_mve1" / "temporal_gate" / unique
    base.mkdir(parents=True, exist_ok=False)

    ledger_root = base / "ledger_root"
    fitness1_path = base / "fitness1.json"
    fitness2_path = base / "fitness2.json"

    worlds = ["WORLD_EU_STRICT_HEALTH", "WORLD_US_COMMERCIAL", "WORLD_ACADEMIC_OPEN"]

    fitness1 = {
        "schema_id": "kt.multiversal_fitness_record.v1",
        "artifact_id": "ADAPTER_TEMPORAL_TEST",
        "timestamp": "1970-01-01T00:00:00Z",
        "world_fitness": [{"world_id": wid, "region": "A"} for wid in worlds],
        "temporal_lineage": [{"world_id": wid, "epoch": 0, "region": "A"} for wid in worlds],
        "promotion_blocked": False,
        "block_reason_code": "OK",
        "determinism_fingerprint": "0" * 64,
    }
    fitness2 = {
        **fitness1,
        "world_fitness": [{"world_id": worlds[0], "region": "B"}] + [{"world_id": wid, "region": "A"} for wid in worlds[1:]],
        "temporal_lineage": [{"world_id": worlds[0], "epoch": 1, "region": "B"}] + [{"world_id": wid, "epoch": 0, "region": "A"} for wid in worlds[1:]],
        "promotion_blocked": False,
        "block_reason_code": "OK",
        "determinism_fingerprint": "1" * 64,
    }

    fitness1_path.write_text(json.dumps(fitness1, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fitness2_path.write_text(json.dumps(fitness2, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = _py_env(repo_root)

    out1 = base / "out1"
    p1 = _run(
        [
            "python",
            "-m",
            "tools.eval.temporal_fitness_ledger",
            "--fitness-record",
            str(fitness1_path),
            "--run-id",
            "RUN_1",
            "--out-dir",
            str(out1),
            "--ledger-root",
            str(ledger_root),
        ],
        cwd=repo_root,
        env=env,
    )
    assert p1.returncode == 0, p1.stderr
    assert (out1 / "temporal_fitness_gate.json").is_file()

    out2 = base / "out2"
    p2 = _run(
        [
            "python",
            "-m",
            "tools.eval.temporal_fitness_ledger",
            "--fitness-record",
            str(fitness2_path),
            "--run-id",
            "RUN_2",
            "--out-dir",
            str(out2),
            "--ledger-root",
            str(ledger_root),
        ],
        cwd=repo_root,
        env=env,
    )
    assert p2.returncode != 0
    gate2 = json.loads((out2 / "temporal_fitness_gate.json").read_text(encoding="utf-8"))
    assert gate2.get("promotion_blocked") is True
    assert worlds[0] in (gate2.get("regressed_world_ids") or [])


def test_titan_promotion_gate_smoke(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    unique = f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base = write_root(repo_root=repo_root) / "titan_mve1" / "promotion_gate" / unique
    out_dir = base / "mve_run"
    out_dir.mkdir(parents=True, exist_ok=False)

    pack = repo_root / "KT-Codex" / "packs" / "KT_CORE_PRESSURE_PACK_v1" / "pack_manifest.json"
    law = _law_hash(repo_root)
    env = _py_env(repo_root)

    r = _run(
        [
            "python",
            "-m",
            "tools.eval.mve_runner",
            "--mode",
            "mve1",
            "--pack-manifest",
            str(pack),
            "--adapter-id",
            "ADAPTER_TEST_V1",
            "--seed",
            "7",
            "--law-bundle-hash-in-force",
            law,
            "--out-dir",
            str(out_dir),
        ],
        cwd=repo_root,
        env=env,
    )
    assert r.returncode == 0, r.stderr

    temporal_out = base / "temporal"
    ledger_root = base / "ledger"
    p_temporal = _run(
        [
            "python",
            "-m",
            "tools.eval.temporal_fitness_ledger",
            "--fitness-record",
            str(out_dir / "mve" / "multiversal_fitness.json"),
            "--run-id",
            "RUN_SMOKE",
            "--out-dir",
            str(temporal_out),
            "--ledger-root",
            str(ledger_root),
        ],
        cwd=repo_root,
        env=env,
    )
    assert p_temporal.returncode == 0, p_temporal.stderr

    gate_out = base / "gate"
    p_gate = _run(
        [
            "python",
            "-m",
            "tools.eval.titan_promotion_gate",
            "--mve-dir",
            str(out_dir / "mve"),
            "--temporal-gate",
            str(temporal_out / "temporal_fitness_gate.json"),
            "--run-id",
            "RUN_SMOKE",
            "--out-dir",
            str(gate_out),
        ],
        cwd=repo_root,
        env=env,
    )
    assert p_gate.returncode == 0, p_gate.stderr
    assert (gate_out / "titan_promotion_gate.json").is_file()
    assert (gate_out / "promotion_dependency_graph.json").is_file()
