from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.verification.seal_mode_test_roots import write_root


def _run(cmd: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, env=env)


def _py_env(repo_root: Path) -> dict[str, str]:
    env = dict(**__import__("os").environ)
    env["PYTHONPATH"] = f"{repo_root/'KT_PROD_CLEANROOM'/'04_PROD_TEMPLE_V2'/'src'};{repo_root/'KT_PROD_CLEANROOM'}"
    return env


def test_mve_runner_determinism_same_seed(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    base = write_root(repo_root=repo_root) / "mve_runner_determinism" / "same_seed" / tmp_path.name
    out1 = base / "run1"
    out2 = base / "run2"
    out1.mkdir(parents=True, exist_ok=False)
    out2.mkdir(parents=True, exist_ok=False)

    pack = repo_root / "KT-Codex" / "packs" / "KT_CORE_PRESSURE_PACK_v1" / "pack_manifest.json"
    env = _py_env(repo_root)
    law = "cd593dee1cc0b4c30273c90331124c3686f510ff990005609b3653268e66d906"

    r1 = _run(
        [
            "python",
            "-m",
            "tools.eval.mve_runner",
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
        env=env,
    )
    assert r1.returncode == 0, r1.stderr

    r2 = _run(
        [
            "python",
            "-m",
            "tools.eval.mve_runner",
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
        env=env,
    )
    assert r2.returncode == 0, r2.stderr

    m1 = json.loads((out1 / "mve" / "mve_sha256_manifest.json").read_text(encoding="utf-8"))
    m2 = json.loads((out2 / "mve" / "mve_sha256_manifest.json").read_text(encoding="utf-8"))
    assert m1 == m2


def test_mve_runner_determinism_diff_seed_changes_manifest(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    base = write_root(repo_root=repo_root) / "mve_runner_determinism" / "diff_seed" / tmp_path.name
    out1 = base / "seed1"
    out2 = base / "seed2"
    out1.mkdir(parents=True, exist_ok=False)
    out2.mkdir(parents=True, exist_ok=False)

    pack = repo_root / "KT-Codex" / "packs" / "KT_CORE_PRESSURE_PACK_v1" / "pack_manifest.json"
    env = _py_env(repo_root)
    law = "cd593dee1cc0b4c30273c90331124c3686f510ff990005609b3653268e66d906"

    r1 = _run(
        [
            "python",
            "-m",
            "tools.eval.mve_runner",
            "--pack-manifest",
            str(pack),
            "--adapter-id",
            "ADAPTER_TEST_V1",
            "--seed",
            "1",
            "--law-bundle-hash-in-force",
            law,
            "--out-dir",
            str(out1),
        ],
        env=env,
    )
    assert r1.returncode == 0, r1.stderr

    r2 = _run(
        [
            "python",
            "-m",
            "tools.eval.mve_runner",
            "--pack-manifest",
            str(pack),
            "--adapter-id",
            "ADAPTER_TEST_V1",
            "--seed",
            "2",
            "--law-bundle-hash-in-force",
            law,
            "--out-dir",
            str(out2),
        ],
        env=env,
    )
    assert r2.returncode == 0, r2.stderr

    m1 = json.loads((out1 / "mve" / "mve_sha256_manifest.json").read_text(encoding="utf-8"))
    m2 = json.loads((out2 / "mve" / "mve_sha256_manifest.json").read_text(encoding="utf-8"))
    assert m1 != m2
