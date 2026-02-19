from __future__ import annotations

import json
import os
import subprocess
import hashlib
from pathlib import Path


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parents[3]


def _base_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_tree(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[p.relative_to(root).as_posix()] = _sha256_file(p)
    return out


def test_rapid_lora_loop_stub_engine_smoke(tmp_path: Path) -> None:
    repo_root = _repo_root()
    env = _base_env(repo_root)

    dataset_path = tmp_path / "ds.jsonl"
    dataset_path.write_text("{\"text\":\"hello\"}\n", encoding="utf-8")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps({"job_id": "job_test_001", "seed": 1}), encoding="utf-8")

    out_root = repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "_TEST_RAPID_LORA"
    out_root.mkdir(parents=True, exist_ok=True)
    out_dir = out_root / f"stub_{os.getpid()}"
    if out_dir.exists():
        # Best-effort cleanup (test-only under exports/_runs/_TEST_*).
        for p in sorted(out_dir.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink()
            elif p.is_dir():
                try:
                    p.rmdir()
                except OSError:
                    pass
        try:
            out_dir.rmdir()
        except OSError:
            pass

    cmd = [
        "python",
        "-m",
        "tools.training.rapid_lora_loop",
        "--dataset",
        str(dataset_path),
        "--config",
        str(cfg_path),
        "--engine",
        "stub",
        "--out-dir",
        str(out_dir),
    ]
    p = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p.returncode == 0, p.stdout
    assert (out_dir / "verdict.txt").exists()
    assert (out_dir / "training_run_manifest.PASS.json").exists()


def test_rapid_lora_loop_stub_engine_rerun_is_noop_verify(tmp_path: Path) -> None:
    repo_root = _repo_root()
    env = _base_env(repo_root)

    dataset_path = tmp_path / "ds.jsonl"
    dataset_path.write_text("{\"text\":\"hello\"}\n", encoding="utf-8")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps({"job_id": "job_test_002", "seed": 2}), encoding="utf-8")

    out_root = repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "_TEST_RAPID_LORA"
    out_root.mkdir(parents=True, exist_ok=True)
    out_dir = out_root / f"stub_verify_{os.getpid()}"
    if out_dir.exists():
        for p in sorted(out_dir.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink()
            elif p.is_dir():
                try:
                    p.rmdir()
                except OSError:
                    pass
        try:
            out_dir.rmdir()
        except OSError:
            pass

    cmd = [
        "python",
        "-m",
        "tools.training.rapid_lora_loop",
        "--dataset",
        str(dataset_path),
        "--config",
        str(cfg_path),
        "--engine",
        "stub",
        "--out-dir",
        str(out_dir),
    ]

    p1 = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p1.returncode == 0, p1.stdout
    before = _hash_tree(out_dir)
    assert "verdict.txt" in before
    assert "hashes.txt" in before

    p2 = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p2.returncode == 0, p2.stdout
    assert "cmd=verify" in p2.stdout
    assert "noop=1" in p2.stdout

    after = _hash_tree(out_dir)
    assert after == before
