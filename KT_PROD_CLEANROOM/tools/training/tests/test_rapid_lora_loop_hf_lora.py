from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

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
    env["KT_SEAL_MODE"] = "1"
    return env


def test_rapid_lora_loop_hf_lora_creates_pass_manifest(tmp_path: Path) -> None:
    transformers = pytest.importorskip("transformers")
    torch = pytest.importorskip("torch")
    _ = pytest.importorskip("peft")

    repo_root = Path(__file__).resolve().parents[4]
    env = _py_env(repo_root)

    # Minimal local base model dir (no network).
    from transformers import GPT2Config, GPT2LMHeadModel

    model_dir = (tmp_path / "base_model").resolve()
    cfg = GPT2Config(vocab_size=64, n_positions=32, n_ctx=32, n_embd=32, n_layer=1, n_head=1)
    model = GPT2LMHeadModel(cfg)
    model.save_pretrained(model_dir, safe_serialization=True)

    # Minimal dataset dir.
    ds_dir = (tmp_path / "ds").resolve()
    ds_dir.mkdir(parents=True, exist_ok=True)
    (ds_dir / "ds.jsonl").write_text(json.dumps({"text": "hello"}, sort_keys=True) + "\n", encoding="utf-8")

    # Minimal config (seeded; deterministic).
    cfg_path = (tmp_path / "cfg.json").resolve()
    cfg_obj = {
        "job_id": "test_hf_lora",
        "adapter_id": "adapter.test",
        "seed": 1,
        "training_mode": "lora",
        "max_steps": 1,
        "batch_size": 1,
        "seq_len": 8,
        "lr": 0.001,
        "lora_rank": 4,
    }
    cfg_path.write_text(json.dumps(cfg_obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    out_parent = write_root(repo_root=repo_root) / "rapid_lora_loop_hf_lora"
    out_parent.mkdir(parents=True, exist_ok=True)
    out_dir = out_parent / f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"

    p = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.training.rapid_lora_loop",
            "--dataset",
            str(ds_dir),
            "--config",
            str(cfg_path),
            "--engine",
            "hf_lora",
            "--enable-real-engine",
            "--base-model-dir",
            str(model_dir),
            "--out-dir",
            str(out_dir),
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 0, p.stdout + "\n" + p.stderr
    assert (out_dir / "training_run_manifest.PASS.json").exists()
    assert (out_dir / "adapter_artifact.zip").exists()
