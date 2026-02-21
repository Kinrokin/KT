from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from tools.verification.seal_mode_test_roots import write_root


def _py_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{repo_root/'KT_PROD_CLEANROOM'/'04_PROD_TEMPLE_V2'/'src'};{repo_root/'KT_PROD_CLEANROOM'}"
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)


def test_notebook_canonize_md_extracts_cells_and_imports(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    unique = f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base = write_root(repo_root=repo_root) / "golden_notebooks" / "canonize" / unique
    base.mkdir(parents=True, exist_ok=False)

    nb = base / "nb.md"
    nb.write_text(
        "# Notebook Plan\n\n```python\nimport os\nfrom pathlib import Path\n```\n\n```python\nimport json\n```\n",
        encoding="utf-8",
    )

    out_dir = base / "out"
    env = _py_env(repo_root)
    p = _run(
        ["python", "-m", "tools.notebooks.notebook_canonize", "--notebook", str(nb), "--out-dir", str(out_dir)],
        cwd=repo_root,
        env=env,
    )
    assert p.returncode == 0, p.stderr
    manifest = json.loads((out_dir / "notebook_manifest.json").read_text(encoding="utf-8"))
    assert manifest.get("cell_count") == 2
    imports = set(manifest.get("imports") or [])
    assert {"os", "pathlib", "json"} <= imports


def test_replay_manifest_verify_reports_divergence(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    unique = f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base = write_root(repo_root=repo_root) / "golden_notebooks" / "replay_verify" / unique
    root = base / "root"
    root.mkdir(parents=True, exist_ok=False)

    f = root / "a.txt"
    f.write_text("hello\n", encoding="utf-8")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    manifest = {"a.txt": sha}
    manifest_path = base / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = _py_env(repo_root)
    out1 = base / "div1.json"
    p1 = _run(
        ["python", "-m", "tools.verification.replay_manifest_verify", "--manifest", str(manifest_path), "--root", str(root), "--out", str(out1)],
        cwd=repo_root,
        env=env,
    )
    assert p1.returncode == 0, p1.stderr
    rep1 = json.loads(out1.read_text(encoding="utf-8"))
    assert rep1.get("status") == "PASS"

    # Mutate file, expect FAIL.
    f.write_text("goodbye\n", encoding="utf-8")
    out2 = base / "div2.json"
    p2 = _run(
        ["python", "-m", "tools.verification.replay_manifest_verify", "--manifest", str(manifest_path), "--root", str(root), "--out", str(out2)],
        cwd=repo_root,
        env=env,
    )
    assert p2.returncode != 0
    rep2 = json.loads(out2.read_text(encoding="utf-8"))
    assert rep2.get("status") == "FAIL"
    assert rep2.get("hash_mismatches")

