from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
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
    # Seal-mode policy_c uses tmp roots; ensure temp dirs exist.
    tmp = str((repo_root / "tmp").resolve())
    env.setdefault("TMPDIR", tmp)
    env.setdefault("TMP", tmp)
    env.setdefault("TEMP", tmp)
    return env


def test_books_runner_canonize_only_writes_final_reports(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    base = write_root(repo_root=repo_root) / "books_runner" / f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base.mkdir(parents=True, exist_ok=False)

    suite_dir = tmp_path / "suite"
    suite_dir.mkdir(parents=True, exist_ok=False)
    books_dir = suite_dir / "books"
    books_dir.mkdir(parents=True, exist_ok=False)

    b0 = books_dir / "b0.md"
    b0.write_text("# B0\n\n```python\nimport os\n```\n", encoding="utf-8")
    b1 = books_dir / "b1.md"
    b1.write_text("# B1\n\n```python\nimport json\n```\n", encoding="utf-8")

    manifest = {
        "schema_id": "kt.operator.golden_notebook_suite_manifest.v1",
        "suite_id": "TEST",
        "version": "1.0.0",
        "books": [
            {"book_id": "00", "name": "B0", "notebook_plan_path": str(b0.as_posix()), "exec": []},
            {"book_id": "01", "name": "B1", "notebook_plan_path": str(b1.as_posix()), "exec": []},
        ],
    }
    man_path = suite_dir / "NOTEBOOK_SUITE_MANIFEST.v1.json"
    man_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = _py_env(repo_root)
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.books_runner",
            "--profile",
            "v1",
            "--allow-dirty",
            "--run-root",
            str(base),
            "--suite-manifest",
            str(man_path),
            "--book-set",
            "00,01",
            "--mode",
            "canonize_only",
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 0, p.stdout + "\n" + p.stderr

    final_path = base / "FINAL_REPORT.json"
    assert final_path.exists()
    rep = json.loads(final_path.read_text(encoding="utf-8"))
    assert rep.get("status") == "PASS"

    book0 = base / "books" / "book_00" / "FINAL_REPORT.json"
    book1 = base / "books" / "book_01" / "FINAL_REPORT.json"
    assert book0.exists()
    assert book1.exists()
