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


def test_suite_fitness_regions(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    unique = f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base = write_root(repo_root=repo_root) / "suite_fitness" / unique
    base.mkdir(parents=True, exist_ok=False)

    def _write_eval(path: Path, *, passed: int, total: int) -> None:
        rows = [{"case_id": f"C{i:03d}", "passed": (i < passed)} for i in range(total)]
        obj = {
            "schema_id": "kt.suite_eval_report.v1",
            "suite_eval_report_id": "EVAL_TEST",
            "suite_definition_id": "SUITE_TEST",
            "case_results": rows,
        }
        path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = _py_env(repo_root)

    eval_easy = base / "easy.json"
    _write_eval(eval_easy, passed=99, total=100)
    out_easy = base / "out_easy"
    p1 = subprocess.run(
        ["python", "-m", "tools.suites.compute_suite_fitness", "--suite-eval-report", str(eval_easy), "--out-dir", str(out_easy)],
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert p1.returncode == 0, p1.stdout
    rec1 = json.loads((out_easy / "suite_fitness_record.json").read_text(encoding="utf-8"))
    assert rec1.get("region") == "C"
    assert rec1.get("recommended_action") == "ESCALATE_OR_MUTATE"

    eval_ok = base / "ok.json"
    _write_eval(eval_ok, passed=65, total=100)
    out_ok = base / "out_ok"
    p2 = subprocess.run(
        ["python", "-m", "tools.suites.compute_suite_fitness", "--suite-eval-report", str(eval_ok), "--out-dir", str(out_ok)],
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert p2.returncode == 0, p2.stdout
    rec2 = json.loads((out_ok / "suite_fitness_record.json").read_text(encoding="utf-8"))
    assert rec2.get("region") == "A"
