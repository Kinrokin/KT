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


def test_feedback_engine_emits_proposals(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    unique = f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    base = write_root(repo_root=repo_root) / "titan_feedback" / unique
    run_root = base / "run"
    out_dir = base / "out"
    run_root.mkdir(parents=True, exist_ok=False)

    # Minimal evidence files (safe, schema-lite).
    (run_root / "suite_fitness_record.json").write_text(
        json.dumps({"schema_id": "kt.suite_fitness_record.v1", "region": "C", "pass_rate": 0.99}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_root / "mve_drift_report.json").write_text(
        json.dumps({"schema_id": "kt.mve_drift_report.v1", "terminal": True, "violations": []}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_root / "mve_capture_resistance_report.json").write_text(
        json.dumps({"schema_id": "kt.mve_capture_resistance_report.v1", "status": "FAIL"}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_root / "multiversal_fitness.json").write_text(
        json.dumps(
            {
                "schema_id": "kt.multiversal_fitness_record.v1",
                "world_fitness": [{"world_id": "WORLD_EU_STRICT_HEALTH", "region": "C"}],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    env = _py_env(repo_root)
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.feedback.titan_feedback_engine",
            "--run-root",
            str(run_root),
            "--out-dir",
            str(out_dir),
            "--seed",
            "0",
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert p.returncode == 0, p.stdout
    manifest = json.loads((out_dir / "proposal_manifest.json").read_text(encoding="utf-8"))
    assert int(manifest.get("proposal_count", 0)) >= 3
    assert (out_dir / "operator_review_checklist.md").is_file()
