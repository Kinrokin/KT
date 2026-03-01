from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from schemas.fl3_suite_definition_schema import validate_fl3_suite_definition
from tools.suites.generate_metamorphic_variants import MetamorphicSpec, generate_metamorphic_suite
from tools.verification.seal_mode_test_roots import group_root, unique_run_dir


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parents[3]


def test_generate_metamorphic_suite_is_deterministic_and_schema_valid() -> None:
    repo_root = _repo_root()
    base_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_FORMAT_CONTROL.v1.json"
    base = json.loads(base_path.read_text(encoding="utf-8"))
    validate_fl3_suite_definition(base)

    spec = MetamorphicSpec(
        seed=123,
        variants_per_case=2,
        transforms=("whitespace", "punctuation", "format", "order"),
        counterpressure_level="mild",
    )
    out1 = generate_metamorphic_suite(base_suite=base, spec=spec, allow_sensitive_prompts=False)
    out2 = generate_metamorphic_suite(base_suite=base, spec=spec, allow_sensitive_prompts=False)
    assert out1["suite_definition_id"] == out2["suite_definition_id"]
    assert out1["cases"] == out2["cases"]
    validate_fl3_suite_definition(out1)


def test_generate_metamorphic_variants_cli_emits_manifest_and_hashes() -> None:
    repo_root = _repo_root()
    base_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_FORMAT_CONTROL.v1.json"
    out_root = group_root(repo_root=repo_root, group="SUITE_PACK")
    out_root.mkdir(parents=True, exist_ok=True)
    out_dir = unique_run_dir(parent=out_root, label=f"meta_{os.getpid()}")

    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    cmd = [
        "python",
        "-m",
        "tools.suites.generate_metamorphic_variants",
        "--in-suite",
        str(base_path),
        "--out-dir",
        str(out_dir),
        "--seed",
        "123",
        "--variants-per-case",
        "1",
        "--transforms",
        "whitespace,punctuation",
    ]
    p1 = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p1.returncode == 0, p1.stdout
    assert (out_dir / "verdict.txt").exists()
    assert (out_dir / "manifest.json").exists()
    assert (out_dir / "hashes.txt").exists()
    assert (out_dir / "suite_metamorphic.v1.json").exists()
    assert (out_dir / "case_lineage.jsonl").exists()

    # Second run into same out_dir must fail-closed (WORM collision).
    p2 = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p2.returncode != 0
    assert "FAIL_CLOSED" in (p2.stdout or "")
