from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


SUITE_PATHS = [
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/tests/test_paradox_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/tests/test_temporal_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/tests/test_multiverse_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/tests/test_council_router.py",
]


def build_wave2c_independent_suite_report(*, root: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(root / "KT_PROD_CLEANROOM")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    coverage_dir = (root / "KT_PROD_CLEANROOM" / "reports" / ".wave_coverage").resolve()
    coverage_dir.mkdir(parents=True, exist_ok=True)
    env["COVERAGE_FILE"] = str((coverage_dir / f"wave2c_organ_contract_suite.{os.getpid()}.coverage").resolve())
    cmd = ["python", "-m", "pytest", "-p", "pytest_cov.plugin", "-q", *SUITE_PATHS]
    proc = subprocess.run(cmd, cwd=str(root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = proc.stdout or ""
    return {
        "schema_id": "kt.wave2c.independent_organ_test_suites.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if int(proc.returncode) == 0 else "FAIL",
        "scope_boundary": "Wave 2C independent organ suites prove deterministic organ behavior before any broader runtime promotion or router cutover is considered.",
        "command": " ".join(cmd),
        "suite_paths": SUITE_PATHS,
        "output_tail": output.strip().splitlines()[-20:],
        "stronger_claim_not_made": [
            "learned_router_cutover_occurred",
            "tournament_or_product_widening_occurred",
            "broad_externality_widened",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Wave 2C independent organ contract suites.")
    parser.add_argument("--output", default="KT_PROD_CLEANROOM/reports/kt_wave2c_independent_organ_test_suites.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    out_path = Path(str(args.output)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    report = build_wave2c_independent_suite_report(root=root)
    write_json_stable(out_path, report)
    print(json.dumps({"status": report["status"], "suite_paths": report["suite_paths"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
