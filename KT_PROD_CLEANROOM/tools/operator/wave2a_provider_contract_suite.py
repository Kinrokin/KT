from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


SUITE_PATHS = [
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_provider_adapters.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_provider_resilience.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_wave2a_adapter_activation.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/tests/test_council_live_hashed.py",
]


def build_wave2a_provider_contract_suite_report(*, root: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(root / "KT_PROD_CLEANROOM")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    coverage_dir = (root / "KT_PROD_CLEANROOM" / "reports" / ".wave_coverage").resolve()
    coverage_dir.mkdir(parents=True, exist_ok=True)
    env["COVERAGE_FILE"] = str((coverage_dir / "wave2a_provider_contract_suite.coverage").resolve())
    cmd = ["python", "-m", "pytest", "-p", "pytest_cov", "-q", *SUITE_PATHS]
    proc = subprocess.run(cmd, cwd=str(root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = proc.stdout or ""
    return {
        "schema_id": "kt.wave2a.provider_contract_test_suite.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if int(proc.returncode) == 0 else "FAIL",
        "scope_boundary": "Wave 2A provider contract suite proves ABI loading, live-hashed bounded failure, and live-lane resilience without opening router elevation or organ realization.",
        "command": " ".join(cmd),
        "suite_paths": SUITE_PATHS,
        "output_tail": output.strip().splitlines()[-20:],
        "stronger_claim_not_made": [
            "semantic_router_elevation_occurred",
            "organ_realization_occurred",
            "product_language_widened",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Wave 2A provider contract suite and emit a machine-readable receipt.")
    parser.add_argument("--output", default="KT_PROD_CLEANROOM/reports/kt_wave2a_provider_contract_test_suite.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report = build_wave2a_provider_contract_suite_report(root=root)
    out_path = Path(str(args.output)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    write_json_stable(out_path, report)
    print(json.dumps({"status": report["status"], "suite_paths": report["suite_paths"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
