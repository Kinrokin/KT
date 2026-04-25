from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


PYPROJECT_REL = "KT_PROD_CLEANROOM/pyproject.toml"
LOCKFILE_REL = "KT_PROD_CLEANROOM/requirements-wave0.lock.txt"
PYTEST_REL = "KT_PROD_CLEANROOM/pytest.ini"
WORKFLOW_REL = ".github/workflows/ci_truth_barrier.yml"


def build_wave1_ci_reproducibility_strategy_receipt(*, root: Path) -> Dict[str, Any]:
    pyproject = root / PYPROJECT_REL
    lockfile = root / LOCKFILE_REL
    pytest_ini = root / PYTEST_REL
    workflow = root / WORKFLOW_REL

    lock_text = lockfile.read_text(encoding="utf-8") if lockfile.exists() else ""
    workflow_text = workflow.read_text(encoding="utf-8") if workflow.exists() else ""
    pyproject_text = pyproject.read_text(encoding="utf-8") if pyproject.exists() else ""

    hash_lines = [line for line in lock_text.splitlines() if "--hash=sha256:" in line]
    uses_require_hashes = "--require-hashes -r KT_PROD_CLEANROOM/requirements-wave0.lock.txt" in workflow_text
    mentions_pip_compile = "pip-compile" in lock_text
    no_bazel = not any((root / name).exists() for name in ("WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"))
    no_primary_nix = not any((root / name).exists() for name in ("flake.nix", "shell.nix", "default.nix"))
    no_alt_language_bootstrap = "cargo build" not in workflow_text and "go build" not in workflow_text
    pyproject_present = pyproject.exists() and "[project]" in pyproject_text
    pytest_present = pytest_ini.exists() and "[pytest]" in pytest_ini.read_text(encoding="utf-8")

    checks = [
        {"check": "pyproject_manifest_present", "status": "PASS" if pyproject_present else "FAIL", "ref": PYPROJECT_REL},
        {"check": "hashed_lockfile_present", "status": "PASS" if bool(hash_lines) and mentions_pip_compile else "FAIL", "ref": LOCKFILE_REL},
        {"check": "pytest_baseline_present", "status": "PASS" if pytest_present else "FAIL", "ref": PYTEST_REL},
        {"check": "ci_uses_require_hashes_lockfile", "status": "PASS" if uses_require_hashes else "FAIL", "ref": WORKFLOW_REL},
        {"check": "no_bazel_primary_bootstrap", "status": "PASS" if no_bazel else "FAIL", "ref": "."},
        {"check": "no_nix_primary_bootstrap", "status": "PASS" if no_primary_nix else "FAIL", "ref": "."},
        {"check": "no_new_language_build_bootstrap", "status": "PASS" if no_alt_language_bootstrap else "FAIL", "ref": WORKFLOW_REL},
    ]
    failures = [row["check"] for row in checks if row["status"] != "PASS"]

    return {
        "schema_id": "kt.wave1.ci_reproducibility_strategy_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "local_dev_primary": "pip_compile_exact_hash_lockfile",
        "ci_strategy": "lockfile_require_hashes_with_optional_future_nix_not_active_now",
        "checks": checks,
        "hash_line_count": len(hash_lines),
        "stronger_claim_not_made": [
            "repo_root_import_fragility_closed",
            "cross_environment_runtime_reproducibility_widened_by_wave1",
            "bazel_or_new_language_bootstrap_required",
        ],
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the narrow Wave 1 CI/local reproducibility strategy.")
    parser.add_argument("--output", default="KT_PROD_CLEANROOM/reports/kt_wave1_ci_reproducibility_strategy_receipt.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report = build_wave1_ci_reproducibility_strategy_receipt(root=root)
    out_path = Path(str(args.output)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    write_json_stable(out_path, report)
    print(json.dumps({"status": report["status"], "failures": report["failures"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
