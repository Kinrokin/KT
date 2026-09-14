from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GROWTH_ROOTS = (
    "KT_PROD_CLEANROOM/tools/growth/artifacts/",
    "KT_PROD_CLEANROOM/tools/growth/ledgers/",
)
POLICY_FILES = {
    GROWTH_ROOTS[0] + ".gitkeep",
    GROWTH_ROOTS[0] + "ARTIFACT_POLICY.md",
    GROWTH_ROOTS[1] + ".gitkeep",
    GROWTH_ROOTS[1] + "LEDGER_POLICY.md",
}


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def check(root: Path = ROOT) -> list[str]:
    errors = []
    try:
        census = json.loads((root / "reports/repo_pristine_census_v1.json").read_text(encoding="utf-8"), object_pairs_hook=unique_keys)
        risks = json.loads((root / "reports/repo_path_length_risk_index_v1.json").read_text(encoding="utf-8"), object_pairs_hook=unique_keys)
        if not isinstance(census, dict) or census.get("duplicate_current_authority_status") != "PASS":
            errors.append("duplicate current authority report is missing or blocked")
        if not isinstance(risks, dict) or type(risks.get("blocker_count")) is not int or risks["blocker_count"] != 0:
            errors.append("path length report has a missing, invalid or nonzero blocker_count")
    except (OSError, ValueError) as exc:
        errors.append(f"cannot read retained reports: {exc}")
    try:
        tracked = subprocess.check_output(
            ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "ls-files", "-z"], cwd=root
        ).decode("utf-8").split("\0")
        errors.extend(
            f"tracked runtime output: {path}"
            for path in tracked
            if path.startswith(GROWTH_ROOTS) and path not in POLICY_FILES
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        errors.append(f"cannot inspect tracked output paths: {exc}")
    return errors


def main() -> int:
    errors = check(ROOT)
    print(json.dumps({"schema_id": "kt.no_bloat_check.v1", "status": "FAIL" if errors else "PASS",
                      "scope": "tracked growth outputs and retained report gate fields", "errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
