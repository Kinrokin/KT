from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    registry = json.loads((ROOT / "registry/artifact_authority_registry.json").read_text(encoding="utf-8"))
    tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
    paths = {artifact["path"] for artifact in registry["artifacts"]}
    missing = sorted(set(tracked) - paths)
    unknowns = [artifact["path"] for artifact in registry["artifacts"] if artifact["primary_class"] == "UNKNOWN_REVIEW_REQUIRED"]
    if registry["schema_id"] != "kt.artifact_authority_registry.v3":
        raise SystemExit("unexpected registry schema_id")
    if missing:
        raise SystemExit(f"registry missing tracked files: {missing[:20]}")
    if unknowns:
        raise SystemExit(f"unknown artifact review required: {unknowns[:20]}")
    print(json.dumps({"schema_id": "kt.artifact_authority_registry_check.v1", "status": "PASS", "tracked_file_count": len(tracked)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
