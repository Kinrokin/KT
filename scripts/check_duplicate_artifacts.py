from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    registry = json.loads((ROOT / "registry/artifact_authority_registry.json").read_text(encoding="utf-8"))
    by_role: dict[str, list[str]] = defaultdict(list)
    for artifact in registry["artifacts"]:
        if artifact.get("current_authority") and artifact.get("controls_execution"):
            by_role[f"{artifact['role']}::{artifact['path']}"].append(artifact["path"])
    duplicates = {role: paths for role, paths in by_role.items() if len(paths) > 1}
    if duplicates:
        raise SystemExit(json.dumps(duplicates, indent=2))
    print(json.dumps({"schema_id": "kt.duplicate_artifact_check.v1", "status": "PASS"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
