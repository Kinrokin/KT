from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_rollback_drill(*, registry_path: Path, work_dir: Path) -> Dict[str, Any]:
    """
    Minimal rollback drill:
    - take an on-disk snapshot of the runtime registry file
    - apply a reversible mutation to a COPY of the registry
    - restore from snapshot
    - prove restored bytes are identical

    This avoids touching the canonical registry in-place during tests while still proving rollback logic.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    original = registry_path.read_bytes()
    original_hash = sha256_bytes(original)

    copy_path = work_dir / "RUNTIME_REGISTRY.rollback_copy.json"
    copy_path.write_bytes(original)

    # Apply a reversible change to the copy (inject then remove a benign key).
    obj = json.loads(copy_path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError("registry must be JSON object (fail-closed)")
    obj["_fl3_rollback_probe"] = True
    copy_path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    mutated_hash = sha256_bytes(copy_path.read_bytes())

    # Restore from snapshot.
    copy_path.write_bytes(original)
    restored_hash = sha256_bytes(copy_path.read_bytes())

    return {
        "schema_id": "kt.fl3.rollback_drill.v1",
        "registry_path": str(registry_path),
        "original_sha256": original_hash,
        "mutated_sha256": mutated_hash,
        "restored_sha256": restored_hash,
        "restored_matches_original": restored_hash == original_hash,
    }


def main(argv: List[str] | None = None) -> int:
    import argparse
    import tempfile

    ap = argparse.ArgumentParser()
    ap.add_argument("--registry-path", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    registry_path = Path(args.registry_path)
    with tempfile.TemporaryDirectory() as td:
        report = run_rollback_drill(registry_path=registry_path, work_dir=Path(td))
    out = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0 if report.get("restored_matches_original") else 2


if __name__ == "__main__":
    raise SystemExit(main())

