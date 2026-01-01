from __future__ import annotations

import json
from pathlib import Path

from distill_runner import _append_chained_ledger  # type: ignore


def main() -> int:
    artifacts_root = Path("KT_PROD_CLEANROOM/tools/growth/artifacts/distillation").resolve()
    ledger = artifacts_root / "distillation_ledger_chained.jsonl"

    if ledger.exists():
        raise SystemExit("ledger_already_exists (fail-closed)")
    artifacts_root.mkdir(parents=True, exist_ok=True)

    # Bootstrap from existing run dirs (deterministic order by folder name).
    run_dirs = sorted([p for p in artifacts_root.iterdir() if p.is_dir()])
    if not run_dirs:
        raise SystemExit("no_runs_found (fail-closed)")

    for run_dir in run_dirs:
        rm = run_dir / "run_manifest.json"
        ma = run_dir / "model_artifact.json"
        if not rm.exists() or not ma.exists():
            continue
        run_obj = json.loads(rm.read_text(encoding="utf-8"))
        art_obj = json.loads(ma.read_text(encoding="utf-8"))
        if not isinstance(run_obj, dict) or not isinstance(art_obj, dict):
            raise SystemExit("run_or_art_not_object (fail-closed)")
        _append_chained_ledger(
            ledger_path=ledger,
            payload={
                "schema": "kt.distill.ledger_record",
                "schema_version": 1,
                "run_dir": run_dir.as_posix(),
                "run_hash": str(run_obj.get("run_hash", "")),
                "artifact_hash": str(art_obj.get("artifact_hash", "")),
            },
        )

    print(str(ledger))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

