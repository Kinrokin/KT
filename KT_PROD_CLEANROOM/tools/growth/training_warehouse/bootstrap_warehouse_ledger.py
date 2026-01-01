from __future__ import annotations

import json
from pathlib import Path

from warehouse_store import append_chained_ledger


def main() -> int:
    artifacts_root = Path("KT_PROD_CLEANROOM/tools/growth/artifacts/training_warehouse").resolve()
    manifest = artifacts_root / "warehouse_manifest.jsonl"
    ledger = artifacts_root / "warehouse_ledger_chained.jsonl"

    if ledger.exists():
        raise SystemExit("ledger_already_exists (fail-closed)")
    if not manifest.exists():
        raise SystemExit("manifest_missing (fail-closed)")

    lines = [ln for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        raise SystemExit("manifest_empty (fail-closed)")

    for ln in lines:
        obj = json.loads(ln)
        if not isinstance(obj, dict):
            raise SystemExit("manifest_line_not_object (fail-closed)")
        append_chained_ledger(
            ledger_path=ledger,
            payload={
                "schema": "kt.training.warehouse.ledger_record",
                "schema_version": 1,
                "manifest_record": obj,
            },
        )
    print(str(ledger))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

