from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    path = Path("reports/adapter_isolation_contract_receipt.json")
    receipt = json.loads(path.read_text(encoding="utf-8-sig"))
    ok = (
        receipt.get("schema_id") == "kt.adapter_isolation_receipt.v1"
        and receipt.get("adapter_promotion_authorized") is False
        and receipt.get("claim_ceiling_preserved") is True
        and receipt.get("status") in {"SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED", "PASS"}
    )
    print(json.dumps({"path": str(path), "adapter_isolation_check_pass": ok}, indent=2, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
