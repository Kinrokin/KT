from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import json_safe, load_v17_5_evidence


if __name__ == "__main__":
    evidence = load_v17_5_evidence()
    print(
        json.dumps(
            json_safe(
                {
                    "source_kind": evidence["source_kind"],
                    "source_zip": evidence.get("source_zip"),
                    "row_member": evidence.get("row_member"),
                    "row_member_sha256": evidence.get("row_member_sha256"),
                    "rows": len(evidence["rows"]),
                    "status": "PASS",
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )
