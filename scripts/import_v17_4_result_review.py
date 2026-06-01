from __future__ import annotations

import json

from v17_5_multirescuer_common import json_safe, load_v17_4_evidence


if __name__ == "__main__":
    evidence = load_v17_4_evidence()
    print(
        json.dumps(
            json_safe(
                {
                    "rows": len(evidence["rows"]),
                    "assessment_zip_sha256": evidence["zip_sha256"],
                    "status": "PASS",
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )
