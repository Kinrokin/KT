from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import build_lean_packaging_contract, json_safe


if __name__ == "__main__":
    lean, disk, hf, assessment = build_lean_packaging_contract()
    print(
        json.dumps(
            json_safe(
                {
                    "lean_packaging": lean,
                    "disk_guard": disk,
                    "minimal_hf_upload": hf,
                    "assessment_only": assessment,
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )
