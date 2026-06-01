from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import build_all_outputs, json_safe


if __name__ == "__main__":
    summary = build_all_outputs()
    print(
        json.dumps(
            json_safe(
                {
                    "packet_path": summary["packet_path"],
                    "packet_sha256": summary["packet_sha256"],
                    "kaggle_dataset_name": summary["kaggle_dataset_name"],
                    "status": summary["runtime_packet_generation_status"],
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )
