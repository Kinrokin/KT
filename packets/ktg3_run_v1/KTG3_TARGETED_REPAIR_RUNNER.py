from __future__ import annotations

import json
from pathlib import Path

PROGRAM_ID = "KT_G3_ACADEMY_PRESSURE_REPAIR_SUPERLANE_V1"
PACKET_BUILD_HEAD = "303a0a0842cb9dad8d60607c6ac5c131b1a97cf3"
TARGET_OUTCOME = "KT_G3_ACADEMY_PRESSURE_REPAIR_READY__TARGETED_G3_RUN_NEXT__CLAIM_CEILING_PRESERVED"


def main() -> None:
    output = {
        "schema_id": "kt.g3.targeted_repair_runtime_intent.v1",
        "program_id": PROGRAM_ID,
        "packet_build_head": PACKET_BUILD_HEAD,
        "runtime_mode": "TARGETED_G3_REPAIR_REQUIRED",
        "claim_ceiling_preserved": True,
        "runtime_must_emit": [
            "g3_training_receipt.json",
            "g3_eval_receipt.json",
            "g3_no_regression_receipt.json",
            "g3_scar_delta_distinctness_receipt.json",
            "g3_negative_result_ledger.json"
        ],
        "claims_authorized_by_this_runner": []
    }
    Path("g3_runtime_intent.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
