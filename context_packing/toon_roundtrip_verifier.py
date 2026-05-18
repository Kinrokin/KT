from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from context_packing.json_to_toon_adapter import to_toon


def verify_json_to_toon_stability(value: Any) -> dict[str, Any]:
    first = to_toon(value)
    second = to_toon(json.loads(json.dumps(value, sort_keys=True)))
    return {
        "schema_id": "kt.fp0.toon_roundtrip_verifier.receipt.v2",
        "authority": "PREP_ONLY_NO_CLAIM_EXPANSION",
        "json_remains_canonical": True,
        "stable_render": first == second,
        "claim_expansion_allowed": False,
    }


if __name__ == "__main__":
    import sys

    payload = json.loads(sys.stdin.read())
    print(json.dumps(verify_json_to_toon_stability(payload), indent=2, sort_keys=True))
