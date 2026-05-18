from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from context_packing.json_to_columnar_adapter import json_text_to_columnar
from context_packing.json_to_toon_adapter import json_text_to_toon


def benchmark_payload(value: Any) -> dict[str, Any]:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=True)
    toon = json_text_to_toon(canonical)
    columnar = json_text_to_columnar(canonical)
    return {
        "schema_id": "kt.fp0.context_pack_benchmark.receipt.v2",
        "authority": "PREP_ONLY_NO_CLAIM_EXPANSION",
        "json_bytes": len(canonical.encode("utf-8")),
        "toon_bytes": len(toon.encode("utf-8")),
        "columnar_bytes": len(columnar.encode("utf-8")),
        "json_remains_canonical": True,
        "claim_expansion_allowed": False,
    }


if __name__ == "__main__":
    import sys

    print(json.dumps(benchmark_payload(json.loads(sys.stdin.read())), indent=2, sort_keys=True))
