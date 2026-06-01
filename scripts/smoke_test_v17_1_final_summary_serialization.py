from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from v17_1_canary_repair_common import json_safe


def main() -> int:
    try:
        import numpy as np

        scalar = np.int64(7)
    except Exception:  # noqa: BLE001
        scalar = 7
    ugly = {
        "path": Path("final/final_summary.json"),
        "set": {"b", "a"},
        "tuple": ("x", 2),
        "counter": Counter({"base_raw": 3}),
        "defaultdict": defaultdict(int, {"k": 1}),
        "numpy_scalar": scalar,
        "bytes": b"ok",
        "nested": [{"path": Path("x")}],
    }
    encoded = json.dumps(json_safe(ugly), sort_keys=True)
    required = ["final/final_summary.json", "base_raw", "ok", "numpy_scalar"]
    missing = [token for token in required if token not in encoded]
    print(encoded)
    return 0 if not missing else 2


if __name__ == "__main__":
    raise SystemExit(main())
