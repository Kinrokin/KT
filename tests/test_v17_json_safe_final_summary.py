from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from scripts.v17_1_canary_repair_common import json_safe


def test_json_safe_handles_final_summary_problem_types():
    payload = {
        "path": Path("x/y"),
        "set": {"b", "a"},
        "tuple": ("a", 1),
        "counter": Counter({"route": 2}),
        "defaultdict": defaultdict(int, {"base": 1}),
        "bytes": b"hello",
    }
    encoded = json.dumps(json_safe(payload), sort_keys=True)
    assert "x/y" in encoded
    assert "route" in encoded
    assert "hello" in encoded
