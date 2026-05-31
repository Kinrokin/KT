import json
from pathlib import Path

ROOT = Path.cwd()


def test_route_rescuer_heatmap_counts_all_oracle_gaps():
    obj = json.loads((ROOT / "reports/route_rescuer_heatmap.json").read_text(encoding="utf-8"))
    assert obj["gap_count"] == 28
    assert sum(obj["by_oracle_route"].values()) == 28
    assert "formal_math_repair_adapter_global" in obj["by_oracle_route"]
