from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_activation_margin_sweep_recomputes_distinct_route_distributions():
    diagnosis = json.loads((ROOT / "reports/v17_1_activation_margin_sweep_diagnosis.json").read_text(encoding="utf-8"))
    distributions = json.loads((ROOT / "admission/v17_1_margin_sweep_route_distribution_by_margin.json").read_text(encoding="utf-8"))
    assert diagnosis["activation_margin_sweep_effective"] is True
    assert diagnosis["status"] == "PASS"
    assert len({tuple(sorted(v.items())) for v in distributions["distributions"].values()}) > 1
