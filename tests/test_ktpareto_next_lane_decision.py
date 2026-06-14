import json
import zipfile
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_repo_next_lawful_move_is_kaggle_sweep_after_merge():
    ensure_ktpareto_built()
    summary = json.loads((ROOT / "reports" / "ktpareto_builder_summary.json").read_text())
    decision = json.loads((ROOT / "reports" / "ktpareto_packet_decision.json").read_text())
    assert summary["next_lawful_move"] == "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100"
    assert decision["next_lawful_move"] == "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100"


def test_ktpareto_runtime_selects_exactly_one_post_assessment_lane():
    ensure_ktpareto_built()
    with zipfile.ZipFile(ROOT / "packets" / "ktpareto_v1.zip") as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8")
    assert "def choose_next(summary, knee_receipt):" in runner
    assert "summary[\"next_lawful_move\"] = choose_next(summary, knee_receipt)" in runner
    assert "AUTHOR_SELECTOR_MICRO_FURNACE_KAGGLE_V1" in runner
