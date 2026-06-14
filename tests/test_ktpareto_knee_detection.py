import json
import zipfile
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_knee_detection_contract_is_in_runtime_packet():
    ensure_ktpareto_built()
    with zipfile.ZipFile(ROOT / "packets" / "ktpareto_v1.zip") as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8")
    assert "budget_pareto_knee_receipt.json" in runner
    assert "piecewise_linear_elbow_plus_marginal_efficiency" in runner
    assert "sse_by_breakpoint" in runner
    assert "marginal_efficiency_by_transition" in runner


def test_ktpareto_builder_summary_marks_knee_ready():
    ensure_ktpareto_built()
    summary = json.loads((ROOT / "reports" / "ktpareto_builder_summary.json").read_text())
    assert summary["ktpareto_knee_detection_status"] == "PACKET_CONTRACT_READY"
