import json
import zipfile
from pathlib import Path


def test_v2_result_court_is_executable_and_not_pending():
    receipt = json.loads(Path("reports/stop300_v2_result_court_contract.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        court = zf.read("runtime/result_court.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS_EXECUTABLE_CONJUNCTIVE_COURT_BOUND"
    assert "execute_result_court" in runner
    assert "MEASURED_OUTPUTS_EMITTED_PENDING_COURT" not in court
