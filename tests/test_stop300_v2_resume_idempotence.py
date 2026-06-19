import json
import zipfile
from pathlib import Path


def test_v2_resume_ledger_uses_scope_phase_row_repetition_arm_key():
    receipt = json.loads(Path("reports/stop300_v2_restart_resume_contract.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        resume = zf.read("runtime/resume_ledger.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS_RESET_DURABLE"
    assert receipt["completed_key"] == "evidence_scope_hash/phase/row_id/repetition/arm"
    assert "BLOCK_SCOPE_MISMATCH" in resume
    assert "os.replace" in resume
