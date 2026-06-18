from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_ktstop10_assessment_import_binds_sha() -> None:
    subprocess.run(["python", "scripts/import_ktstop10_assessment.py"], check=True)
    receipt = json.loads(Path("reports/ktstoprt_assessment_import_receipt.json").read_text())
    assert receipt["status"] == "PASS"
    assert receipt["assessment_sha256"] == "c1580bec70abea0da8ef86441b6a2158a9f8325ba151bf5a3e6bd197cab15076"
    assert receipt["claim_ceiling_status"] == "PRESERVED"
