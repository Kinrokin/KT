from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_prefix_equivalence_contract_is_runtime_required_gate() -> None:
    subprocess.run(["python", "scripts/build_ktstoprt_packet.py"], check=True)
    receipt = json.loads(Path("reports/ktstoprt_prefix_equivalence_contract.json").read_text())
    assert receipt["status"] == "REQUIRED_AT_RUNTIME"
    assert "10/10" in receipt["hard_gate"]
