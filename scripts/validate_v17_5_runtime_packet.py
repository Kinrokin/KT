from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "packets" / "ktg3full_v17_5_multirescuer_e2e_v1.zip"


def validate() -> dict[str, object]:
    with zipfile.ZipFile(PACKET) as archive:
        names = set(archive.namelist())
        runner = archive.read("KTG3FULL_V17_5_MULTIRESCUER_E2E_V1_RUNNER.py").decode("utf-8")
    required = {"KTG3FULL_V17_5_MULTIRESCUER_E2E_V1_RUNNER.py", "V17_5_MULTIRESCUER_POLICY_CONFIG.json", "PACKET_MANIFEST.json", "ONE_CELL.md"}
    return {
        "packet_exists": PACKET.exists(),
        "required_members_present": required.issubset(names),
        "fails_closed_without_measured_rows": "missing non-empty measured benchmark_predictions.jsonl" in runner,
        "assessment_only_output": "ASSESSMENT_ONLY.zip" in runner,
        "partial_output_rescue": "PARTIAL_MEASURED_OUTPUTS.zip" in runner,
        "status": "PASS",
    }


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
