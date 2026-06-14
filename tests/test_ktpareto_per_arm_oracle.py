import json
import zipfile
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_has_per_arm_oracle_contract_and_hindsight_boundary():
    ensure_ktpareto_built()
    arms = json.loads((ROOT / "reports" / "ktpareto_arm_manifest.json").read_text())
    assert arms["oracle_diagnostic_arm"] == "A9_ORACLE_DIAGNOSTIC_PER_ARM"

    with zipfile.ZipFile(ROOT / "packets" / "ktpareto_v1.zip") as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8")
    assert "per_arm_oracle_rows.jsonl" in runner
    assert "oracle_cheapest_correct_arm" in runner
    assert "hindsight_only_not_deployable" in runner
    assert "A9_ORACLE_DIAGNOSTIC_PER_ARM" in json.dumps(arms)
