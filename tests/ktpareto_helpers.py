import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def ensure_ktpareto_built() -> None:
    required = [
        ROOT / "packets" / "ktpareto_v1.zip",
        ROOT / "reports" / "ktpareto_packet_decision.json",
        ROOT / "reports" / "ktpareto_builder_summary.json",
        ROOT / "reports" / "ktpareto_row_policy_receipt.json",
    ]
    if all(path.exists() for path in required):
        return
    subprocess.run([sys.executable, "scripts/build_ktpareto_packet.py"], cwd=ROOT, check=True)
