# V17.7.3 Measured Arm Kaggle One Cell

Packet: `packets/ktv1773_measured_arm_v1.zip`
Packet SHA256: `5af1f7bb6f830a12d065e333270c92ae8c197f45b6ec7006b764004d83daf94e`
Dataset name: `ktv1773-arm-v1`
Runtime mode: `RUN_TARGETED_BOUNDARY_ROW_FURNACE_MEASURED_ARMS`

This packet is evidence-only. It does not train, does not run V18, does not optimize policy, and does not promote routes or adapters.

```python
import hashlib, os, subprocess, sys, zipfile
from pathlib import Path

DATASET = "ktv1773-arm-v1"
PACKET_NAME = "ktv1773_measured_arm_v1.zip"
EXPECTED_SHA256 = "5af1f7bb6f830a12d065e333270c92ae8c197f45b6ec7006b764004d83daf94e"

candidates = []
for root in [Path("/kaggle/input") / DATASET, Path("/kaggle/input"), Path("/kaggle/working")]:
    if root.exists():
        candidates.extend(root.rglob(PACKET_NAME))
candidates = sorted(set(candidates))
assert candidates, f"Missing {PACKET_NAME}"
packet = candidates[0]
actual = hashlib.sha256(packet.read_bytes()).hexdigest()
assert actual == EXPECTED_SHA256, f"packet sha mismatch: {actual} != {EXPECTED_SHA256}"

work = Path("/kaggle/working/ktv1773_measured_arm_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as z:
    z.extractall(work)

os.environ["KT_RUNTIME_MODE"] = "RUN_TARGETED_BOUNDARY_ROW_FURNACE_MEASURED_ARMS"
os.environ["KT_EVIDENCE_ONLY"] = "1"
os.environ["KT_ENABLE_ADAPTER_TRAINING"] = "0"
os.environ["KT_ENABLE_ROUTER_TRAINING"] = "0"
os.environ["KT_ALLOW_POLICY_OPTIMIZATION"] = "0"
os.environ["KT_PROMOTION_ALLOWED"] = "0"
os.environ["KT_ALLOW_V18"] = "0"

subprocess.check_call([sys.executable, str(work / "KTV1773_MEASURED_ARM_MASTER_RUNNER.py")])
```
