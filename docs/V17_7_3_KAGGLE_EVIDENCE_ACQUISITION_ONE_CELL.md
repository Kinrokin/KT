# V17.7.3 Kaggle Evidence Acquisition One Cell

Packet: `packets/ktv1773_evidence_acquisition_e2e_v1.zip`
Packet SHA256: `7713a020bd27f1285ae8ab025d3240cd24d1ae7817ff3445802d95a14de1b0c0`
Dataset name: `ktv1773-evidence-v1`
Runtime mode: `RUN_TARGETED_BOUNDARY_ROW_FURNACE`

This packet is evidence-only. It does not train, does not run V18, does not optimize policy, and does not promote routes or adapters.

```python
import os, subprocess, sys, zipfile
from pathlib import Path

PACKET = Path("/kaggle/input/ktv1773-evidence-v1/ktv1773_evidence_acquisition_e2e_v1.zip")
if not PACKET.exists():
    PACKET = Path("/kaggle/working/ktv1773_evidence_acquisition_e2e_v1.zip")
assert PACKET.exists(), f"Missing packet: {PACKET}"

work = Path("/kaggle/working/ktv1773_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(PACKET) as z:
    z.extractall(work)

os.environ["KT_RUNTIME_MODE"] = "RUN_TARGETED_BOUNDARY_ROW_FURNACE"
subprocess.check_call([sys.executable, str(work / "KTV1773_MICRO_FURNACE_MASTER_RUNNER.py")])
```
