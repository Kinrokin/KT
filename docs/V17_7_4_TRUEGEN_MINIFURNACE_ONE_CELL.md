# V17.7.4 True-Generation Mini-Furnace One Cell

Packet: `packets/ktv1774_truegen_e2e_v1.zip`

Kaggle dataset name: `ktv1774-truegen-v1`

SHA256: `fb4ce9987eb1cd8891b750c9215f764a3c1a1b7ef89723b24fbd01d1c224c96f`

This runner performs fresh generation or fails closed. It does not train, promote routes/adapters, authorize V18, or expand the claim ceiling.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_TRUEGEN_MINIFURNACE"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"

candidates = [
    Path("/kaggle/input/ktv1774-truegen-v1/ktv1774_truegen_e2e_v1.zip"),
    Path("/kaggle/working/ktv1774_truegen_e2e_v1.zip"),
]
packet = next((p for p in candidates if p.exists()), None)
if packet is None:
    raise FileNotFoundError("missing ktv1774_truegen_e2e_v1.zip")

work = Path("/kaggle/working/ktv1774_truegen_e2e_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)

os.chdir(work)
sys.path.insert(0, str(work))
subprocess.check_call([sys.executable, "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
