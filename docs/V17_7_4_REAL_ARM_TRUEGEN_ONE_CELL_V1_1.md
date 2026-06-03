# V17.7.4 Real-Arm Truegen One Cell V1.1

Packet: `packets/ktv1774_real_arm_truegen_v1_1.zip`

Kaggle dataset name: `ktv1774-real-arms-v1-1`

SHA256: `7e06ba57af41b8544a73b8ec916dddae411b0059e68dd8bdd248692df6f89ad6`

This packet is not the smoke packet. It requires the real-arm config and fails closed if adapter-source bindings are missing.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_REAL_ARM_TRUEGEN_MINIFURNACE"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_ROOT", "/kaggle/input/datasets/robertking1995/adapterssafetensors")

candidates = [
    Path("/kaggle/input/ktv1774-real-arms-v1-1/ktv1774_real_arm_truegen_v1_1.zip"),
    Path("/kaggle/working/ktv1774_real_arm_truegen_v1_1.zip"),
]
packet = next((p for p in candidates if p.exists()), None)
if packet is None:
    raise FileNotFoundError("missing ktv1774_real_arm_truegen_v1_1.zip")

work = Path("/kaggle/working/ktv1774_real_arm_truegen_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)

runner = work / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
print("hf_dataset_url:", os.environ.get("KT_HF_DATASET_URL", "HF_UPLOAD_NOT_RUN_BY_REPO_SIDE_LANE"))
```
