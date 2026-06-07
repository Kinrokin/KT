# V17.7.4 ReproLock Shuffle Control One Cell

Packet: `packets/ktv1774_reprolock_shuffle_control_v1.zip`

Kaggle dataset name: `ktv1774-reprolock-shuffle-control-v1`

SHA256: `9f7ab9e5eb4dbb5e387ef7422b88f3fa81125fb03a51091759d179aaaa7fbc99`

This is not held-out generalization. It is a row-order/leakage/negative-control stability test over the existing byte-locked 50-row ReproLock control.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_REPROLOCK_SHUFFLE_CONTROL_50"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "ORACLE_ACADEMY_REPROLOCK"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "50"
os.environ["KT_MINIFURNACE_ROWS"] = "50"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_REPROLOCK_LOAD_TOKENIZER"] = "0"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/ktv1774-reprolock-shuffle-control-v1/ktv1774_reprolock_shuffle_control_v1.zip")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_reprolock_shuffle_control_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_REPROLOCK_SHUFFLE_CONTROL_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
