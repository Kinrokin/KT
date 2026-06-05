# V17.7.4 Oracle Academy Reentry One Cell

Packet: `packets/ktv1774_oracle_academy_reentry_v1.zip`

Kaggle dataset name: `ktv1774-oracle-academy-v1`

SHA256: `55823dbb8c69bbea723b42678347febec17aa2a067f3432eeef9cf93a86782c0`

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_ORACLE_ACADEMY_REENTRY_50"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "ORACLE_AUTOPSY_ACADEMY_REENTRY"
os.environ["KT_COMPACT_ANSWER_CONTRACT"] = "1"
os.environ["KT_REASONING_PRESERVING_COMPACT"] = "1"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "50"
os.environ["KT_MINIFURNACE_ROWS"] = "50"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/ktv1774-oracle-academy-v1/ktv1774_oracle_academy_reentry_v1.zip")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_oracle_academy_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
