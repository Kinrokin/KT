# V17.7.4 Oracle Academy Relocked One Cell

Packet: `packets/ktv1774_oracle_academy_relocked_v1.zip`

Kaggle dataset name: `ktv1774-oracle-relocked-v1`

SHA256: `601d89b655ac07800b533016cd248f2f8734d6d6ea87ec57bc0311c15539bb60`

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_ORACLE_ACADEMY_RELOCKED_50"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "ORACLE_ACADEMY_RELOCKED_AFTER_REPROLOCK"
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

packet = Path("/kaggle/input/ktv1774-oracle-relocked-v1/ktv1774_oracle_academy_relocked_v1.zip")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_oracle_relocked_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
