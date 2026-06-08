# V17.7.4 Control-Only GSM8K Extension One Cell

Packet: `packets/ktv1774_control_only_gsm8k_extension_v1.zip`

Kaggle dataset name: `ktv1774-control-gsm8k-extension-v1`

SHA256: `6dc7ef8057a9cf7a59a328e33dbf501543e5a5cc85d608ee652baf1486ddec4a`

This is a control-only evidence acquisition run. It preserves the known-good first-pass path and does not train, promote, authorize V18, run parser/canonicalizer repair, run scratchpad, run KT-hat, or change route/admission behavior.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_100"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "ORACLE_ACADEMY_REPROLOCK"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "100"
os.environ["KT_MINIFURNACE_ROWS"] = "100"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_REPROLOCK_LOAD_TOKENIZER"] = "0"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/ktv1774-control-gsm8k-extension-v1/ktv1774_control_only_gsm8k_extension_v1.zip")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_control_only_gsm8k_extension_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
