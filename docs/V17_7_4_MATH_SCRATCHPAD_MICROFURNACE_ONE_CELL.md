# V17.7.4 Math Scratchpad Microfurnace One Cell

Packet: `packets/ktv1774_math_scratchpad_microfurnace_v1.zip`

Kaggle dataset name: `ktv1774-math-scratchpad-microfurnace-v1`

SHA256: `b12315d98149ac456a33b67ebe1be2578761a10420d82329a9808a4424cfbb7d`

This is a 25-row GSM8K-only scratchpad evidence run. It preserves claim ceiling and does not train, promote, authorize V18, change routes, add KT-hat, or claim router/G2/commercial authority.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_MATH_SCRATCHPAD_MICROFURNACE_25"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "REAL_BENCHMARK_GAUGE"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "25"
os.environ["KT_MINIFURNACE_ROWS"] = "25"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_COMPACT_ANSWER_CONTRACT"] = "1"
os.environ["KT_REASONING_PRESERVING_COMPACT"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/ktv1774-math-scratchpad-microfurnace-v1/ktv1774_math_scratchpad_microfurnace_v1.zip")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_math_scratchpad_microfurnace_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_MATH_SCRATCHPAD_MICROFURNACE_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
