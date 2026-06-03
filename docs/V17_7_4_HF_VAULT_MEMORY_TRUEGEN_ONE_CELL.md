# V17.7.4 HF-Vault Memory-Safe Compression Frontier Truegen One Cell

Packet: `packets/ktv1774_hf_vault_memory_v1.zip`

Kaggle dataset name: `ktv1774-hf-vault-memory-v1`

SHA256: `4c2353bcfa8594499e2f34724c5bd33a6b84ef383272edf476a4f89243490ce1`

This packet is not the smoke packet. It requires the real-arm config and fails closed if adapter-source bindings are missing. It prefers the HF final-only adapter vault, runs one arm at a time, streams rows to disk, emits GPU memory telemetry, and returns only an assessment ZIP. It also emits token-economics, bloat-attribution, ablation-ladder, router-admission, and compression-frontier receipts.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_COMPRESSION_FRONTIER_TRUEGEN_MINIFURNACE"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("KT_TRUEGEN_LADDER_STAGE", "3")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")
# Use local only if HF is unavailable and a Kaggle adapter dataset is attached.
# os.environ["KT_TRUEGEN_ADAPTER_SOURCE"] = "local"
# os.environ.setdefault("KT_TRUEGEN_ADAPTER_ROOT", "/kaggle/input/datasets/robertking1995/adapterssafetensors")

candidates = [
    Path("/kaggle/input/ktv1774-hf-vault-memory-v1/ktv1774_hf_vault_memory_v1.zip"),
    Path("/kaggle/working/ktv1774_hf_vault_memory_v1.zip"),
]
packet = next((p for p in candidates if p.exists()), None)
if packet is None:
    raise FileNotFoundError("missing ktv1774_hf_vault_memory_v1.zip")

work = Path("/kaggle/working/ktv1774_hf_vault_memory_packet")
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
