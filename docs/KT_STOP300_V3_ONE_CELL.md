# KT STOP300 V3 One-Cell Runbook

Packet: `packets/ktstop300_v3.zip`

SHA256: `2196dceafa858f910909e1c214c0402ab80868e19db66a25e8614096549d99d9`

Kaggle dataset: `ktstop300-v3`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V3`

```python
import hashlib, os, zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v3/ktstop300_v3.zip')
expected_sha = '2196dceafa858f910909e1c214c0402ab80868e19db66a25e8614096549d99d9'
actual_sha = hashlib.sha256(packet.read_bytes()).hexdigest()
if actual_sha != expected_sha:
    raise RuntimeError(f'packet sha mismatch: {actual_sha}')
os.environ['KT_AUTHORIZED_PACKET_SHA256'] = actual_sha
os.environ['KT_AUTHORIZED_MERGE_HEAD'] = os.environ.get('KT_AUTHORIZED_MERGE_HEAD', 'MERGED_MAIN_HEAD_TO_BIND_AFTER_PROTECTED_MERGE')
work = Path('/kaggle/working/ktstop300_v3_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.
