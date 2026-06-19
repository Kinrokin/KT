# KT STOP300 V4 One-Cell Runbook

Packet: `packets/ktstop300_v4.zip`

SHA256: `32ed95da638d72dc3355277a9b0c70686c33e48fad76b48fb2efffc6d26c3ab3`

Kaggle dataset: `ktstop300-v4`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4`

```python
import hashlib, os, zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v4/ktstop300_v4.zip')
expected_sha = '32ed95da638d72dc3355277a9b0c70686c33e48fad76b48fb2efffc6d26c3ab3'
actual_sha = hashlib.sha256(packet.read_bytes()).hexdigest()
if actual_sha != expected_sha:
    raise RuntimeError(f'packet sha mismatch: {actual_sha}')
os.environ['KT_AUTHORIZED_PACKET_SHA256'] = actual_sha
os.environ['KT_AUTHORIZED_PACKET_SUBJECT_HEAD'] = '105e7d842404e71267b830807e942bd7954abace'
os.environ['KT_CURRENT_MAIN_HEAD'] = '105e7d842404e71267b830807e942bd7954abace'
os.environ['KT_EXPECTED_RUN_MODE'] = 'RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4'
os.environ.setdefault('KT_RAISE_ON_BLOCKER', '0')
work = Path('/kaggle/working/ktstop300_v4_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.
