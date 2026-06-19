# KT STOP300 V4.1 One-Cell Runbook

Packet: `packets/ktstop300_v4_1.zip`

SHA256: `8ff159f76e22767bca73c16e512d7b97643fe101b056211ab708b5e078100c0a`

Kaggle dataset: `ktstop300-v4-1`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4_1`

Packet subject merge head: `aa12b0e4c927d5451ba36032806ba1017eb3bf23`

Final current main head: set this to the post-replay protected-merge head verified by fresh clone before launch.

```python
import hashlib, os, zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v4-1/ktstop300_v4_1.zip')
expected_sha = '8ff159f76e22767bca73c16e512d7b97643fe101b056211ab708b5e078100c0a'
expected_subject_head = 'aa12b0e4c927d5451ba36032806ba1017eb3bf23'
expected_run_mode = 'RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4_1'
actual_sha = hashlib.sha256(packet.read_bytes()).hexdigest()
if actual_sha != expected_sha:
    raise RuntimeError(f'packet sha mismatch: {actual_sha}')
os.environ['KT_AUTHORIZED_PACKET_SHA256'] = actual_sha
os.environ['KT_AUTHORIZED_PACKET_SUBJECT_HEAD'] = expected_subject_head
os.environ['KT_CURRENT_MAIN_HEAD'] = os.environ['KT_CURRENT_MAIN_HEAD']
os.environ['KT_EXPECTED_RUN_MODE'] = expected_run_mode
os.environ.setdefault('KT_RAISE_ON_BLOCKER', '0')
work = Path('/kaggle/working/ktstop300_v4_1_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.
