# KT STOP300 One-Cell Runbook

Packet: `packets/ktstop300_v1.zip`

SHA256: `27e068c1551820007b67a34d050d4ce02123c838acd1a498a5c4c0e26684299a`

Kaggle dataset: `ktstop300-v1`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V1`

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v1/ktstop300_v1.zip')
work = Path('/kaggle/working/ktstop300_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, selector deployment, shadow execution, production runtime authority, production prompt mutation, or production math-mode authority.
