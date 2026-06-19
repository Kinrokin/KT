# KT STOP300 V2 One-Cell Runbook

Packet: `packets/ktstop300_v2.zip`

SHA256: `72948378246db869db4bb37f3c4f5f861c737034d63058331fe94eece02d4f93`

Kaggle dataset: `ktstop300-v2`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V2`

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v2/ktstop300_v2.zip')
work = Path('/kaggle/working/ktstop300_v2_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, selector deployment, shadow execution, production runtime authority, production prompt mutation, or production math-mode authority.
