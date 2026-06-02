# V17.7.4 True-Generation Mini-Furnace One Cell

Packet: `packets/ktv1774_truegen_minifurnace_v1.zip`

This is the next evidence move selected by V17.7.3 measurement-authority adjudication. It is not V18 and does not train.

```python
from pathlib import Path
import subprocess, sys, zipfile

PACKET = Path('/kaggle/input/ktv1774-truegen-minifurnace/ktv1774_truegen_minifurnace_v1.zip')
if not PACKET.exists():
    PACKET = Path('/kaggle/working/ktv1774_truegen_minifurnace_v1.zip')
work = Path('/kaggle/working/ktv1774_truegen_minifurnace_packet')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(PACKET) as archive:
    archive.extractall(work)
subprocess.check_call([sys.executable, str(work / 'KTV1774_TRUEGEN_MINIFURNACE_RUNNER.py')])
```
