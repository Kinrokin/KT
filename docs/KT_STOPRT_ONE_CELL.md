# KT STOPRT One-Cell Runbook

Packet: `packets/ktstoprt_v1.zip`

SHA256: `620dda5b47587da4927d57545378b51ecc1879be75965e5fe72dbc3bce064eec`

Kaggle dataset: `ktstoprt-v1`

Run mode: `RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1`

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstoprt-v1/ktstoprt_v1.zip')
work = Path('/kaggle/working/ktstoprt_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is sandbox inference confirmation only. It does not train, promote, deploy selectors, mutate adapters, mutate production prompts, or grant production math-mode authority.
