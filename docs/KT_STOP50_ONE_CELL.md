# KT STOP50 One-Cell Runbook

Packet: `packets/ktstop50_v1.zip`

SHA256: `88897536607e923a0723ad60bb9219712a447a00abd18cd8c0b2db21aa71bc18`

Kaggle dataset: `ktstop50-v1`

Run mode: `RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_50ROW_V1`

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop50-v1/ktstop50_v1.zip')
work = Path('/kaggle/working/ktstop50_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is sandbox inference only. It does not train, promote, deploy selectors, mutate adapters, mutate production prompts, grant production runtime authority, or grant production math-mode authority.
