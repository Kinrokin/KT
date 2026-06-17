# KT STOP10 One-Cell Runbook

Packet: `packets/ktstop10_v1.zip`

SHA256: `640ae33f1c7a5694bf640aaa5b1857dd0b801b252b55cd3e0fa31e8a574af464`

Kaggle dataset: `ktstop10-v1`

Run mode: `RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1`

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop10-v1/ktstop10_v1.zip')
work = Path('/kaggle/working/ktstop10_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is a 10-row diagnostic prompt probe only. It does not train, promote, deploy selectors, mutate adapters, mutate production prompts, or grant production math-mode authority.
