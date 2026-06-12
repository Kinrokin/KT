# KT BUD100 One Cell

Dataset name:

```text
ktbud100-v1
```

Packet:

```text
packets/ktbud100_v1.zip
```

Packet SHA256:

```text
216eb74184cf5649e9d9ba2a08401b34ad29df02362578c5b4569b27c232e500
```

Run mode:

```text
RUN_KT_BUDGET_MONITOR_GSM8K_100
```

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path

packet = Path('/kaggle/input/ktbud100-v1/ktbud100_v1.zip')
work = Path('/kaggle/working/ktbud100_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
exec((work / 'KAGGLE_BOOTSTRAP_CELL.py').read_text(encoding='utf-8'))
```

This packet is assessment-only. It does not train, mutate adapters, promote routes,
authorize production prompt changes, or expand claim ceiling.
