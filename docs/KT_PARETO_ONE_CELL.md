# KT Pareto One Cell

Dataset name:

```text
ktpareto-v1
```

Packet:

```text
packets/ktpareto_v1.zip
```

Packet SHA256:

```text
cd9fc3ae9b94ed25d0d7f12c9f62f79dd2c50ada788b8f03891247e2d7ba2844
```

Run mode:

```text
RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100
```

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path

packet = Path('/kaggle/input/ktpareto-v1/ktpareto_v1.zip')
work = Path('/kaggle/working/ktpareto_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
exec((work / 'KAGGLE_BOOTSTRAP_CELL.py').read_text(encoding='utf-8'))
```

This packet is assessment-only. It does not train, promote, deploy selectors,
mutate adapters, mutate production prompts, or expand claim ceiling.
