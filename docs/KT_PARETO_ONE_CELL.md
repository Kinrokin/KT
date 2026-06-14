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
191b2e36cbbd00157d3b1245c69e657ea6dc638c0618e4793c3a1ae52cc51455
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
