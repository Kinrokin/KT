# KT Counterfactual Microfurnace V1 One Cell

Dataset name:

```text
ktcf-v1
```

Packet:

```text
packets/ktcf_v1.zip
```

Packet SHA256:

```text
33332094005a25ca3ace961139eee1f7a5ae51ee1c3f9f918413373536a178dd
```

Run mode:

```text
RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1
```

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path

packet = Path('/kaggle/input/ktcf-v1/ktcf_v1.zip')
work = Path('/kaggle/working/ktcf_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
exec((work / 'KAGGLE_BOOTSTRAP_CELL.py').read_text(encoding='utf-8'))
```

This is a diagnostic counterfactual microfurnace only. It does not train,
promote, deploy selectors, deploy budget arms, mutate adapters, mutate
production prompts, or create production math-mode authority.
