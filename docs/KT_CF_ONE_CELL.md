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
96b4621fa27fb999a04c0c4a3c56a359402e0d6fa8ce69eca841d47e901a7db3
```

Run mode:

```text
RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1
```

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktcf-v1/ktcf_v1.zip')
work = Path('/kaggle/working/ktcf_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is a diagnostic counterfactual microfurnace only. It does not train,
promote, deploy selectors, deploy budget arms, mutate adapters, mutate
production prompts, or create production math-mode authority.
