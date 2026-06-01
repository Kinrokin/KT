# V17.6 Kaggle Dataset And One Cell

Dataset: `ktv176-e2e-v1`

Packet: `packets/ktv176_e2e_v1.zip`

SHA256: `50fb5acdab6c62aaead9f6ed2d74a8762fc258caac8de63ffed8dedbc89348ae`

This packet is no-training, no-promotion, no learned-router-superiority, and no V18 runtime authority. Supply V17.5 measured rows through `PARTIAL_MEASURED_OUTPUTS.zip` or a non-empty `benchmark_predictions.jsonl`.

```python
import pathlib, subprocess, sys, zipfile
packet = pathlib.Path('/kaggle/input/ktv176-e2e-v1/ktv176_e2e_v1.zip')
work = pathlib.Path('/kaggle/working/ktv176_e2e_v1')
work.mkdir(parents=True, exist_ok=True)
zipfile.ZipFile(packet).extractall(work)
subprocess.check_call([sys.executable, 'KTG3FULL_V17_6_ORACLE_AUTOPSY_E2E_V1_RUNNER.py'], cwd=work)
```
