# V17 Kaggle Dataset And One Cell

Dataset name: `ktg3full-v17-canary-route-value`

Packet: `packets/ktg3full_v17_canary_route_value.zip`

SHA256: `048618bc273ea211c00830b17f7d539bb97c8aaa104dc3fcdee34c0a734d5926`

This is a canary route-value benchmark packet. It does not train, promote adapters, promote routes, or claim learned-router superiority.

Required measured input:

`benchmark_predictions.jsonl`

The runner fails closed if that file is missing or empty.

```python
import zipfile, pathlib, subprocess, sys

packet = pathlib.Path('/kaggle/input/ktg3full-v17-canary-route-value/ktg3full_v17_canary_route_value.zip')
work = pathlib.Path('/kaggle/working/ktg3full_v17')
work.mkdir(parents=True, exist_ok=True)
zipfile.ZipFile(packet).extractall(work)
subprocess.check_call([sys.executable, 'KTG3FULL_V17_CANARY_RUNNER.py'], cwd=work)
```
