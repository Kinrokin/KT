# V17.5 Kaggle Dataset And One Cell

Dataset: `ktg3full-v17-5-multirescuer-e2e-v1`

Packet: `packets/ktg3full_v17_5_multirescuer_e2e_v1.zip`

SHA256: `37480d832451732e1aa7af76869e362cb87fca1fcadb8362517f72ec965feb61`

This packet is assessment-only, no-training, no-promotion, no learned-router-superiority.

```python
import pathlib, subprocess, sys, zipfile
packet = pathlib.Path('/kaggle/input/ktg3full-v17-5-multirescuer-e2e-v1/ktg3full_v17_5_multirescuer_e2e_v1.zip')
work = pathlib.Path('/kaggle/working/ktg3full_v17_5_multirescuer_packet')
work.mkdir(parents=True, exist_ok=True)
zipfile.ZipFile(packet).extractall(work)
subprocess.check_call([sys.executable, 'KTG3FULL_V17_5_MULTIRESCUER_E2E_V1_RUNNER.py'], cwd=work)
```
