# V17.1 Kaggle Dataset And One Cell

Dataset: `ktg3full-v17-e2e-v1-2`

Packet: `packets/ktg3full_v17_e2e_v1_2.zip`

SHA256: `79d63ddc66c3fa471ed38373a91446cde61fb9a3f790e7353a1ca2434f65735e`

```python
import pathlib, subprocess, sys, zipfile
packet = pathlib.Path('/kaggle/input/ktg3full-v17-e2e-v1-2/ktg3full_v17_e2e_v1_2.zip')
work = pathlib.Path('/kaggle/working/ktg3full_v17_e2e_v1_2_packet')
work.mkdir(parents=True, exist_ok=True)
zipfile.ZipFile(packet).extractall(work)
subprocess.check_call([sys.executable, 'KTG3FULL_V17_E2E_V1_2_RUNNER.py'], cwd=work)
```
