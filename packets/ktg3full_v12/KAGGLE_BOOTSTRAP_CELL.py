from __future__ import annotations

import subprocess
from pathlib import Path

packet = Path("/kaggle/input/ktg3full-v12/KTG3FULL_V12_RUNNER.py")
if not packet.exists():
    packet = Path("KTG3FULL_V12_RUNNER.py")
subprocess.run(["python", str(packet)], check=True)
