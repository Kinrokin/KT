from __future__ import annotations

import subprocess
from pathlib import Path

runner = Path("/kaggle/input/ktg3full-v13/KTG3FULL_V13_RUNNER.py")
if not runner.exists():
    runner = Path("KTG3FULL_V13_RUNNER.py")
subprocess.run(["python", str(runner)], check=True)
