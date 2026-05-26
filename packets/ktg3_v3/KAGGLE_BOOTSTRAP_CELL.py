from __future__ import annotations

import subprocess
import sys
from pathlib import Path

packet_dir = Path(__file__).resolve().parent
runner = packet_dir / "KTG3_V3_RUNNER.py"
raise SystemExit(subprocess.call([sys.executable, str(runner)]))
