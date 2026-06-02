from __future__ import annotations

import json
from pathlib import Path

from KT_V1773_MEASURED_ARM_CORE import run_measured_arm_runtime


def main() -> int:
    result = run_measured_arm_runtime(Path(__file__).resolve().parent)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
