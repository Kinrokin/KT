from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from v13_admission_common import no_scaffold_gate_for_dir


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3full_v13_outputs"),
        help="Directory containing runtime assessment outputs.",
    )
    args = parser.parse_args()
    receipt = no_scaffold_gate_for_dir(Path(args.output_dir))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["gate_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
