from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.v17_7_oats_sddr_common import build_all, read_json, repo_root


if __name__ == "__main__":
    build_all()
    receipt = read_json(repo_root() / "reports" / "zero_gpu_router_validation_receipt.json")
    if receipt.get("status") != "PASS":
        raise SystemExit("V17.7 zero-GPU router validation failed")
    print("V17.7 zero-GPU router validation PASS")
