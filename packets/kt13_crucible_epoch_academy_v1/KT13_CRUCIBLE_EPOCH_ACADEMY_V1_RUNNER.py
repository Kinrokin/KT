#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys, json
CMDS = [
 ["tools/operator/validate_crucible_epoch_academy_overlay.py"],
 ["tools/operator/build_crucible_pressure_curriculum.py"],
 ["tools/operator/run_crucible_epoch_academy_pressure.py"],
 ["tools/operator/score_crucible_transfer.py"],
 ["tools/operator/compile_epoch_pressure_receipt.py"],
 ["tools/operator/compile_academy_curriculum_receipt.py"],
 ["tools/operator/map_benchmark_failures_to_crucibles.py"]
]
def main():
    for c in CMDS:
        subprocess.check_call([sys.executable, *c])
    print(json.dumps({"status":"PASS","outcome":"KT_CRUCIBLE_EPOCH_ACADEMY_PRESSURE_CURRICULUM_BOUND__TARGETED_REPAIR_PRESSURE_NEXT"}, indent=2))
if __name__ == "__main__": main()
