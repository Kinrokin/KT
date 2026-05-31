from pathlib import Path
import runpy

runner = Path("/kaggle/input/ktg3full-v15-truth-route/KTG3FULL_V15_TRUTH_ROUTE_RUNNER.py")
if not runner.exists():
    runner = Path("KTG3FULL_V15_TRUTH_ROUTE_RUNNER.py")
runpy.run_path(str(runner), run_name="__main__")
