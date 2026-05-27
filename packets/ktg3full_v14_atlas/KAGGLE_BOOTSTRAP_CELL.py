from pathlib import Path
import subprocess

runner = Path('/kaggle/input/ktg3full-v14-atlas/KTG3FULL_V14_ATLAS_RUNNER.py')
if not runner.exists():
    runner = Path('KTG3FULL_V14_ATLAS_RUNNER.py')
subprocess.run(['python', str(runner)], check=True)
