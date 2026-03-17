from __future__ import annotations

import sys
from pathlib import Path


_TESTS_ROOT = Path(__file__).resolve().parent
_CLEANROOM_ROOT = _TESTS_ROOT.parent
_REPO_ROOT = _CLEANROOM_ROOT.parent
_RUNTIME_SRC = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"

for _path in (_RUNTIME_SRC, _CLEANROOM_ROOT, _REPO_ROOT):
    _text = str(_path)
    if _text not in sys.path:
        sys.path.insert(0, _text)
