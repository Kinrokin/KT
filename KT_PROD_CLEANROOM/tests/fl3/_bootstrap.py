from __future__ import annotations

import sys
from pathlib import Path


def bootstrap_syspath() -> Path:
    """
    Ensure FL3 tests run under plain `pytest` without relying on an external PYTHONPATH.
    Adds:
      - KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src
      - KT_PROD_CLEANROOM
    """
    here = Path(__file__).resolve()
    repo_root = None
    for parent in here.parents:
        if (parent / "KT_PROD_CLEANROOM").is_dir():
            repo_root = parent
            break
    if repo_root is None:
        raise RuntimeError("Unable to locate repo root (expected KT_PROD_CLEANROOM/)")

    src_root = repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"
    cleanroom_root = repo_root / "KT_PROD_CLEANROOM"
    sys.path.insert(0, str(src_root))
    sys.path.insert(0, str(cleanroom_root))
    return repo_root

