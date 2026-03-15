from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.verification.run_sweep_audit import RECEIPTS_DIR_REL, _validate_receipts_cmd


def test_validate_receipts_command_includes_receipts_dir(tmp_path: Path) -> None:
    cmd = _validate_receipts_cmd(out_dir=tmp_path)

    assert cmd == [
        "python",
        "-m",
        "tools.verification.validate_receipts",
        "--receipts-dir",
        RECEIPTS_DIR_REL,
        "--out-dir",
        str(tmp_path),
    ]
