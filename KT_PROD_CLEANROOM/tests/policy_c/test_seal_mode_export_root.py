from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from policy_c.static_safety_check import assert_export_root_allowed  # noqa: E402


class TestPolicyCSealModeExportRoot(unittest.TestCase):
    def test_seal_mode_requires_tmp_policy_c_root(self) -> None:
        orig = dict(os.environ)
        try:
            os.environ["KT_SEAL_MODE"] = "1"
            with tempfile.TemporaryDirectory() as td:
                tmp_root = Path(td).resolve()
                seal_tmp = (tmp_root / "_tmp").resolve()
                seal_tmp.mkdir(parents=True, exist_ok=True)
                os.environ["TMPDIR"] = seal_tmp.as_posix()
                os.environ["TMP"] = seal_tmp.as_posix()
                os.environ["TEMP"] = seal_tmp.as_posix()

                allowed = (seal_tmp / "policy_c" / "runs").resolve()
                allowed.mkdir(parents=True, exist_ok=True)
                assert_export_root_allowed(allowed, allowed_roots=("KT_PROD_CLEANROOM/exports/policy_c",))

                forbidden = (tmp_root / "exports" / "policy_c").resolve()
                with self.assertRaises(RuntimeError):
                    assert_export_root_allowed(forbidden, allowed_roots=("KT_PROD_CLEANROOM/exports/policy_c",))
        finally:
            os.environ.clear()
            os.environ.update(orig)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
