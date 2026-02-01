from __future__ import annotations

import importlib.util
import os
from pathlib import Path


def _maybe_install_kt_io_guard() -> None:
    if os.environ.get("KT_IO_GUARD", "0") != "1":
        return
    # Import late to avoid import-time side effects unless explicitly enabled.
    #
    # IMPORTANT: Do not `import tools...` here. Temple invariants include a negative-space
    # check that treats `tools` as a runtime namespace; importing the cleanroom `tools/`
    # package would be sourced from a non-runtime path and fail closed.
    io_guard_path = (Path(__file__).resolve().parent / "tools" / "verification" / "io_guard.py").resolve()
    spec = importlib.util.spec_from_file_location("kt_io_guard", io_guard_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"FAIL: unable to load io_guard module from {io_guard_path.as_posix()} (fail-closed)")
    mod = importlib.util.module_from_spec(spec)
    # Ensure the module is registered before execution; decorators (e.g. dataclasses)
    # may consult sys.modules during import-time evaluation.
    import sys

    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    install = getattr(mod, "install_global_guard_from_env", None)
    if not callable(install):
        raise RuntimeError("FAIL: io_guard module missing install_global_guard_from_env (fail-closed)")
    install()


_maybe_install_kt_io_guard()
