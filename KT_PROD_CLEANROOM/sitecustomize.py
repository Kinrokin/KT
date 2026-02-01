from __future__ import annotations

import os


def _maybe_install_kt_io_guard() -> None:
    if os.environ.get("KT_IO_GUARD", "0") != "1":
        return
    # Import late to avoid import-time side effects unless explicitly enabled.
    from tools.verification.io_guard import install_global_guard_from_env

    install_global_guard_from_env()


_maybe_install_kt_io_guard()

