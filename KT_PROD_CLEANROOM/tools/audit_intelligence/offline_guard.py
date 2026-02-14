from __future__ import annotations

import socket
from contextlib import contextmanager
from typing import Any


class OfflineViolation(RuntimeError):
    pass


_ORIG_SOCKET = None
_ORIG_CREATE_CONNECTION = None


def enable_offline_guard() -> None:
    """
    Best-effort mechanical enforcement: block socket creation.
    Audit intelligence must be offline-only.
    """
    global _ORIG_SOCKET, _ORIG_CREATE_CONNECTION

    if _ORIG_SOCKET is not None or _ORIG_CREATE_CONNECTION is not None:
        return

    def _blocked(*_a: Any, **_kw: Any) -> Any:
        raise OfflineViolation("FAIL_CLOSED: network disabled for audit intelligence")

    _ORIG_SOCKET = socket.socket
    _ORIG_CREATE_CONNECTION = socket.create_connection
    socket.socket = _blocked  # type: ignore[assignment]
    socket.create_connection = _blocked  # type: ignore[assignment]


def disable_offline_guard() -> None:
    global _ORIG_SOCKET, _ORIG_CREATE_CONNECTION

    if _ORIG_SOCKET is None and _ORIG_CREATE_CONNECTION is None:
        return

    if _ORIG_SOCKET is not None:
        socket.socket = _ORIG_SOCKET  # type: ignore[assignment]
    if _ORIG_CREATE_CONNECTION is not None:
        socket.create_connection = _ORIG_CREATE_CONNECTION  # type: ignore[assignment]

    _ORIG_SOCKET = None
    _ORIG_CREATE_CONNECTION = None


@contextmanager
def offline_guard() -> Any:
    enable_offline_guard()
    try:
        yield
    finally:
        disable_offline_guard()
