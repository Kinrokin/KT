from __future__ import annotations

import builtins
import io
import json
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union


class IOGuardViolation(RuntimeError):
    pass


def _as_path(p: Union[str, os.PathLike[str]]) -> Path:
    return Path(os.fspath(p))

def _is_devnull_path(p: Path) -> bool:
    """
    Allow writes to the platform null device (e.g. /dev/null or NUL).

    This is not stateful I/O and is commonly used by libraries (pytest/logging) as a sink.
    """
    devnull = os.devnull
    if devnull:
        try:
            dn = Path(devnull)
            pp = p
            if not dn.is_absolute():
                dn = (Path.cwd() / dn)
            if not pp.is_absolute():
                pp = (Path.cwd() / pp)
            if pp.resolve().as_posix().lower() == dn.resolve().as_posix().lower():
                return True
        except Exception:
            pass

    # Windows: device paths sometimes appear as \\.\nul or with trailing slashes.
    s = str(p).replace("/", "\\").lower().rstrip("\\")
    if s in {"nul", "\\\\.\\nul", "\\\\.\\nul:"}:
        return True
    if s.startswith("\\\\.\\nul"):
        return True
    return False


def _is_write_mode(mode: str) -> bool:
    # Anything that can create or mutate bytes on disk.
    return any(ch in mode for ch in ("w", "a", "x", "+"))


def _under_any_root(*, target: Path, roots: Sequence[Path]) -> bool:
    t = target.resolve()
    for r in roots:
        try:
            t.relative_to(r.resolve())
            return True
        except Exception:
            continue
    return False


@dataclass(frozen=True)
class IOGuardConfig:
    allowed_write_roots: Tuple[Path, ...]
    deny_network: bool = True
    receipt_path: Optional[Path] = None


class IOGuard:
    """
    Fail-closed I/O guard for the canonical seal lane.

    - Denies network (socket/DNS) when enabled.
    - Denies filesystem writes outside allowlisted roots.
    - Does not attempt to prevent reads (the canonical lane reads repo code and pinned artifacts).
    """

    def __init__(self, config: IOGuardConfig):
        self._cfg = config
        self._orig_open: Optional[Callable[..., Any]] = None
        self._orig_io_open: Optional[Callable[..., Any]] = None
        self._orig_path_open: Optional[Callable[..., Any]] = None
        self._orig_connect: Optional[Callable[..., Any]] = None
        self._orig_getaddrinfo: Optional[Callable[..., Any]] = None
        self._orig_create_connection: Optional[Callable[..., Any]] = None

        self.violations: List[Dict[str, Any]] = []

    def _write_receipt(self) -> None:
        if not self._cfg.receipt_path:
            return
        payload = {
            "schema_id": "kt.io_guard_receipt.v1",
            "status": "PASS" if not self.violations else "FAIL",
            "violations": self.violations,
        }
        rp = self._cfg.receipt_path
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    def _deny(self, *, kind: str, details: Dict[str, Any]) -> None:
        rec = {"kind": kind, "details": details}
        self.violations.append(rec)
        self._write_receipt()
        raise IOGuardViolation(f"FAIL: forbidden {kind} (fail-closed): {details}")

    def __enter__(self) -> "IOGuard":
        # Filesystem write guard (builtins.open).
        self._orig_open = builtins.open
        self._orig_io_open = io.open
        self._orig_path_open = Path.open

        def _guard_open(delegate: Callable[..., Any], file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if isinstance(file, int):
                return delegate(file, mode, *args, **kwargs)
            if isinstance(file, (str, os.PathLike)) and isinstance(mode, str) and _is_write_mode(mode):
                target = _as_path(file)
                if _is_devnull_path(target):
                    return delegate(file, mode, *args, **kwargs)
                if not target.is_absolute():
                    target = (Path.cwd() / target)
                if not _under_any_root(target=target, roots=self._cfg.allowed_write_roots):
                    self._deny(
                        kind="filesystem_write",
                        details={
                            "path": str(target),
                            "mode": mode,
                        },
                    )
            return delegate(file, mode, *args, **kwargs)

        def _open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
            return _guard_open(self._orig_open, file, mode, *args, **kwargs)  # type: ignore[arg-type]

        def _io_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
            return _guard_open(self._orig_io_open, file, mode, *args, **kwargs)  # type: ignore[arg-type]

        builtins.open = _open  # type: ignore[assignment]
        io.open = _io_open  # type: ignore[assignment]

        def _path_open(self_path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
            if isinstance(mode, str) and _is_write_mode(mode):
                target = self_path
                if _is_devnull_path(target):
                    return self._orig_path_open(self_path, mode, *args, **kwargs)  # type: ignore[misc]
                if not target.is_absolute():
                    target = (Path.cwd() / target)
                if not _under_any_root(target=target, roots=self._cfg.allowed_write_roots):
                    self._deny(kind="filesystem_write", details={"path": str(target), "mode": mode})
            return self._orig_path_open(self_path, mode, *args, **kwargs)  # type: ignore[misc]

        Path.open = _path_open  # type: ignore[assignment]

        # Network guard (socket).
        if self._cfg.deny_network:
            self._orig_connect = socket.socket.connect
            self._orig_getaddrinfo = socket.getaddrinfo
            self._orig_create_connection = socket.create_connection

            def _connect(sock: socket.socket, address: Any) -> Any:  # type: ignore[override]
                self._deny(kind="network_connect", details={"address": repr(address)})

            def _getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
                self._deny(kind="network_dns", details={"host": repr(host), "port": repr(port)})

            def _create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
                self._deny(kind="network_create_connection", details={"address": repr(address)})

            socket.socket.connect = _connect  # type: ignore[assignment]
            socket.getaddrinfo = _getaddrinfo  # type: ignore[assignment]
            socket.create_connection = _create_connection  # type: ignore[assignment]

        # Emit a baseline PASS receipt at enter-time (if enabled) so downstream seal packaging
        # can treat the receipt as an always-present artifact. Violations will overwrite it
        # with FAIL and details (fail-closed).
        self._write_receipt()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        # Always restore.
        if self._orig_open is not None:
            builtins.open = self._orig_open  # type: ignore[assignment]
        if self._orig_io_open is not None:
            io.open = self._orig_io_open  # type: ignore[assignment]
        if self._orig_path_open is not None:
            Path.open = self._orig_path_open  # type: ignore[assignment]

        if self._cfg.deny_network:
            if self._orig_connect is not None:
                socket.socket.connect = self._orig_connect  # type: ignore[assignment]
            if self._orig_getaddrinfo is not None:
                socket.getaddrinfo = self._orig_getaddrinfo  # type: ignore[assignment]
            if self._orig_create_connection is not None:
                socket.create_connection = self._orig_create_connection  # type: ignore[assignment]

        # If we recorded violations but the caller swallowed exceptions, still persist the receipt.
        self._write_receipt()
        return False


_GLOBAL_GUARD: Optional[IOGuard] = None


def install_global_guard_from_env() -> None:
    """
    Install a process-wide guard based on env vars.

    Intended to be called from sitecustomize (subprocess safety), guarded by KT_IO_GUARD=1.
    """
    global _GLOBAL_GUARD
    if _GLOBAL_GUARD is not None:
        return

    roots_raw = os.environ.get("KT_IO_GUARD_ALLOWED_WRITE_ROOTS", "")
    if not roots_raw:
        return
    try:
        roots_list = json.loads(roots_raw)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("KT_IO_GUARD_ALLOWED_WRITE_ROOTS must be JSON list (fail-closed)") from exc
    if not isinstance(roots_list, list) or not all(isinstance(x, str) and x.strip() for x in roots_list):
        raise RuntimeError("KT_IO_GUARD_ALLOWED_WRITE_ROOTS must be JSON list of strings (fail-closed)")

    roots = tuple(Path(x).resolve() for x in roots_list)
    receipt = os.environ.get("KT_IO_GUARD_RECEIPT_PATH", "").strip()
    receipt_path: Optional[Path] = None
    if receipt:
        base = Path(receipt).resolve()
        # Avoid concurrent clobbering across subprocesses by PID-suffixing.
        receipt_path = base.with_name(f"{base.stem}.{os.getpid()}{base.suffix}")
    deny_network = os.environ.get("KT_IO_GUARD_DENY_NETWORK", "1") == "1"

    guard = IOGuard(IOGuardConfig(allowed_write_roots=roots, deny_network=deny_network, receipt_path=receipt_path))
    _GLOBAL_GUARD = guard
    guard.__enter__()
