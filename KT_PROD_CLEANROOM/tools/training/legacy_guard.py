from __future__ import annotations

import os


def _is_truthy_env(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}


def require_legacy_allow(*, allow_legacy: bool, tool_name: str, env_var: str = "KT_ALLOW_LEGACY_TRAINING") -> None:
    """
    Fail-closed guard for legacy training entrypoints.

    KT V1 posture: only the FL3 factory lane is canonical; legacy harnesses are disabled by default.
    """
    if allow_legacy or _is_truthy_env(env_var):
        return
    raise SystemExit(
        f"FAIL_CLOSED: legacy entrypoint disabled by default: {tool_name}. "
        f"Re-run with --allow-legacy or set {env_var}=1."
    )

