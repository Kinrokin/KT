import os


class LiveModeError(RuntimeError):
    """Raised when live mode policy is violated."""


def enforce_live_guard() -> None:
    """
    Fail-closed live mode guard.

    Rules:
    - If KT_LIVE != "1", no-op.
    - If KT_LIVE == "1" and KT_LIVE_PROOF != "LIVE_HASHED" -> fail.
    - If KT_LIVE == "1" and proof is LIVE_HASHED but no receipts are present yet -> fail.
      (Receipts requirement can be relaxed later when a receipt path is integrated.)
    """
    live = (os.getenv("KT_LIVE", "0") or "").strip()
    proof = (os.getenv("KT_LIVE_PROOF") or "").strip()

    if live != "1":
        return

    if proof != "LIVE_HASHED":
        raise LiveModeError("KT_LIVE=1 requires KT_LIVE_PROOF=LIVE_HASHED (fail-closed)")

    # Placeholder: once live receipts exist, guard should verify their presence.
    raise LiveModeError("LIVE_HASHED active but no receipts present (fail-closed)")
