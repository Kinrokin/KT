from __future__ import annotations

from pathlib import Path

from KT_V1774_TRUEGEN_ARM_CORE import run_truegen_runtime


def main() -> int:
    summary = run_truegen_runtime(Path(__file__).resolve().parent)
    return 0 if summary.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
