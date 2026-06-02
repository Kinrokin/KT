from __future__ import annotations

from v17_7_3_evidence_acquisition_common import build_all


def main() -> int:
    summary = build_all()
    print(summary["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
