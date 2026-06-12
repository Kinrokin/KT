from __future__ import annotations

import sys

from ktbud100_common import main


if __name__ == "__main__":
    question = " ".join(sys.argv[1:])
    raise SystemExit(main(["classify", "--question", question]))
