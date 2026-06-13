from __future__ import annotations

import json

from ktbud100_review_common import build_summary


if __name__ == "__main__":
    print(json.dumps(build_summary(), indent=2, sort_keys=True))
