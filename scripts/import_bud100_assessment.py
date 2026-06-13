from __future__ import annotations

import json

from ktbud100_review_common import import_assessment


if __name__ == "__main__":
    print(json.dumps(import_assessment(), indent=2, sort_keys=True))
