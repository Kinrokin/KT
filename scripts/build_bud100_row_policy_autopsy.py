from __future__ import annotations

import json

from ktbud100_review_common import build_row_policy_autopsy


if __name__ == "__main__":
    print(json.dumps(build_row_policy_autopsy(), indent=2, sort_keys=True))
