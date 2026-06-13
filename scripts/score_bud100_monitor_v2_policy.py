from __future__ import annotations

import json

from ktbud100_v2_policy_common import score_policy


if __name__ == "__main__":
    print(json.dumps(score_policy(), indent=2, sort_keys=True))
