from __future__ import annotations

import json

from ktbud100_v2_policy_common import compare_against_fixed512


if __name__ == "__main__":
    print(json.dumps(compare_against_fixed512(), indent=2, sort_keys=True))
