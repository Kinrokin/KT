from __future__ import annotations

import json

from v17_5_multirescuer_common import build_multirescuer_policy, json_safe


if __name__ == "__main__":
    print(json.dumps(json_safe(build_multirescuer_policy()), indent=2, sort_keys=True))
