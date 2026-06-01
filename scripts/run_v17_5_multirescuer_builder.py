from __future__ import annotations

import json

from v17_5_multirescuer_common import build_all_outputs, json_safe


if __name__ == "__main__":
    print(json.dumps(json_safe(build_all_outputs()), indent=2, sort_keys=True))
