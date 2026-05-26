from __future__ import annotations

import json

from accountability_common import self_deception_scorecard


if __name__ == "__main__":
    print(json.dumps(self_deception_scorecard("manual"), indent=2, sort_keys=True))
