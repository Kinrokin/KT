from __future__ import annotations

import json

from ktbud100_review_common import reconcile_scorecard


if __name__ == "__main__":
    print(json.dumps(reconcile_scorecard(), indent=2, sort_keys=True))
