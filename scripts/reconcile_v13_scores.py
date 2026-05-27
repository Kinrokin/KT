from __future__ import annotations

import json

from accountability_common import repo_root
from v14_omni_common import reconcile_v13_scores


if __name__ == "__main__":
    print(json.dumps(reconcile_v13_scores(repo_root()), indent=2, sort_keys=True))
