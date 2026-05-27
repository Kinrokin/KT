from __future__ import annotations

import json

from accountability_common import repo_root
from v14_omni_common import import_v13_evidence


if __name__ == "__main__":
    print(json.dumps(import_v13_evidence(repo_root()), indent=2, sort_keys=True))
