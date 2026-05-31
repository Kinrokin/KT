from __future__ import annotations

import json
from pathlib import Path

from v15_oracle_harvest_common import repo_root, read_json


if __name__ == "__main__":
    print(json.dumps(read_json(repo_root() / "reports/do_not_train_oracle_receipt.json"), indent=2, sort_keys=True))
