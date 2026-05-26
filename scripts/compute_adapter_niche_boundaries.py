from __future__ import annotations

import json

from accountability_common import build_specialist_routing, repo_root


if __name__ == "__main__":
    result = build_specialist_routing(repo_root())
    print(json.dumps({"niche": result["niche"], "registry": result["registry"]}, indent=2, sort_keys=True))
