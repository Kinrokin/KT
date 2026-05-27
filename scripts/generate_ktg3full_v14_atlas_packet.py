from __future__ import annotations

import json

from accountability_common import git_head, repo_root
from v14_omni_common import generate_packet, write_version_and_packet_hygiene


if __name__ == "__main__":
    root = repo_root()
    sha = generate_packet(root, git_head(root))
    write_version_and_packet_hygiene(root, sha)
    print(json.dumps({"packet": "packets/ktg3full_v14_atlas.zip", "sha256": sha}, indent=2, sort_keys=True))
