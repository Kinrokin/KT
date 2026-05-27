from __future__ import annotations

from accountability_common import repo_root
from v14_omni_common import build_oracle_and_capability


if __name__ == "__main__":
    build_oracle_and_capability(repo_root())
    print("route value training rows emitted")
