from __future__ import annotations

import json

from v17_5_multirescuer_common import build_multirescuer_policy, build_packet, json_safe


if __name__ == "__main__":
    packet, sha = build_packet(build_multirescuer_policy())
    print(json.dumps(json_safe({"packet_path": packet, "packet_sha256": sha}), indent=2, sort_keys=True))
