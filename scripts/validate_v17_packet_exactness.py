from __future__ import annotations

import json

from v17_canary_coalition_common import validate_exact_packet, write_json, repo_root


def main() -> int:
    result = validate_exact_packet()
    write_json(repo_root() / "reports/v17_packet_exactness_validation.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
