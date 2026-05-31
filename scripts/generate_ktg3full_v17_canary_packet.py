from __future__ import annotations

import json

from v17_canary_coalition_common import build_packet, read_json, repo_root, write_json


def main() -> int:
    root = repo_root()
    packet_path, packet_sha = build_packet(
        read_json(root / "admission/v17_canary_policy_config.json"),
        read_json(root / "admission/v17_runtime_feature_contract.json"),
    )
    write_json(
        root / "reports/v17_packet_generation_receipt.json",
        {
            "schema_id": "kt.v17_packet_generation_receipt.v1",
            "packet_path": packet_path.relative_to(root).as_posix(),
            "packet_sha256": packet_sha,
            "runtime_authority": False,
            "promotion_authority": False,
            "claim_ceiling_preserved": True,
            "status": "PASS",
        },
    )
    print(json.dumps({"packet_path": packet_path.as_posix(), "packet_sha256": packet_sha}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
