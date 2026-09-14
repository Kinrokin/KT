from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repo_layout_contract_preserves_audit_only_boundary() -> None:
    contract = json.loads((ROOT / "governance/repo_layout_contract.json").read_text(encoding="utf-8"))

    assert contract["schema_id"] == "kt.repo_layout_contract.v1"
    assert contract["do_not_delete_evidence"] is True
    assert contract["do_not_bulk_move_files"] is True
    assert contract["current_packet"] is None
    manifest = json.loads((ROOT / "packets/current/manifest.json").read_text(encoding="utf-8"))
    assert manifest["packets"] == []
    assert contract["claim_ceiling_preserved"] is True
