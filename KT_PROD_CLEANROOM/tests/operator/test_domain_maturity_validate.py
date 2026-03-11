from __future__ import annotations

import json
from pathlib import Path

from tools.operator.domain_maturity_validate import build_domain_maturity_report


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_domain_maturity_validate_accepts_known_taxonomy_states(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "status_taxonomy.json",
        {
            "schema_id": "kt.governance.status_taxonomy.v1",
            "maturity_ladder": ["PLANNED", "SPECIFIED", "MATERIALIZED", "TESTED", "PROVEN_ON_CURRENT_HEAD", "ACTIVE_AUTHORITY"],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v3",
            "constitutional_domains": [
                {"domain_id": "DOMAIN_1", "maturity_state": "ACTIVE_AUTHORITY", "status": "ACTIVE_AUTHORITY", "gate_state": "OPEN"},
                {"domain_id": "DOMAIN_2", "maturity_state": "MATERIALIZED", "status": "MATERIALIZED", "gate_state": "LOCKED"},
            ],
        },
    )
    report = build_domain_maturity_report(root=tmp_path)
    assert report["status"] == "PASS", report


def test_domain_maturity_validate_rejects_unknown_states(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "status_taxonomy.json",
        {
            "schema_id": "kt.governance.status_taxonomy.v1",
            "maturity_ladder": ["PLANNED", "SPECIFIED"],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v3",
            "constitutional_domains": [
                {"domain_id": "DOMAIN_1", "maturity_state": "ACTIVE_AUTHORITY", "status": "ACTIVE_AUTHORITY", "gate_state": "OPEN"},
            ],
        },
    )
    report = build_domain_maturity_report(root=tmp_path)
    assert report["status"] == "FAIL"
    assert "DOMAIN_1:invalid_maturity_state" in report["failures"]
