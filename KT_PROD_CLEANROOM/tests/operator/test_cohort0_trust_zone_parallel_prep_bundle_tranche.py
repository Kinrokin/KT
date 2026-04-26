from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_trust_zone_parallel_prep_bundle_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_parallel_prep_bundle_emits_non_authoritative_outputs(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    governance = tmp_path / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / "cohort0_trust_zone_registry_scope_contract_receipt.json",
        {"schema_id": "contract", "status": "PASS", "outcome": "OK", "next_lawful_move": "EXECUTE_TRUST_ZONE_BOUNDARY_PURIFICATION_PARALLEL_PREP_BUNDLE"},
    )
    _write_json(
        governance / "trust_zone_registry.json",
        {
            "schema_id": "registry",
            "zones": [
                {"zone_id": "CANONICAL", "include": ["KT_PROD_CLEANROOM/governance/**"], "exclude": []},
                {"zone_id": "COMMERCIAL", "include": ["README.md", "docs/**"], "exclude": []},
            ],
        },
    )
    (tmp_path / "README.md").write_text("No broad SOTA claim should become proof.\n", encoding="utf-8")
    (tmp_path / "KT_PROD_CLEANROOM" / "governance").mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(tranche.common, "git_ls_files", lambda root: ["README.md", "KT_PROD_CLEANROOM/governance/trust_zone_registry.json", "misc/unknown.txt"])

    result = tranche.run(
        reports_root=reports,
        contract_receipt_path=reports / "cohort0_trust_zone_registry_scope_contract_receipt.json",
        trust_zone_registry_path=governance / "trust_zone_registry.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    inventory = _load(reports / tranche.OUTPUTS["candidate_inventory"])
    violations = _load(reports / tranche.OUTPUTS["commercial_claim_violations"])
    branch_receipt = _load(reports / tranche.OUTPUTS["branch_authority_receipt"])
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert inventory["unknown_zone_path_count"] == 1
    assert violations["candidate_violation_count"] >= 1
    assert branch_receipt["may_drive_live_posture"] is False


def test_parallel_prep_bundle_requires_contract_authorization(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    governance = tmp_path / "KT_PROD_CLEANROOM" / "governance"
    _write_json(reports / "cohort0_trust_zone_registry_scope_contract_receipt.json", {"schema_id": "contract", "status": "PASS", "next_lawful_move": "SOMETHING_ELSE"})
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "zones": []})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")

    with pytest.raises(RuntimeError, match="authorize the parallel prep bundle"):
        tranche.run(
            reports_root=reports,
            contract_receipt_path=reports / "cohort0_trust_zone_registry_scope_contract_receipt.json",
            trust_zone_registry_path=governance / "trust_zone_registry.json",
        )
